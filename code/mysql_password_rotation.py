# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import boto3
import json
import logging
import os
from datetime import datetime
import re
from requests.auth import HTTPDigestAuth
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import pymysql
from datetime import datetime, timezone, timedelta
import psycopg2


logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RDS_DB_INSTANCE_ARN_LENGTH = 256


def lambda_handler(event, context):

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if "RotationEnabled" in metadata and not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # Call the appropriate step
    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(service_client, arn, token):

    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Get username character limit from environment variable
        alt_user = get_alt_username(current_dict['username'])
        current_dict['username'] = alt_user
        random_password = get_random_password(service_client)
        current_dict['password'] = random_password
        raw_host = current_dict['raw_host']
        updated_host = raw_host.replace("{username}",alt_user).replace("{password}", random_password)
        current_dict['host'] = updated_host

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):

    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info("setSecret: AWSPENDING secret is already set as password in MySQL DB for secret arn %s." % arn)
        return

    # Make sure the host from current and pending match
    if current_dict['mysql_host'] != pending_dict['mysql_host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['mysql_host'], current_dict['mysql_host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['mysql_host'], current_dict['mysql_host']))

    # Before we do anything with the secret, make sure the AWSCURRENT secret is valid by logging in to the db
    # This ensures that the credential we are rotating is valid to protect against a confused deputy attack
    conn = get_connection(current_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)
    conn.close()

    # Use the master arn from the current secret to fetch master secret contents
    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)

    # Fetch dbname from the Child User
    master_dict['dbname'] = current_dict.get('dbname', None)

    if current_dict['mysql_host'] != master_dict['mysql_host'] and not is_rds_replica_database(current_dict, master_dict):
        # If current dict is a replica of the master dict, can proceed
        logger.error("setSecret: Current database host %s is not the same host as/rds replica of master %s" % (current_dict['mysql_host'], master_dict['mysql_host']))
        raise ValueError("Current database host %s is not the same host as/rds replica of master %s" % (current_dict['mysql_host'], master_dict['mysql_host']))

    # Now log into the database with the master credentials
    conn = get_connection(master_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using credentials in master secret %s" % master_arn)
        raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

    # Now set the password to the pending password
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT User FROM mysql.user WHERE User = %s", pending_dict['username'])
            # Create the user if it does not exist
            if cur.rowcount == 0:
                cur.execute("CREATE USER %s IDENTIFIED BY %s", (pending_dict['username'], pending_dict['password']))

            # Copy grants to the new user
            cur.execute("SHOW GRANTS FOR %s", current_dict['username'])
            for row in cur.fetchall():
                grant = row[0].split(' TO ')
                new_grant_escaped = grant[0].replace('%', '%%')  # % is a special character in Python format strings.
                cur.execute(new_grant_escaped + " TO %s", (pending_dict['username'],))

            # Get the version of MySQL
            cur.execute("SELECT VERSION()")
            ver = cur.fetchone()[0]

            # Copy TLS options to the new user
            escaped_encryption_statement = get_escaped_encryption_statement(ver)
            cur.execute("SELECT ssl_type, ssl_cipher, x509_issuer, x509_subject FROM mysql.user WHERE User = %s", current_dict['username'])
            tls_options = cur.fetchone()
            ssl_type = tls_options[0]
            if not ssl_type:
                cur.execute(escaped_encryption_statement + " NONE", pending_dict['username'])
            elif ssl_type == "ANY":
                cur.execute(escaped_encryption_statement + " SSL", pending_dict['username'])
            elif ssl_type == "X509":
                cur.execute(escaped_encryption_statement + " X509", pending_dict['username'])
            else:
                cur.execute(escaped_encryption_statement + " CIPHER %s AND ISSUER %s AND SUBJECT %s", (pending_dict['username'], tls_options[1], tls_options[2], tls_options[3]))

            # Set the password for the user and commit
            password_option = get_password_option(ver)
            cur.execute("SET PASSWORD FOR %s = " + password_option, (pending_dict['username'], pending_dict['password']))
            conn.commit()
            logger.info("setSecret: Successfully set password for %s in MySQL DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        conn.close()


def test_secret(service_client, arn, token):

    # Try to login with the pending secret, if it succeeds, return
    conn = get_connection(get_secret_dict(service_client, arn, "AWSPENDING", token))
    if conn:
        # This is where the lambda will validate the user's permissions. Modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW()")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into MySQL DB with AWSPENDING secret in %s." % arn)
        return
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % arn)
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):

    # First describe the secret to get the current version
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))
    username = current_dict['username']
    user_prefix = get_user_prefix(username)
    logger.info("Triggering get_mongodb_atlas_users user with user_prefix -->> %s" % user_prefix)
    users = get_mysql_users(user_prefix,service_client, arn)
    logger.info("Triggering get_older_users with users -->> %s" % users)
    users_to_delete = get_older_users(users)
    logger.info("Triggering delete_mongodb_atlas_user with users_to_delete -->> %s" % users_to_delete)
    for user in users_to_delete:
        delete_mysql_user(service_client,arn,user)


def get_connection(secret_dict):

    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 3306
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else None

    # Get SSL connectivity configuration
    use_ssl, fall_back = get_ssl_config(secret_dict)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to non-SSL on failure
    conn = connect_and_authenticate(secret_dict, port, dbname, use_ssl)
    if conn or not fall_back:
        return conn
    else:
        return connect_and_authenticate(secret_dict, port, dbname, False)


def get_ssl_config(secret_dict):

    # Default to True for SSL and fall_back mode if 'ssl' key DNE
    if 'ssl' not in secret_dict:
        return True, True

    # Handle type bool
    if isinstance(secret_dict['ssl'], bool):
        return secret_dict['ssl'], False

    # Handle type string
    if isinstance(secret_dict['ssl'], str):
        ssl = secret_dict['ssl'].lower()
        if ssl == "true":
            return True, False
        elif ssl == "false":
            return False, False
        else:
            # Invalid string value, default to True for both SSL and fall_back mode
            return True, True

    # Invalid type, default to True for both SSL and fall_back mode
    return True, True


def connect_and_authenticate(secret_dict, port, dbname, use_ssl):


    ssl = {'ca': '/etc/pki/tls/cert.pem'} if use_ssl else None

    # Try to obtain a connection to the db
    try:
        # Checks hostname and verifies server certificate implictly when 'ca' key is in 'ssl' dictionary
        conn = pymysql.connect(host=secret_dict['mysql_host'], user=secret_dict['username'], password=secret_dict['password'], port=port, database=dbname, connect_timeout=5, ssl=ssl)
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", secret_dict['username'], secret_dict['mysql_host']))
        return conn
    except pymysql.OperationalError as e:
        if 'certificate verify failed: IP address mismatch' in e.args[1]:
            logger.error("Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secret_dict['mysql_host'])
        return None


def get_secret_dict(service_client, arn, stage, token=None, master_secret=False):

    required_fields = ['mysql_host', 'username', 'password', 'engine']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Run validations against the secret
    if master_secret and (set(secret_dict.keys()) == set(['username', 'password'])):
        # If this is an RDS-made Master Secret, we can fetch `host` and other connection params
        # from the DescribeDBInstances/DescribeDBClusters RDS API using the DB Instance/Cluster ARN as a filter.
        # The DB Instance/Cluster ARN is fetched from the RDS-made Master Secret's System Tags.
        db_instance_info = fetch_instance_arn_from_system_tags(service_client, arn)
        if len(db_instance_info) != 0:
            secret_dict = get_connection_params_from_rds_api(secret_dict, db_instance_info)
            logger.info("setSecret: Successfully fetched connection params for Master Secret %s from DescribeDBInstances API." % arn)

        # For non-RDS-made Master Secrets that are missing `host`, this will error below when checking for required connection params.

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    supported_engines = ["mysql", "aurora-mysql"]
    if secret_dict['engine'] not in supported_engines:
        raise KeyError("Database engine must be set to 'mysql' in order to use this rotation lambda")

    # Parse and return the secret JSON string
    return secret_dict


def get_alt_username(current_username):
    # Get the current time in IST (UTC+5:30)
    ist_time = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    timestamp_str = ist_time.strftime('%Y%m%d%H%M%S')  # Format as YYYYMMDDHHMMSS
    logger.info("Current time in IST is %s" % (ist_time))
    
    # Regular expression to match the pattern ending with a timestamp
    timestamp_pattern = re.compile(r"_(\d{14})$")  # Match YYYYMMDDHHMMSS format

    # Check if the current username ends with a timestamp
    if timestamp_pattern.search(current_username):
        # Update the existing timestamp with the latest value in IST
        return timestamp_pattern.sub(f"_{timestamp_str}", current_username)
    else:
        # Append the current timestamp if it's not already present
        return f"{current_username}_{timestamp_str}"

def get_password_option(version):

    if version.startswith("8"):
        return "%s"
    else:
        return "PASSWORD(%s)"


def get_escaped_encryption_statement(version):

    if version.startswith("5.6"):
        return "GRANT USAGE ON *.* TO %s@'%%' REQUIRE"
    else:
        return "ALTER USER %s@'%%' REQUIRE"


def is_rds_replica_database(replica_dict, master_dict):

    # Setup the client
    rds_client = boto3.client('rds')

    # Get instance identifiers from endpoints
    replica_instance_id = replica_dict['mysql_host'].split(".")[0]
    master_instance_id = master_dict['mysql_host'].split(".")[0]

    try:
        describe_response = rds_client.describe_db_instances(DBInstanceIdentifier=replica_instance_id)
    except Exception as err:
        logger.warning("Encountered error while verifying rds replica status: %s" % err)
        return False
    instances = describe_response['DBInstances']

    # Host from current secret cannot be found
    if not instances:
        logger.info("Cannot verify replica status - no RDS instance found with identifier: %s" % replica_instance_id)
        return False

    # DB Instance identifiers are unique - can only be one result
    current_instance = instances[0]
    return master_instance_id == current_instance.get('ReadReplicaSourceDBInstanceIdentifier')


def fetch_instance_arn_from_system_tags(service_client, secret_arn):

    metadata = service_client.describe_secret(SecretId=secret_arn)

    if 'Tags' not in metadata:
        logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have a tag aws:rds:primarydbinstancearn or a tag aws:rds:primarydbclusterarn" % secret_arn)
        return {}

    tags = metadata['Tags']

    # Check if DB Instance/Cluster ARN is present in secret Tags
    db_instance_info = {}
    for tag in tags:
        if tag['Key'].lower() == 'aws:rds:primarydbinstancearn' or tag['Key'].lower() == 'aws:rds:primarydbclusterarn':
            db_instance_info['ARN_SYSTEM_TAG'] = tag['Key'].lower()
            db_instance_info['ARN'] = tag['Value']

    # DB Instance/Cluster ARN must be present in secret System Tags to use this work-around
    if len(db_instance_info) == 0:
        logger.warning("setSecret: DB Instance ARN not present in Metadata System Tags for secret %s" % secret_arn)
    elif len(db_instance_info['ARN']) > MAX_RDS_DB_INSTANCE_ARN_LENGTH:
        logger.error("setSecret: %s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_info['ARN'], MAX_RDS_DB_INSTANCE_ARN_LENGTH))
        raise ValueError("%s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_info['ARN'], MAX_RDS_DB_INSTANCE_ARN_LENGTH))

    return db_instance_info


def get_connection_params_from_rds_api(master_dict, master_instance_info):

    # Setup the client
    rds_client = boto3.client('rds')

    if master_instance_info['ARN_SYSTEM_TAG'] == 'aws:rds:primarydbinstancearn':
        # Call DescribeDBInstances RDS API
        try:
            describe_response = rds_client.describe_db_instances(DBInstanceIdentifier=master_instance_info['ARN'])
        except Exception as err:
            logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeDBInstances RDS API: %s" % err)
            raise Exception("Encountered API error while fetching connection parameters from DescribeDBInstances RDS API: %s" % err)
        # Verify the instance was found
        instances = describe_response['DBInstances']
        if len(instances) == 0:
            logger.error("setSecret: %s is not a valid DB Instance ARN. No Instances found when using DescribeDBInstances RDS API to get connection params." % master_instance_info['ARN'])
            raise ValueError("%s is not a valid DB Instance ARN. No Instances found when using DescribeDBInstances RDS API to get connection params." % master_instance_info['ARN'])

        # put connection parameters in master secret dictionary
        primary_instance = instances[0]
        master_dict['mysql_host'] = primary_instance['Endpoint']['Address']
        master_dict['port'] = primary_instance['Endpoint']['Port']
        master_dict['engine'] = primary_instance['Engine']

    elif master_instance_info['ARN_SYSTEM_TAG'] == 'aws:rds:primarydbclusterarn':
        # Call DescribeDBClusters RDS API
        try:
            describe_response = rds_client.describe_db_clusters(DBClusterIdentifier=master_instance_info['ARN'])
        except Exception as err:
            logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeDBClusters RDS API: %s" % err)
            raise Exception("Encountered API error while fetching connection parameters from DescribeDBClusters RDS API: %s" % err)
        # Verify the instance was found
        instances = describe_response['DBClusters']
        if len(instances) == 0:
            logger.error("setSecret: %s is not a valid DB Cluster ARN. No Instances found when using DescribeDBClusters RDS API to get connection params." % master_instance_info['ARN'])
            raise ValueError("%s is not a valid DB Cluster ARN. No Instances found when using DescribeDBClusters RDS API to get connection params." % master_instance_info['ARN'])

        # put connection parameters in master secret dictionary
        primary_instance = instances[0]
        master_dict['mysql_host'] = primary_instance['Endpoint']
        master_dict['port'] = primary_instance['Port']
        master_dict['engine'] = primary_instance['Engine']

    return master_dict


def get_environment_bool(variable_name, default_value):

    variable = os.environ.get(variable_name, str(default_value))
    return variable.lower() in ['true', '1', 'y', 'yes']


def get_random_password(service_client):

    passwd = service_client.get_random_password(
        ExcludeCharacters=os.environ.get('EXCLUDE_CHARACTERS', '\'>~`@#$%^*\|;:"?.,/!-_=+(){}[]*&<\''),
        PasswordLength=int(os.environ.get('PASSWORD_LENGTH', 26)),
        ExcludeNumbers=get_environment_bool('EXCLUDE_NUMBERS', False),
        ExcludePunctuation=get_environment_bool('EXCLUDE_PUNCTUATION', False),
        ExcludeUppercase=get_environment_bool('EXCLUDE_UPPERCASE', False),
        ExcludeLowercase=get_environment_bool('EXCLUDE_LOWERCASE', False),
        RequireEachIncludedType=get_environment_bool('REQUIRE_EACH_INCLUDED_TYPE', True)
    )
    return passwd['RandomPassword']


def get_user_prefix(username):
    logger.info("username coming to get prefix in get_user_prefix method -->>  %s" % username)
    if "_" in username:
        return  "_".join(username.split("_")[:-1])  # Join everything before the last underscore
    return username

def get_mysql_users(service_prefix, service_client, arn):

    # Fetch the current secret from Secrets Manager
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    master_secret_dict = get_secret_dict(service_client, current_dict['masterarn'], "AWSCURRENT")
    # Establish a connection to the database using the current secret
    conn = get_connection(master_secret_dict)
    if not conn:
        logger.error("get_users_list: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)
    
    try:
        # Execute the query to fetch the list of users from MySQL
        with conn.cursor() as cur:
            cur.execute("SELECT User FROM mysql.user")
            unfiltered_users = [row[0] for row in cur.fetchall()]
            if unfiltered_users:
                logger.info("unfiltered_users list -->>  %s " % unfiltered_users)
                filtered_users = [user for user in unfiltered_users if service_prefix in user]
            else:
                logger.info("No users found or an error occurred.")

            logger.info("get_mysql_users: Successfully fetched user list from MySQL DB for secret arn %s." % arn)
            return filtered_users
    finally:
        # Close the connection
        conn.close()


def extract_timestamp(username):
    # Split the username by the last underscore and extract the last part
    if "_" in username:
        timestamp_str = username.split("_")[-1]  # Get the part after the last underscore
        # Validate if the timestamp is the correct length (14 digits for YYYYMMDDHHMMSS)
        if len(timestamp_str) == 14 and timestamp_str.isdigit():
            return int(timestamp_str)  # Return as an integer
    return None  # Return None if no valid timestamp is found

def get_older_users(usernames):
    # Extract the timestamps from the usernames and filter out invalid ones
    valid_usernames = [username for username in usernames if extract_timestamp(username) is not None]

    # Sort the users based on the timestamps (latest timestamp first)
    sorted_users = sorted(valid_usernames, key=lambda x: extract_timestamp(x), reverse=True)
    
    # Keep the latest 2 users
    users_to_keep = sorted_users[:2]
    logger.info("Users to keep -->> %s", users_to_keep)
    
    # Users to delete are those not in the latest 2
    users_to_delete = sorted_users[2:]
    logger.info("Users to delete -->> %s", users_to_delete)
    
    return users_to_delete


def delete_mysql_user(service_client, arn, username):
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    master_secret_dict = get_secret_dict(service_client, current_dict['masterarn'], "AWSCURRENT")
    # Establish a connection to the database using the current secret
    conn = get_connection(master_secret_dict)
    if not conn:
        logger.error("delete_user: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)

    try:
        with conn.cursor() as cur:
            # Ensure the user exists before attempting to delete
            cur.execute("SELECT 1 FROM mysql.user WHERE User = %s", (username,))
            if cur.fetchone() is None:
                logger.error("delete_user: User %s does not exist in the MySQL DB for secret arn %s" % (username, arn))
                raise KeyError("User %s does not exist in the MySQL DB for secret arn %s" % (username, arn))

            # Correctly delete the user by injecting the role name safely using sql.Identifier
            drop_user_query = f"DROP USER '{username}'@'%'"
            cur.execute(drop_user_query)  # Execute the composed SQL query
            conn.commit()
            logger.info("delete_mysql_user: Successfully deleted user %s from MySQL DB for secret arn %s." % (username, arn))
    except psycopg2.Error as e:
        logger.error(f"Error occurred: {e}")
        raise
    finally:
        # Close the connection
        conn.close()