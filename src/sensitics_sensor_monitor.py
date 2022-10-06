import boto3
from botocore.exceptions import ClientError
import time
import logging
import os
import sys
import requests
from splunk_hec_handler import SplunkHecHandler


def lambda_handler(event, context):
    logger = get_logger()
    logger.debug("Getting diagnostics...")

    try:
        start = time.time()
        response = requests.get(os.environ["SENSITICS_URL"], timeout=5)
        end = time.time()
        logger.debug(f'Got diagnostics in {end - start} seconds')
        response.raise_for_status()
        log_sensor_statuses(response.json()["sensors"], logger)
    except requests.exceptions.HTTPError as errh:
        logger.error("Http Error:", errh)
        sys.exit()
    except requests.exceptions.ConnectionError as errc:
        logger.error("Error Connecting:", errc)
        sys.exit()
    except requests.exceptions.Timeout as errt:
        logger.error("Timeout Error:", errt)
        sys.exit()
    except requests.exceptions.RequestException as err:
        logger.error("Exception:", err)
        sys.exit()


def log_sensor_statuses(sensors, logger):
    logger.debug("Logging to Splunk...")
    start = time.time()
    for sensor in sensors:
        logger.info(sensor)
    end = time.time()

    logger.debug(f'Logged in {end - start} seconds')


def get_logger():
    splunk_hec_host = os.environ["SPLUNK_HEC_HOST"]
    hec_token_secret_name = os.environ["HEC_TOKEN_AWS_SECRET_NAME"]
    splunk_index = os.environ["SPLUNK_INDEX"]
    splunk_handler = SplunkHecHandler(
        splunk_hec_host,
        get_splunk_token(hec_token_secret_name),
        index=splunk_index,
        port=443, 
        proto='https'
    )
    logger = logging.getLogger("SplunkHecHandler")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(splunk_handler)

    return logger


def get_splunk_token(secret_name):
    secretsmanager = boto3.client("secretsmanager")

    try:
        secret_value = secretsmanager.get_secret_value(SecretId=secret_name)
    except ClientError as error:
        error_message = error.response["Error"]["Message"]
        print(f"Couldn't get value for secret {secret_name}: {error_message}")
        sys.exit()
    else:
        return secret_value["SecretString"]


if __name__ == "__main__":
    """
    Handle command-line invocation for testing purposes.
    """
    lambda_handler(None, None)
