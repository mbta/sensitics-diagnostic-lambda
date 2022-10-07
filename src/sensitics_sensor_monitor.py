"""
This Lambda function makes a request to an endpoint provided by Sensitics to fetch diagnostics
for Urine Detection sensors deployed in MBTA elevators and then logs the diagnostics to
Splunk.
"""

import time
import logging
import os
import sys
import requests
import boto3  # pylint: disable=E0401
from botocore.exceptions import ClientError  # pylint: disable=E0401
from splunk_hec_handler import SplunkHecHandler


def get_splunk_token(secret_name):
    """
    Helper method to fetch secrets from AWS Secrets Manager
    """
    secretsmanager = boto3.client("secretsmanager")

    try:
        secret_value = secretsmanager.get_secret_value(SecretId=secret_name)
    except ClientError as error:
        error_message = error.response["Error"]["Message"]
        print(f"Couldn't get value for secret {secret_name}: {error_message}")
        sys.exit()
    else:
        return secret_value["SecretString"]


# Configure logger
splunk_handler = SplunkHecHandler(
    os.environ["SPLUNK_HEC_HOST"],
    get_splunk_token(os.environ["HEC_TOKEN_AWS_SECRET_NAME"]),
    index=os.environ["SPLUNK_INDEX"],
    port=443,
    proto="https",
)
logger = logging.getLogger("SplunkHecHandler")
logger.setLevel(logging.DEBUG)
logger.addHandler(splunk_handler)


def lambda_handler(event, context):  # pylint: disable=W0613
    """
    Entry point for lambda invocation via Eventbridge
    """
    print("Getting diagnostics...")

    try:
        start = time.time()
        response = requests.get(os.environ["SENSITICS_URL"], timeout=5)
        end = time.time()
        response.raise_for_status()
        request_timing_log = {"message": "Sensitics RTT", "duration": end - start}
        logger.debug(request_timing_log)
        log_sensor_statuses(response.json()["sensors"])
    except requests.exceptions.HTTPError as errh:
        log = {"type" : "Http", "exception" : errh}
        logger.error(log)
        sys.exit()
    except requests.exceptions.ConnectionError as errc:
        log = {"type" : "Connection", "exception" : errc}
        logger.error(log)
        sys.exit()
    except requests.exceptions.Timeout as errt:
        log = {"type" : "Timeout", "exception" : errt}
        logger.error(log)
        sys.exit()
    except requests.exceptions.RequestException as err:
        log = {"type" : "Request", "exception" : err}
        logger.error(log)
        sys.exit()


def log_sensor_statuses(sensors):
    """
    Helper method to iterate through sensor list and log to Splunk
    """
    print("Logging to Splunk...")
    start = time.time()
    for sensor_status in sensors:
        sensor_status["message"] = "Sensor info"
        logger.info(sensor_status)
    end = time.time()

    splunk_timing_log = {"message": "Log to splunk time", "duration": end - start}
    logger.debug(splunk_timing_log)


if __name__ == "__main__":
    lambda_handler(None, None)
