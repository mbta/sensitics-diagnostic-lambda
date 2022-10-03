from asyncio.log import logger
import json
import logging
import os
import requests
from splunk_hec_handler import SplunkHecHandler

logging.getLogger("sensitics_logger")

def lambda_handler(event, context):
  print("Getting diagnostics...")
  url = os.environ['SENSITICS_URL']
  response = requests.get(url)
  print(response.json())

if __name__ == "__main__":
    """
    Handle command-line invocation for testing purposes.
    """
    lambda_handler(None, None)
