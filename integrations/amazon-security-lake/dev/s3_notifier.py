#!/usr/bin/env python3

# Development environment only: stands in for the S3 event notifications that invoke the AWS
# Lambda function in AWS. Creates the buckets of the environment, then polls the raw bucket and
# invokes the function, in the Lambda runtime interface emulator, once for every new object, with
# the event S3 would send.
#
# Environment:
#   AWS_ENDPOINT     S3 endpoint, e.g. http://s3:5000.
#   S3_BUCKET_RAW    Bucket Logstash writes to.
#   BUCKETS          Comma-separated buckets to create, the raw one included.
#   LAMBDA_URL       Invocation URL of the emulator,
#                    e.g. http://lambda:8080/2015-03-31/functions/function/invocations.
#   POLL_SECONDS     Seconds between polls. Default: 10.

import json
import logging
import os
import time

import boto3
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("s3-notifier")


def s3_event(bucket: str, key: str, size: int) -> dict:
    """The event of an S3 ObjectCreated notification, as AWS sends it to Lambda."""
    return {"Records": [{
        "eventVersion": "2.1",
        "eventSource": "aws:s3",
        "awsRegion": os.environ.get("AWS_REGION", "us-east-1"),
        "eventName": "ObjectCreated:Put",
        "s3": {"s3SchemaVersion": "1.0", "bucket": {"name": bucket, "arn": f"arn:aws:s3:::{bucket}"},
               "object": {"key": key, "size": size}},
    }]}


def main():
    s3 = boto3.client("s3", endpoint_url=os.environ["AWS_ENDPOINT"])
    raw = os.environ["S3_BUCKET_RAW"]
    for bucket in filter(None, os.environ.get("BUCKETS", raw).split(",")):
        s3.create_bucket(Bucket=bucket)
        logger.info("bucket %s ready", bucket)
    url, poll = os.environ["LAMBDA_URL"], float(os.environ.get("POLL_SECONDS", 10))

    seen = set()
    while True:
        objects = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=raw):
            objects += [o for o in page.get("Contents", []) if o["Key"] not in seen]
        for obj in sorted(objects, key=lambda o: o["LastModified"]):
            try:
                response = requests.post(url, data=json.dumps(s3_event(raw, obj["Key"], obj["Size"])), timeout=300)
                response.raise_for_status()
                logger.info("%s: %s", obj["Key"], response.text)
                seen.add(obj["Key"])
            except requests.RequestException as e:
                logger.error("%s: the function failed, retrying on the next poll: %s", obj["Key"], e)
        time.sleep(poll)


if __name__ == "__main__":
    main()
