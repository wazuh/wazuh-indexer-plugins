"""
AWS Lambda function of the Amazon Security Lake integration.

Invoked by the S3 event notifications of the bucket that Logstash writes the Wazuh findings
to. Converts every file into OCSF Detection Findings, and writes them in Parquet into the
location of the Wazuh custom source in the Security Lake bucket:

    ext/<SOURCE_LOCATION>/region=<REGION>/accountId=<ACCOUNT_ID>/eventDay=<YYYYMMDD>/<file>.parquet

The name of the Parquet file derives from the name of the source file, so a retried
invocation overwrites its own output instead of duplicating it.

Environment:
    AWS_BUCKET        Security Lake bucket, e.g. aws-security-data-lake-us-east-1-xxxxxxxxxxxx.
    SOURCE_LOCATION   Location of the custom source under ext/, as Security Lake shows it:
                      the source name, or name/version, e.g. wazuh or wazuh/1.0.
    ACCOUNT_ID        AWS account ID of the custom source.
    REGION            AWS region of the custom source.
    ROLE_ARN          Optional. Role of the custom source to write to the Security Lake bucket with,
                      for a Security Lake in another account. Without it, the function writes
                      with its own role.
    EXTERNAL_ID       Optional. External ID of that role.
    S3_BUCKET_OCSF    Optional. Bucket to also write the findings to, as OCSF JSON, for debugging.
    AWS_ENDPOINT      Optional. Endpoint of S3 and STS, for S3-compatible storage in development.
"""
import gzip
import io
import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone

import boto3
import pyarrow as pa
import pyarrow.parquet as pq

import ocsf
import wazuh_ocsf_converter

logger = logging.getLogger()
logger.setLevel("INFO")

REQUIRED_VARIABLES = ("AWS_BUCKET", "SOURCE_LOCATION", "ACCOUNT_ID", "REGION")
DAY = re.compile(r"^\d{8}$")


class ConfigurationError(Exception):
    pass


def client(service: str, credentials: dict = None):
    """A boto3 client, with the given temporary credentials, or the default ones of the function."""
    kwargs = {}
    if os.environ.get("AWS_ENDPOINT"):
        kwargs["endpoint_url"] = os.environ["AWS_ENDPOINT"]
    if os.environ.get("REGION"):
        kwargs["region_name"] = os.environ["REGION"]
    if credentials:
        kwargs.update(aws_access_key_id=credentials["AccessKeyId"],
                      aws_secret_access_key=credentials["SecretAccessKey"],
                      aws_session_token=credentials["SessionToken"])
    return boto3.client(service, **kwargs)


def assume_role(arn: str, external_id: str = None, session_name: str = "wazuh-security-lake") -> dict:
    """Temporary credentials of a role."""
    kwargs = {"RoleArn": arn, "RoleSessionName": session_name}
    if external_id:
        kwargs["ExternalId"] = external_id
    return client("sts").assume_role(**kwargs)["Credentials"]


def read_lines(s3, bucket: str, key: str) -> list:
    """Lines of an S3 object, gzip-compressed or not."""
    data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8").splitlines()


def to_parquet(findings: list) -> bytes:
    """Findings as a Parquet file of the OCSF schema of the integration."""
    buffer = io.BytesIO()
    pq.write_table(pa.Table.from_pylist(findings, schema=ocsf.SCHEMA), buffer, compression="zstd")
    return buffer.getvalue()


def destination_key(key: str, source_location: str, region: str, account_id: str, extension: str) -> str:
    """
    Key of the output of a source file, in the partition of its day. Logstash writes the files
    under <kind>/<category>/<YYYYMMDD>/: the day is the day of the documents of the file.

    findings/security/20261022/ls.s3.0c4e.2026-10-22T10.00.part0.txt.gz becomes
    ext/wazuh/region=us-east-1/accountId=111111111111/eventDay=20261022/findings_security_ls.s3.0c4e.2026-10-22T10.00.part0.parquet
    """
    parts = key.split("/")
    day = next((p for p in reversed(parts[:-1]) if DAY.match(p)), None)
    if day is None:
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        logger.warning("no day in the key %s: using the current day, %s", key, day)
    base = re.sub(r"(\.txt)?(\.gz)?$", "", parts[-1])
    name = "_".join([p for p in parts[:-1] if p != day] + [base])
    return f"ext/{source_location.strip('/')}/region={region}/accountId={account_id}/eventDay={day}/{name}.{extension}"


def lambda_handler(event, context):
    missing = [name for name in REQUIRED_VARIABLES if not os.environ.get(name)]
    if missing:
        raise ConfigurationError(f"environment variables not set: {', '.join(missing)}")
    lake_bucket = os.environ["AWS_BUCKET"]
    source_location = os.environ["SOURCE_LOCATION"]
    account_id = os.environ["ACCOUNT_ID"]
    region = os.environ["REGION"]
    ocsf_bucket = os.environ.get("S3_BUCKET_OCSF")

    # The source files are read with the role of the function. The Security Lake bucket is
    # written with the role of the custom source, when it is in another account.
    source = client("s3")
    if os.environ.get("ROLE_ARN"):
        logger.info("assuming the role %s", os.environ["ROLE_ARN"])
        destination = client("s3", assume_role(os.environ["ROLE_ARN"], os.environ.get("EXTERNAL_ID")))
    else:
        destination = source

    results = []
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"], encoding="utf-8")
        logger.info("converting s3://%s/%s", bucket, key)

        findings, skipped = wazuh_ocsf_converter.transform_events(read_lines(source, bucket, key))
        result = {"key": key, "findings": len(findings), "skipped": skipped}
        if findings:
            parquet_key = destination_key(key, source_location, region, account_id, "parquet")
            destination.put_object(Bucket=lake_bucket, Key=parquet_key, Body=to_parquet(findings))
            result["parquet"] = parquet_key
            logger.info("wrote %d findings to s3://%s/%s", len(findings), lake_bucket, parquet_key)
            if ocsf_bucket:
                ocsf_key = destination_key(key, source_location, region, account_id, "json")
                source.put_object(Bucket=ocsf_bucket, Key=ocsf_key, Body=json.dumps(findings).encode("utf-8"))
                result["ocsf"] = ocsf_key
        else:
            logger.info("no findings in s3://%s/%s", bucket, key)
        results.append(result)
    return {"files": results}
