import gzip
import io
import json

import boto3
import pyarrow.parquet as pq
import pytest
from moto import mock_aws

import lambda_function

RAW_BUCKET = "wazuh-findings-raw"
LAKE_BUCKET = "aws-security-data-lake-us-east-1-example"
OCSF_BUCKET = "wazuh-findings-ocsf"
RAW_KEY = "findings/security/20261022/ls.s3.0c4e9b1a.2026-10-22T10.00.part0.txt.gz"
PARQUET_KEY = ("ext/wazuh/region=us-east-1/accountId=111111111111/eventDay=20261022/"
               "findings_security_ls.s3.0c4e9b1a.2026-10-22T10.00.part0.parquet")


def finding(doc_id, level="high"):
    return {
        "@timestamp": "2026-10-22T10:00:00.000Z",
        "wazuh": {"rule": {"id": "r1", "title": "Rule title", "level": level}, "agent": {"id": "001", "name": "web-01"}},
        "_export": {"id": doc_id, "data_stream": "wazuh-findings-v5-security"},
    }


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.setenv("AWS_BUCKET", LAKE_BUCKET)
    monkeypatch.setenv("SOURCE_LOCATION", "wazuh")
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in ("ROLE_ARN", "EXTERNAL_ID", "S3_BUCKET_OCSF", "AWS_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        for bucket in (RAW_BUCKET, LAKE_BUCKET, OCSF_BUCKET):
            s3.create_bucket(Bucket=bucket)
        lines = "\n".join([json.dumps(finding("a")), json.dumps(finding("b", "low")), "not json"]) + "\n"
        s3.put_object(Bucket=RAW_BUCKET, Key=RAW_KEY, Body=gzip.compress(lines.encode()))
        yield s3


def s3_event(key, bucket=RAW_BUCKET):
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


def read_parquet(s3, key):
    return pq.read_table(io.BytesIO(s3.get_object(Bucket=LAKE_BUCKET, Key=key)["Body"].read())).to_pylist()


def test_converts_a_file_into_the_security_lake_partition(environment):
    result = lambda_function.lambda_handler(s3_event(RAW_KEY), None)
    assert result == {"files": [{"key": RAW_KEY, "findings": 2, "skipped": 1, "parquet": PARQUET_KEY}]}
    rows = read_parquet(environment, PARQUET_KEY)
    assert [r["finding_info"]["uid"] for r in rows] == ["a", "b"]
    assert [r["severity_id"] for r in rows] == [4, 2]


def test_a_retry_overwrites_its_own_output(environment):
    lambda_function.lambda_handler(s3_event(RAW_KEY), None)
    lambda_function.lambda_handler(s3_event(RAW_KEY), None)
    keys = [o["Key"] for o in environment.list_objects_v2(Bucket=LAKE_BUCKET)["Contents"]]
    assert keys == [PARQUET_KEY]


def test_url_encoded_keys(environment):
    key = "findings/security/20261022/ls.s3.with space.part0.txt.gz"
    environment.put_object(Bucket=RAW_BUCKET, Key=key, Body=gzip.compress((json.dumps(finding("c")) + "\n").encode()))
    result = lambda_function.lambda_handler(s3_event("findings/security/20261022/ls.s3.with+space.part0.txt.gz"), None)
    assert result["files"][0]["findings"] == 1


def test_optional_ocsf_json_copy(environment, monkeypatch):
    monkeypatch.setenv("S3_BUCKET_OCSF", OCSF_BUCKET)
    result = lambda_function.lambda_handler(s3_event(RAW_KEY), None)
    body = environment.get_object(Bucket=OCSF_BUCKET, Key=result["files"][0]["ocsf"])["Body"].read()
    assert len(json.loads(body)) == 2


def test_a_file_without_findings_writes_nothing(environment):
    environment.put_object(Bucket=RAW_BUCKET, Key="findings/security/20261022/empty.txt", Body=b"{}\n")
    result = lambda_function.lambda_handler(s3_event("findings/security/20261022/empty.txt"), None)
    assert result["files"][0] == {"key": "findings/security/20261022/empty.txt", "findings": 0, "skipped": 1}
    assert environment.list_objects_v2(Bucket=LAKE_BUCKET).get("KeyCount") == 0


def test_cross_account_role(environment, monkeypatch):
    monkeypatch.setenv("ROLE_ARN", "arn:aws:iam::222222222222:role/wazuh-security-lake")
    monkeypatch.setenv("EXTERNAL_ID", "example-external-id")
    result = lambda_function.lambda_handler(s3_event(RAW_KEY), None)
    assert result["files"][0]["findings"] == 2


def test_missing_configuration(monkeypatch):
    monkeypatch.delenv("AWS_BUCKET", raising=False)
    with pytest.raises(lambda_function.ConfigurationError):
        lambda_function.lambda_handler(s3_event(RAW_KEY), None)


@pytest.mark.parametrize("key,expected", [
    (RAW_KEY, PARQUET_KEY),
    ("custom/my-stream/20261023/ls.s3.1.part3.txt.gz",
     "ext/wazuh/region=us-east-1/accountId=111111111111/eventDay=20261023/custom_my-stream_ls.s3.1.part3.parquet"),
])
def test_destination_key(key, expected):
    assert lambda_function.destination_key(key, "wazuh", "us-east-1", "111111111111", "parquet") == expected


def test_destination_key_with_a_versioned_source():
    key = lambda_function.destination_key(RAW_KEY, "/wazuh/1.0/", "us-east-1", "111111111111", "parquet")
    assert key.startswith("ext/wazuh/1.0/region=us-east-1/")
