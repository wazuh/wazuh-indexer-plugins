# Amazon Security Lake unit tests

Unit tests of the conversion of the Wazuh findings into OCSF and of the AWS Lambda function, with mocked AWS services (moto): no AWS account is needed.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m pytest -v
```
