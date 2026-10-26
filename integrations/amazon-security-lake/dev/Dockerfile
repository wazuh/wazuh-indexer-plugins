# Development environment only: the stand-in for the S3 event notifications (s3_notifier.py).
FROM python:3.12-slim
RUN pip install --no-cache-dir boto3==1.43.118 requests==2.33.0
COPY s3_notifier.py /usr/local/bin/s3_notifier.py
ENTRYPOINT ["python", "/usr/local/bin/s3_notifier.py"]
