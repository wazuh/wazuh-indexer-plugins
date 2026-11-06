FROM python:3.12-slim
WORKDIR /home/events-generator
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY run.py .
COPY samples/ samples/
ENTRYPOINT ["python", "run.py"]
