# The AWS Lambda function in the Lambda runtime interface emulator of AWS, for the development
# environment. The function is deployed to AWS as a .zip package instead (see the Makefile).
ARG LAMBDA_PYTHON_IMAGE=amazon/aws-lambda-python:3.12.2026.09.30.12-x86_64
FROM ${LAMBDA_PYTHON_IMAGE}

COPY requirements.aws.txt ${LAMBDA_TASK_ROOT}
RUN pip install -r requirements.aws.txt

COPY src ${LAMBDA_TASK_ROOT}

CMD [ "lambda_function.lambda_handler" ]
