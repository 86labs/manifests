FROM python:3.11-slim-bookworm

ARG MLFLOW_VERSION

RUN pip3 install --upgrade pip && \
    pip3 install mlflow==${MLFLOW_VERSION} \
        boto3 \
        PyMySQL

ENTRYPOINT ["mlflow", "server"]
