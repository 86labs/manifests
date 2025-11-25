FROM python:3.11-slim-bookworm

ARG MLFLOW_VERSION

RUN pip3 install --upgrade pip && \
    pip3 install mlflow[auth,extras]==${MLFLOW_VERSION} \
        boto3 \
        PyMySQL \
        pyjwt \
        cryptography \
        requests \
        flask-wtf

ENTRYPOINT ["mlflow", "server"]
