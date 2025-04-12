PHONY: image
export MLFLOW_VERSION ?= 2.21.3
image:
	docker build -t gfeldman8/mlflow:${MLFLOW_VERSION} \
		--build-arg MLFLOW_VERSION=${MLFLOW_VERSION} \
		-f ./Dockerfile \
		.

push:
	docker push gfeldman8/mlflow:${MLFLOW_VERSION}
