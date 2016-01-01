#!/bin/bash

docker build -t gddo-frontend . && \
docker run --name gf \
	-p 8080:8080 -p 8081:8081 \
	-e "HOST=:8080" -e "TLS_HOST=:8081" -e "FQDN=meta-godoc.ngrok.io" \
	-e "GDDO_HOST=$(docker-machine ip default):9090" \
	-e "GOOGLE_APPLICATION_CREDENTIALS=/gcloud/application_default_credentials.json" \
	-v $(pwd)/../secrets/ssl:/ssl -v $(pwd)/../secrets/oauth:/oauth -v "$HOME/.config/gcloud":/gcloud \
	gddo-frontend

docker rm gf
