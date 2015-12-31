#!/bin/bash

NAME="gddo-frontend"

docker build -t $NAME . && \
docker tag -f $NAME us.gcr.io/meta-internal/$NAME && \
gcloud docker push us.gcr.io/meta-internal/$NAME
