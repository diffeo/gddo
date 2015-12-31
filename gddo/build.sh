#!/bin/bash

NAME="gddo-server"
ROOT="$GOPATH/src/github.com/golang/gddo"

cp config.go $ROOT/gddo-server/

docker build -t $NAME $ROOT && \
docker tag -f $NAME us.gcr.io/meta-internal/$NAME && \
gcloud docker push us.gcr.io/meta-internal/$NAME
