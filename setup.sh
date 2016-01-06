#!/bin/bash

PROJ="meta-internal"
NAME="godoc"
ZONE="us-central1-b"

gcloud config set project $PROJ
gcloud config set container/cluster $NAME
gcloud config set compute/zone $ZONE

# create the cluster if desired
if [[ $1 == "--create" ]]; then
	gcloud container clusters create --enable-cloud-logging --enable-cloud-monitoring --machine-type n1-standard-4 $NAME
fi

gcloud container clusters get-credentials $NAME

echo "configured gcloud with cluster $NAME in project $PROJ, zone $ZONEs"
