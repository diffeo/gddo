#!/bin/bash

docker run --name tmp -p 9090:80 \
	-v $(pwd)/secrets/ssl:/ssl \
	-v $(pwd)/secrets/github:/github \
	gddo-server

docker rm tmp
