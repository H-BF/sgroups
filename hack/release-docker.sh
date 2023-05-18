#!/usr/bin/env bash

VERSION=$(git describe --abbrev=0 --tag)
docker login -p $DOCKER_TOKEN -u $DOCKER_LOGIN
docker build -f Dockerfile.server -t fraima/hbf-server:$VERSION .
docker build -f Dockerfile.client -t fraima/hbf-client:$VERSION .
docker push fraima/hbf-client:$VERSION
docker push fraima/hbf-server:$VERSION
