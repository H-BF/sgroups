#!/usr/bin/env bash

VERSION=$(git describe --abbrev=0 --tag)
PROJECT="github.com/H-BF/sgroups"
DST_PACKAGES=("sgroups" "to-nft")
DST_PACKAGE_TYPES=("rpm" "deb")
MAINTAINER="Dobry-kot <dlputilin@dobry-kot.ru>"

TOOLS_ROOT="$GOPATH/src/$PROJECT"
OUTPUTDIR=$TOOLS_ROOT/_output/releases
mkdir -p "$OUTPUTDIR"

DESCRIPTION="test"

PACKAGE_GROUP="HBF"
ITERATION=0

os="linux"
arch=$(basename "linux/amd64")


for DST_PACKAGE in "${DST_PACKAGES[@]}"
do
    for DST_PACKAGE_TYPE in "${DST_PACKAGE_TYPES[@]}"
    do
        fpm -s dir \
        -p ${OUTPUTDIR} \
        -n "$DST_PACKAGE" \
        -a ${arch} \
        -t ${DST_PACKAGE_TYPE} \
        --rpm-os ${os} \
        --license "Apache Software License 2.0" \
        --maintainer "${MAINTAINER}" \
        --description "${DESCRIPTION}" \
        --version $VERSION \
        --rpm-group "${PACKAGE_GROUP}" \
        --deb-group "${PACKAGE_GROUP}" \
        --url "https://${URL}" \
        --deb-systemd hack/services/$DST_PACKAGE.service \
        --deb-default hack/configs/$DST_PACKAGE.yaml \
        --config-files hack/configs/$DST_PACKAGE.yaml \
        bin/$DST_PACKAGE=/usr/bin/$DST_PACKAGE
    done
done


