#!/usr/bin/env bash

VERSION=$(git describe --abbrev=0 --tag)
PROJECT="github.com/fraima/sgroups"
DST_PACKAGES=("sgroups" "to-nft")
DST_PACKAGE_TYPES=("rpm" "deb")
MAINTAINER="Dobry-kot <dlputilin@dobry-kot.ru>"

TOOLS_ROOT="$GOPATH/src/$PROJECT"
OUTPUTDIR=$TOOLS_ROOT/_output/releases
mkdir -p "$OUTPUTDIR"

DESCRIPTION="test"

PACKAGE_GROUP="HBF"
ITERATION=0

OS="linux"
ARCH=$(basename "linux/amd64")


for DST_PACKAGE in "${DST_PACKAGES[@]}"
do
    for DST_PACKAGE_TYPE in "${DST_PACKAGE_TYPES[@]}"
    do
        fpm -s dir \
        -p "${OUTPUTDIR}" \
        -n "${DST_PACKAGE}" \
        -a "${ARCH}" \
        -t "${DST_PACKAGE_TYPE}" \
        --license       "Apache Software License 2.0" \
        --iteration     "0" \
        --rpm-os        "${OS}" \
        --maintainer    "${MAINTAINER}" \
        --description   "${DESCRIPTION}" \
        --version       "${VERSION}" \
        --rpm-group     "${PACKAGE_GROUP}" \
        --deb-group     "${PACKAGE_GROUP}" \
        --url           "https://${URL}" \
        bin/$DST_PACKAGE=/usr/bin/$DST_PACKAGE \
        hack/services/$DST_PACKAGE.service=/lib/systemd/system/$DST_PACKAGE.service \
        hack/configs/$DST_PACKAGE.yaml=/etc/hbf/server/config.yaml
    done
done

for file in $(ls $OUTPUTDIR/ | grep -E "deb|rpm"); do
    SHA256=$(shasum -a 256 "$OUTPUTDIR/$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$OUTPUTDIR/$file.sha256")
    BASE=$(basename "$file")
    echo "| $BASE | $SHA256 " | tee -a release-notes.md
done

