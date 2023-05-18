#!/usr/bin/env bash

PROJECT="github.com/fraima/sgroups"
VERSION=$(git describe --abbrev=0 --tag)

TOOLS_ROOT="$GOPATH/src/$PROJECT"
OUTPUTDIR=$TOOLS_ROOT/_output/releases
mkdir -p "$OUTPUTDIR"

OS="linux"
ARCH=$(basename "linux/amd64")

COMPONENT_BIN="sgroups"

output_bin=${TOOLS_ROOT}/_output/bin/$ARCH-$OS/${COMPONENT_BIN}

DST_PACKAGES=("sg-service" "to-nft" "sgroups-tf")

for DST_PACKAGE in "${DST_PACKAGES[@]}"; do

make $DST_PACKAGE

if [[ "$DST_PACKAGE" == "sgroups-tf" ]]; then
  DST_PACKAGE="terraform-provider-sgroups"
fi

tar -czvf "$OUTPUTDIR/$DST_PACKAGE-$VERSION-$OS-$ARCH.tar.gz" bin/$DST_PACKAGE

done

printf "\n## Downloads\n\n" | tee -a release-notes.md
echo "| file | sha256 " | tee -a release-notes.md
echo "| ---- | ------ " | tee -a release-notes.md

for file in "$OUTPUTDIR"/*.tar.gz; do
    SHA256=$(shasum -a 256 "$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$file.sha256")
    BASE=$(basename "$file")
    echo "| $BASE | $SHA256 " | tee -a release-notes.md
done

