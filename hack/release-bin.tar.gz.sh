#!/usr/bin/env bash

PROJECT="github.com/H-BF/sgroups"
VERSION=$(git describe --abbrev=0 --tag)

TOOLS_ROOT="$GOPATH/src/$PROJECT"
OUTPUTDIR=$TOOLS_ROOT/_output/releases
mkdir -p "$OUTPUTDIR"

GO_LDFLAGS="-X ${PROJECT}/pkg/version.Version=${VERSION}"

os="linux"
arch=$(basename "linux/amd64")

COMPONENT_BIN="sgroups"

output_bin=${TOOLS_ROOT}/_output/bin/$arch-$os/${COMPONENT_BIN}

make to-nft
make sgroups-tf
make sg-service

tar -czvf "$OUTPUTDIR/$COMPONENT_BIN-$VERSION-$os-$arch.tar.gz" bin/*

printf "\n## Downloads\n\n" | tee -a release-notes.md
echo "| file | sha256 | sha512" | tee -a release-notes.md
echo "| ---- | ------ | ------" | tee -a release-notes.md

for file in "$OUTPUTDIR"/*.tar.gz; do
    SHA256=$(shasum -a 256 "$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$file.sha256")
    SHA512=$(shasum -a 512 "$file" | sed -e "s,$file,," | awk '{print $1}' | tee "$file.sha512")
    BASE=$(basename "$file")
    echo "| $BASE | $SHA256 | $SHA512 |" | tee -a release-notes.md
done

