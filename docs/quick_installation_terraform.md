Базовая установка
===========================

Terraform провайдер
----------


=== "bin"

    ``` bash
    export VERSION=1.0.4
    export OS=linux
    export ARCH=amd64
    export GIT=https://github.com/fraima/swarm/releases/download/${VERSION}
    export RELEASE_NAME=terraform-provider-sgroups
    export RELEASE_POSTFIX=${RELEASE_NAME}-${VERSION}-${OS}-${ARCH}.tar.gz
    export PLUGIN_PATH=~/.terraform.d/plugins/registry.terraform.io/fraima/swarm

    mkdir -p $PLUGIN_PATH/$VERSION/${OS}_${ARCH}
    wget -O ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION} ${GIT}/${RELEASE_POSTFIX}

    chmod +x ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION}

    cat <<EOF >> ~/.terraformrc
    plugin_cache_dir = "${HOME}/.terraform.d/plugin-cache"
    disable_checkpoint = true
    EOF
    ```

=== "source"

    ``` bash
    export VERSION=1.0.4
    export OS=linux
    export ARCH=amd64
    export RELEASE_NAME=terraform-provider-sgroups
    export PLUGIN_PATH=~/.terraform.d/plugins/registry.terraform.io/fraima/swarm

    git clone https://github.com/fraima/swarm.git
    cd sgroups
    make sgroups-tf
    cp bin/${RELEASE_NAME} ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION}
    mkdir -p $PLUGIN_PATH/$VERSION/${OS}_${ARCH}
    chmod +x ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION}

    cat <<EOF >> ~/.terraformrc
    plugin_cache_dir = "${HOME}/.terraform.d/plugin-cache"
    disable_checkpoint = true
    EOF
    ```
