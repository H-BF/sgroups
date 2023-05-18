Агент
===========================

Установка
----------

=== "docker"

    ``` bash
    export VERSION=1.0.4
    export HBF_SERVER=example.com:80

    cat <<EOF > config-agent.yaml
    ---
    server:
      graceful-shutdown: 10s
      logger:
        # log level [optional]
        level: INFO
      extapi:
        svc:
          # default dial duraton to conect a service [optional]
          def-daial-duration: 10s
          sgroups:
            # sgroups service dial duration [optional]
            dial-duration: 3s
            # service address [mandatory]
            address: tcp://${HBF_SERVER}
            # interval(duration) backend sync-status check [mandatory]
            check-sync-status: 15s

    EOF

    docker run \
    -d \
    -v $(pwd)/config-agent.yaml:/etc/hbf/agent/config-agent.yaml \
    --name hbf-agent \
    --entrypoint "./bin/sgroups"  
    fraima/hbf-client:$VERSION -config /etc/hbf/agent/config-agent.yaml

    ```

=== "deb"

    ``` bash
    export VERSION=1.0.4
    export ARCH=amd64
    export PACKAGE_TYPE=deb
    export URL=https://github.com/fraima/sgroups/releases/download
    export RELEASE=$VERSION/to-nft_$VERSION-0_$ARCH.$PACKAGE_TYPE

    sudo wget -O /tmp/to-nft $URL/$RELEASE
    sudo dpkg -i /tmp/to-nft
    systemctl enable to-nft
    systemctl start to-nft
    ```

=== "rpm"

    ``` bash
    export VERSION=1.0.4
    export ARCH=x86_64
    export PACKAGE_TYPE=rpm
    export URL=https://github.com/fraima/sgroups/releases/download
    export RELEASE=$VERSION/to-nft_$VERSION-0_$ARCH.$PACKAGE_TYPE

    sudo wget -O /tmp/to-nft $URL/$RELEASE
    sudo dpkg -i /tmp/to-nft
    systemctl enable to-nft
    systemctl start to-nft
    ```

=== "source"

    ``` bash
    export VERSION=1.0.4
    export HBF_SERVER=example.com:80

    ## INSTALL SERVER
    git clone https://github.com/fraima/sgroups.git
    cd sgroups
    make to-nft
    cp bin/to-nft /usr/bin/to-nft
    
    mkdir -p /etc/hbf/agent/
    cat <<EOF > /etc/hbf/agent/config-agent.yaml
    ---
    server:
      graceful-shutdown: 10s
      logger:
        level: INFO

      extapi:
        svc:
          def-daial-duration: 10s
          sgroups:
            dial-duration: 3s
            address: tcp://${HBF_SERVER}
            check-sync-status: 15s
    EOF

    cat <<EOF > /etc/systemd/system/hbf-agent.service
    [Unit]
    Description=hbf agent
    Documentation=https://docs.fraima.io
    After=network.target

    [Service]
    ExecStart=/usr/bin/hbf-agent --config=/etc/hbf/agent/config.yaml
    Restart=always
    RestartSec=5
    Delegate=yes
    KillMode=process
    OOMScoreAdjust=-999
    LimitNOFILE=1048576
    LimitNPROC=infinity
    LimitCORE=infinity

    [Install]
    WantedBy=multi-user.target
    EOF

    systemctl enable hbf-agent.service
    systemctl start  hbf-agent.service
    ```


Настройка
----------
Для настройки агентов требуется использовать конфигурационный файл, который содержит поля, позволяющие настраивать параметры в соответствии с потребностями пользователей.

``` yaml
---
server:
  graceful-shutdown: 10s
  logger:
    # log level [optional]
    level: INFO
  extapi:
    svc:
      # default dial duraton to conect a service [optional]
      def-daial-duration: 10s
      sgroups:
        # sgroups service dial duration [optional]
        dial-duration: 3s
        # service address [mandatory]
        address: tcp://${hbf_server}:9000
        # interval(duration) backend sync-status check [mandatory]
        check-sync-status: 15s

```