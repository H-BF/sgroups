Серверная часть
===========================

Установка
----------

=== "docker"

    ``` bash
    export VERSION=1.0.4
    cat <<EOF > config-server.yaml
    ---
    logger:
        # log level
        level: INFO

    metrics:
        # enable api metrics
        enable: true

    healthcheck:
        # enables|disables health check handler
        enable: true

    server:
        # server endpoint
        endpoint: tcp://0.0.0.0:9006
        # graceful shutdown period
        graceful-shutdown: 30s
    EOF

    docker run \
    -d \
    -v $(pwd)/config-server.yaml:/etc/hbf/server/config-server.yaml \
    --name hbf-server \
    --entrypoint "./bin/sgroups"  
    fraima/hbf-server:$VERSION -config /etc/hbf/server/config-server.yaml

    ```

=== "deb"

    ``` bash
    export VERSION=1.0.4
    export ARCH=amd64
    export PACKAGE_TYPE=deb
    export URL=https://github.com/fraima/swarm/releases/download
    export RELEASE=$VERSION/sgroups_$VERSION-0_$ARCH.$PACKAGE_TYPE

    sudo wget -O /tmp/sgroups $URL/$RELEASE
    sudo dpkg -i /tmp/sgroups
    systemctl enable sgroups
    systemctl start sgroups
    ```

=== "rpm"

    ``` bash
    export VERSION=1.0.4
    export ARCH=x86_64
    export PACKAGE_TYPE=rpm
    export URL=https://github.com/fraima/swarm/releases/download
    export RELEASE=$VERSION/sgroups_$VERSION-0_$ARCH.$PACKAGE_TYPE

    sudo wget -O /tmp/sgroups $URL/$RELEASE
    sudo dpkg -i /tmp/sgroups
    systemctl enable sgroups
    systemctl start sgroups
    ```

=== "source"

    ``` bash
    ## INSTALL SERVER
    git clone https://github.com/fraima/swarm.git
    cd sgroups
    make sg-service
    cp bin/sg-service /usr/bin/hbf-server
    

    cat <<EOF > /etc/hbf/config-server.yaml
    ---
    logger:
      # log level
      level: INFO

    metrics:
      # enable api metrics
      enable: true

    healthcheck:
      # enables|disables health check handler
      enable: true

    server:
      # server endpoint
      endpoint: tcp://0.0.0.0:9006
      # graceful shutdown period
      graceful-shutdown: 30s
    EOF

    cat <<EOF > /etc/systemd/system/hbf-server.service
    [Unit]
    Description=sgroups
    Documentation=https://docs.hbf.fraima.io
    After=network.target

    [Service]
    ExecStart=/usr/bin/sgroups --config=/etc/hbf/server/config.yaml
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

    systemctl enable hbf-server.service
    systemctl start hbf-server.service
    ```

Настройка
----------
Для настройки серверной части требуется использовать конфигурационный файл, который содержит поля, позволяющие настраивать параметры в соответствии с потребностями пользователей.

``` yaml
---
logger:
  # log level
  level: INFO

metrics:
  # enable api metrics
  enable: true

healthcheck:
  # enables|disables health check handler
  enable: true

server:
  # server endpoint
  endpoint: tcp://0.0.0.0:9006
  # graceful shutdown period
  graceful-shutdown: 30s
```
