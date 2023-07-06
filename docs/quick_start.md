
**Как начать?**
---------------

На данный момент мы предлагаем два способа настройки нашей системы: 

- Напрямую через использование API. -> swagger
- С помощью Terraform провайдера.

Если вы выберете настройку через API, то вам необходимо будет создать запросы к нашему API, чтобы интегрировать систему в ваш процесс.

Альтернативно, если вы выберете настройку через Terraform, то вам нужно будет воспользоваться нашим провайдером и определить конфигурацию системы в Terraform файле. Это позволит вам быстро и легко настроить систему с помощью готовых инструментов.

Независимо от выбранного способа настройки, мы готовы помочь вам достичь требуемого результата и интегрировать hbf в вашу инфраструктуру.


**Пример**
--------
Предположим, что у нас две команды `teamA` и `teamB`, команда `teamA` пишет бекенд, а `teamB` пишет фронтенд.
Требуется создать две виртуальные машины одну для `teamA` вторую для `teamB` и открыть доступ от `teamA/backend` до `teamB/frontend` по `80/TCP`.

Для реализации данной задачи мы ввели 4 абстракции.


- `unit` - владелец области (`teamA`, `teamB`)
- `security group` - виртуальная группа области владельца в которой находятся подсети, логически сгруппированных узлов. (`frontend`, `backend`)
- `networks` - подсети управляемых узлов.
- `rule` - правила доступа между `security group` как в рамках одного так и в рамках разных `unit`.

=== "Yandex-Cloud"

    ``` bash 
    cat <<EOF >> templates/cloudi-init.yaml
    #cloud-config
    version: v1

    users:
      - name: dkot
        sudo: ALL=(ALL) NOPASSWD:ALL
        groups: users, admin
        shell: /bin/bash
        lock_passwd: true
        ssh_authorized_keys:
          - ${SSH_PUBLIC_KEY}

    packages:
      - nftables
      - git

    runcmd:
      - git clone https://github.com/H-BF/sgroups
      - cd sgroups
      - make to-nft
      - cp bin/to-nft /usr/bin/hbf-client
      - chmod +x /usr/bin/hbf-client
      - systemctl enable  hbf.service
      - systemctl start   hbf.service

    write_files:

      - path: /etc/hbf/client.yaml
        owner: root:root
        permissions: '0644'
        content: |
            ---
            graceful-shutdown: 10s
            logger:
                level: INFO

            extapi:
                svc:
                def-daial-duration: 10s
                sgroups:
                    dial-duration: 3s
                    address: tcp://193.32.219.99:9000
                    check-sync-status: 5s

      - path: /etc/systemd/system/hbf-client.service
        owner: root:root
        permissions: '0644'
        content: |
            [Unit]
            Description=hbf

            Wants=network-online.target
            After=network-online.target

            [Service]
            ExecStart=/usr/bin/hbf-client -config /etc/hbf/client.yaml

            Restart=always
            StartLimitInterval=0
            RestartSec=10

            [Install]
            WantedBy=multi-user.target
      
    EOF
    ```
    ``` { .tf }
        <настройки провайдера>

        # Определяем VPC
        resource "yandex_vpc_network" "hbf-vpc" {
        name = "hbf-vpc"
        }

        # Определяем тестовую подсеть из которой будут выделяться адреса для ВМ.
        resource "yandex_vpc_subnet" "hbf-subnet" {
            name            = "hbf-subnet"

            v4_cidr_blocks  = ["10.143.0.0/24"]
            zone            =  "ru-central1-a"

            network_id      = yandex_vpc_network.hbf-vpc.id
        }

        resource "yandex_compute_instance" "team-a-backend" {

            description = "HBF-TEAM-A-BACKEND"
        
            platform_id = "standard-v1"

            zone = "ru-central1-a"

            resources {
                cores         = 2
                memory        = 4
                core_fraction = 100
            }

            boot_disk {
                initialize_params {
                image_id = "fd8kdq6d0p8sij7h5qe3"
                size     = 30
                type     = "network-hdd"
                }
            }

            network_interface {
                subnet_id = yandex_vpc_subnet.hbf-subnet.id
                nat = true
            }

            lifecycle {
                ignore_changes = [
                metadata
                ]
            }

            metadata = {
                user-data = "${file("templates/cloudi-init.yaml")}"
            }
        }

        resource "yandex_compute_instance" "team-a-frontend" {

            description = "HBF-TEAM-A-FRONTEND"
        
            platform_id = "standard-v1"

            zone = "ru-central1-a"

            resources {
                cores         = 2
                memory        = 4
                core_fraction = 100
            }

            boot_disk {
                initialize_params {
                    image_id = "fd8kdq6d0p8sij7h5qe3"
                    size     = 30
                    type     = "network-hdd"
                }
            }

            network_interface {
                subnet_id = yandex_vpc_subnet.hbf-subnet.id
                nat = true
            }

            lifecycle {
                ignore_changes = [
                metadata
                ]
            }

            metadata = {
                user-data = "${file("templates/cloudi-init.yaml")}"
            }
        }


    ```

=== "hbf"

    ```{ .tf .annotate }
        <настройки провайдера> 

        locals {

            security_groups  = [
                {
                    name = "teamA_backend"
                    cidrs = [
                        "${yandex_compute_instance.team-a-backend.network_interface[0].ip_address}/32"
                    ]
                    rules = [
                        {
                            sg_to  = "teamA_frontend"
                            access = [
                                {
                                    description = "access from teamA_backend to teamA_frontend"
                                    protocol    = "tcp"
                                    ports_to    = [
                                        80,
                                        443
                                    ]
                                },
                            ]
                        },
                        {
                            sg_to  = "hbf-server"
                            access = [
                                {
                                    description = "access from teamA_backend to hbf-server"
                                    protocol    = "tcp"
                                    ports_to    = [
                                        9000
                                    ]
                                }
                            ]
                        },
                    ]
                },
                {
                    name = "teamA_frontend"
                    cidrs = [
                        "${yandex_compute_instance.team-a-frontend.network_interface[0].ip_address}/32"
                    ]
                    rules = [
                        {
                            sg_to   = "hbf-server"
                            access  = [
                                {
                                    description = "access from teamA_backend to hbf-server"
                                    protocol    = "tcp"
                                    ports_to    = [
                                        9000
                                    ]
                                }
                            ]
                        },
                    ]
                },
                {
                    name = "hbf-server"
                    cidrs = [
                        "193.32.219.99/32"
                    ]
                    rules = []
                },
                {
                    name = "world"
                    cidrs = [
                        "176.0.0.0/8"
                    ]
                    rules = [
                        {
                            sg_to  = "teamA_backend"
                            access = [
                                {
                                    description = "access from world to teamA_backend by ssh"
                                    protocol    = "tcp"
                                    ports_to    = [
                                        22
                                    ]
                                },
                            ]
                        },
                        {
                            sg_to  = "teamA_frontend"
                            access = [
                                {
                                    description = "access from world to teamA_frontend by ssh"
                                    protocol    = "tcp"
                                    ports_to    = [
                                        22
                                    ]
                                }
                            ]
                        },
                    ]
                }
            ]
        }


        module "firewall" {
            depends_on = [
                yandex_compute_instance.team-a-backend,
                yandex_compute_instance.team-a-frontend
            ]
            source = "../modules/hbf"
            security_groups = local.security_groups
        }

    ```