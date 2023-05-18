Абстракции
========================

Подсеть
----------
Подсеть - абстрактный объект системы, который описывает набор подсетей, используемых роем для своей работы.
!!! note ""
    **Подсеть принимает на вход два аргумента**:

    - Уникальное имя
    - Подсеть

=== "curl"

    ``` bash
    curl -X 'POST' \
      'http://127.0.0.1:9000/v1/sync' \
      -H 'accept: application/json' \
      -H 'Content-Type: application/json' \
      -d '{
      "networks": {
        "networks": [
          {
            "name": "network-1",
            "network": {
              "CIDR": "10.1.0.0/24"
            }
          },
          {
            "name": "network-2",
            "network": {
              "CIDR": "10.2.0.0/24"
            }
          }
        ]
      },
      "syncOp": "FullSync"
    }'
    ```

=== "terraform"

    ``` terraform
    resource "sgroups_network" "network-1" {
      name    = network-1
      cidr    = 10.1.0.0/24
    }

    resource "sgroups_network" "network-2" {
      name    = network-2
      cidr    = 10.2.0.0/24
    }
    ```


Группа безопасности
------------------
Группа безопасности - абстрактный объект системы, объединяющий наборы подсетей на основе логической связи. Она используется для управления доступом к ресурсам в системе и упрощения описания правил доступа. Это позволяет обеспечить эффективное управление доступом и достичь высокой производительности системы в целом.

!!! note ""
    **Группа безопасноти принимает на вход два аргумента**:

    - Уникальное имя
    - Список непересекаемых подсетей

=== "curl"

    ``` bash
    curl -X 'POST' \
      'http://127.0.0.1:9000/v1/sync' \
      -H 'accept: application/json' \
      -H 'Content-Type: application/json' \
      -d '{
      "groups": {
        "groups": [
          {
            "name": "security-group-1",
            "networks": [
              {"name": "network-1"}
            ]
          },
          {
            "name": "security-group-2",
            "networks": [
              {"name": "network-2"}
            ]
          }
        ]
      },
      "syncOp": "FullSync"
    }'

    ```

=== "terraform"

    ``` terraform
    resource "sgroups_group" "group-1" {
        depends_on = [
          sgroups_network.network-1
        ]

        name        = "security-group-1"
        networks    = "network-1"
    }

    resource "sgroups_group" "group-2" {
        depends_on = [
          sgroups_network.network-2
        ]

        name        = "security-group-2"
        networks    = "network-2"
    }
    ```

Правило
----------------
Правило в данной системе описывает абстрактную сущность, которая определяет условия взаимодействия между двумя группами безопасности в системе.
!!! note ""
    **Правило принимает на вход пять аргументов**:

    - Протокол (TCP,UDP)
    - Имя группы безопасности отправителя   (SRC SG)
    - Имя группы безопасности получателя    (DST SG)
    - Список портов отправителя (SRC Ports)
    - Список портов получателя  (DST Ports)

=== "curl"

    ``` bash
    curl -X 'POST' \
      'http://127.0.0.1:9000/v1/sync' \
      -H 'accept: application/json' \
      -H 'Content-Type: application/json' \
      -d '{
      "sgRules": {
        "rules": [
          {
            "transport": "TCP",
            "sgFrom": {
              "name": "security-group-1"
            },
            "portsFrom": [
              {"from": 100, "to": 200},
              {"from": 300, "to": 400}
            ],
            "sgTo": {
              "name": "security-group-2"
            },
            "portsTo": [
              {"from": 500, "to": 600},
              {"from": 700, "to": 800}
            ]        
          }
        ]
      },
      "syncOp": "FullSync"
    }'

    ```

=== "terraform"

    ``` terraform
    resource "sgroups_rule" "rules" {
      depends_on = [
        sgroups_group.group-1,
        sgroups_group.group-2,
      ]

      proto       = "tcp"
      sg_from     = "security-group-1"
      sg_to       = "security-group-2"
      ports_from  = "100-200,300-400"
      ports_to    = "500-600,700-800"
    }

    ```

----------------

!!! note  "Опции синхронизации"
    **FullSync**: Удаление + Добавление + Обновление (по умолчанию)

    **Upsert**: Добавление + Обновление

    **Delete**: Удаление