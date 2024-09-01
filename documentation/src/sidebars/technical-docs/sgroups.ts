export const sgroups = [
  {
    type: 'doc',
    label: 'Установка',
    id: 'tech-docs/sgroups/installation-server',
  },
  {
    type: 'doc',
    label: 'Миграция',
    id: 'tech-docs/sgroups/goose',
  },
  {
    type: 'doc',
    label: 'Мониторинг',
    id: 'tech-docs/sgroups/monitoring',
  },
  {
    type: 'doc',
    label: 'Настройка TLS',
    id: 'tech-docs/sgroups/tls-configuration-server',
  },
  {
    type: 'doc',
    label: 'Описание базы данных',
    id: 'tech-docs/sgroups/database',
  },
  {
    type: 'category',
    label: 'API',
    items: [
      {
        type: 'doc',
        label: 'POST /v2/sync',
        id: 'tech-docs/sgroups/api/v1/sync',
      },
      {
        type: 'doc',
        label: 'POST /v2/list-security-groups',
        id: 'tech-docs/sgroups/api/v1/security-groups',
      },
      {
        type: 'doc',
        label: 'GET /v2/{address}/sg',
        id: 'tech-docs/sgroups/api/v1/address-sg',
      },
      {
        type: 'doc',
        label: 'POST /v2/list-networks',
        id: 'tech-docs/sgroups/api/v1/networks',
      },
      {
        type: 'doc',
        label: 'GET /v2/sg/{sgName}/subnets',
        id: 'tech-docs/sgroups/api/v1/subnets',
      },
      {
        type: 'doc',
        label: 'POST /v2/sg-sg-icmp-rules',
        id: 'tech-docs/sgroups/api/v1/sg-sg-icmp-rules',
      },
      {
        type: 'doc',
        label: 'POST /v2/sg-icmp-rules',
        id: 'tech-docs/sgroups/api/v1/sg-icmp-rules',
      },
      {
        type: 'doc',
        label: 'POST /v2/sg-sg-rules',
        id: 'tech-docs/sgroups/api/v1/rules',
      },
      {
        type: 'doc',
        label: 'POST /v2/fqdn-rules',
        id: 'tech-docs/sgroups/api/v1/fqdn-rules',
      },
      {
        type: 'doc',
        label: 'POST /v2/ie-cidr-sg-rules',
        id: 'tech-docs/sgroups/api/v1/cidr-sg-rules',
      },
      {
        type: 'doc',
        label: 'POST /v2/ie-cidr-sg-icmp-rules',
        id: 'tech-docs/sgroups/api/v1/cidr-sg-icmp-rules',
      },
      {
        type: 'doc',
        label: 'POST v2/ie-sg-sg-rules',
        id: 'tech-docs/sgroups/api/v1/ie-sg-sg-rules',
      },
      {
        type: 'doc',
        label: 'POST v2/ie-sg-sg-icmp-rules',
        id: 'tech-docs/sgroups/api/v1/ie-sg-sg-icmp-rules',
      },
      {
        type: 'doc',
        label: 'GET /v2/sync/status',
        id: 'tech-docs/sgroups/api/v1/status',
      },
    ],
  },
]
