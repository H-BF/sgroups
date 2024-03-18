/* eslint-disable import/no-default-export */
import { toNft } from './src/sidebars/technical-docs/to-nft'
import { sgroups } from './src/sidebars/technical-docs/sgroups'
import { terraform } from './src/sidebars/technical-docs/terraform'
import { ruleConfiguration } from './src/sidebars/technical-docs/rule-configuration'

const sidebars = {
  informationSidebar: [
    {
      type: 'doc',
      label: 'Введение',
      id: 'info/introduction',
    },
    {
      type: 'doc',
      label: 'Выбор инструмента',
      id: 'info/toolset',
    },
    {
      type: 'doc',
      label: 'Терминология',
      id: 'info/terminology',
    },
  ],

  techDocs: [
    {
      type: 'doc',
      label: 'Компоненты',
      id: 'tech-docs/components',
    },
    {
      type: 'doc',
      label: 'Требования',
      id: 'tech-docs/installation-system-requirements',
    },
    {
      type: 'category',
      label: 'HBF-агент',
      collapsed: false,
      items: toNft,
    },
    {
      type: 'category',
      label: 'HBF-сервер',
      collapsed: false,
      items: sgroups,
    },
    {
      type: 'category',
      label: 'Terraform',
      collapsed: false,
      items: terraform,
    },
    {
      type: 'category',
      label: 'Конфигурация  ресурсов',
      collapsed: false,
      items: ruleConfiguration,
    },
  ],
}

export default sidebars
