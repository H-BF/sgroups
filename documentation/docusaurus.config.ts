import { themes as prismThemes } from 'prism-react-renderer'
import type { Config } from '@docusaurus/types'
import type * as Preset from '@docusaurus/preset-classic'

const config: Config = {
  title: 'Swarm',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'http://localhost',
  baseUrl: '/',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'ru',
    locales: ['ru'],
  },

  markdown: {
    mermaid: true,
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
          includeCurrentVersion:
            (process.env.DOC_INCLUDE_CURRENT_VERSION &&
              process.env.DOC_INCLUDE_CURRENT_VERSION.toLowerCase() === 'true') ||
            false,
        },
        blog: false,
        pages: {
          path: 'src/pages',
          routeBasePath: '',
          include: ['**/*.{js,jsx,ts,tsx,md,mdx}'],
          exclude: ['**/_*.{js,jsx,ts,tsx,md,mdx}', '**/_*/**', '**/*.test.{js,jsx,ts,tsx}', '**/__tests__/**'],
          mdxPageComponent: '@theme/MDXPage',
          remarkPlugins: [],
          rehypePlugins: [],
          beforeDefaultRemarkPlugins: [],
          beforeDefaultRehypePlugins: [],
        },
        theme: {
          customCss: './src/css/custom.scss',
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [require.resolve('./plugins/webpack'), require.resolve('./plugins/medusa'), 'docusaurus-plugin-astroturf'],

  themes: ['@docusaurus/theme-mermaid'],

  stylesheets: [
    {
      href: 'https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap',
      type: 'text/css',
      crossOrigin: 'anonymous',
    },
    {
      href: 'https://fonts.googleapis.com/css2?family=Source+Code+Pro:ital,wght@0,200..900;1,200..900&display=swap',
      type: 'text/css',
      crossOrigin: 'anonymous',
    },
  ],

  themeConfig: {
    navbar: {
      logo: {
        src: 'img/logo.jpg',
      },
      title: 'SGroups',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'informationSidebar',
          position: 'left',
          label: 'Информация',
        },
        {
          type: 'docSidebar',
          sidebarId: 'techDocs',
          position: 'left',
          label: 'Техническая документация',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: true,
    },
    footer: {
      style: 'dark',
      copyright: `Copyright © ${new Date().getFullYear()} Исключительные права на ПО принадлежат ООО «ПРТ» (ИНН 7735199547; ОГРН 1237700341185). Все права защищены.`,
      links: [
        {
          title: 'Документы',
          items: [
            {
              label: 'Пользовательское соглашение',
              to: '/docs/polzovatelskoe-soglashenie.pdf',
            },
          ],
        },
        {
          title: 'Документация',
          items: [
            {
              label: 'Руководство пользователя',
              href: "/files/documentation.pdf",
            },
            {
              label: 'Пользовательская документация',
              href: "/files/documentation.pdf",
            },
          ],
        },
        {
          title: 'Контакты',
          items: [
            {
              label: 'Telegram',
              href: 'https://t.me/sgroups_support',
            },
          ],
        },
      ],
  },
      prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'hcl', 'json', 'docker'],
    },
  } satisfies Preset.ThemeConfig,

  scripts: [
    {
      src: '/js/observer.js',
      async: false,
    },
  ],
}

export default config
