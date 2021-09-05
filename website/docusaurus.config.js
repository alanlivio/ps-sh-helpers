(module.exports = {
  title: 'bash-helpers',
  tagline: 'Dinosaurs are cool',
  url: 'https://alanlivio.github.io',
  baseUrl: '/bash-helpers/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  projectName: 'bash-helpers',
  organizationName: 'alanlivio',
  presets: [
    [
      '@docusaurus/preset-classic',
      ({
        docs: false,
        prism: false,
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],
  themeConfig:
    ({
      colorMode: {
        defaultMode: 'dark',
        respectPrefersColorScheme: false,
        disableSwitch: true,
      },
      navbar: {
        title: 'bash-helpers',
        logo: {
          alt: 'bash-helpers Logo',
          src: 'logo.svg',
        },
        items: [
          {
            href: 'https://github.com/alanlivio/bash-helpers',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
    }),
});
