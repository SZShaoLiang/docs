module.exports = {
    title: 'fallingyang\'s blog',
    description: 'Just playing around',
    themeConfig: {
        sidebar: 'auto',
        nav: [
          { text: 'Home', link: '/' },
          { text: 'External', link: 'https://google.com' },
          {
            text: 'Languages',
            items: [
              { text: 'Chinese', link: '/language/chinese' },
              { text: 'Japanese', link: '/language/japanese' }
            ]
          }
        ]
      }
}