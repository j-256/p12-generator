const path = require('path');

module.exports = {
  entry: './webpack-entry.js',
  output: {
    path: path.resolve(__dirname, 'static'),
    filename: 'bundle.js',
  },
  mode: 'development',
  devServer: {
    static: {
      directory: __dirname,
    },
    watchFiles: ['main.js'], // Watch main.js for changes and reload
    hot: true,
    port: 3000
  },
};
