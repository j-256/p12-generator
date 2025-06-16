const path = require('path');

module.exports = {
  entry: './webpack-entry.js',
  output: {
    path: path.resolve(__dirname, 'static'),
    filename: 'bundle.js',
  },
  mode: 'production'
};
