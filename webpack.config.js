module.exports = {
  entry: {
    'did-veres-one': './lib'
  },
  output: {
    filename: '[name].min.js',
    library: '[name]',
    libraryTarget: 'amd',
  }
}
