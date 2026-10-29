const binding = require('./build/Release/tiny.node');
module.exports = function add(a, b) { return binding.add(a, b); };
