'use strict';

var format        = require('./format')
  , resolveObject = require('./resolve-object');

module.exports = function (source, relative) { return format(resolveObject(source, relative)); };
