'use strict';

var stringify       = require('querystring2/stringify')
  , slashedProtocol = require('./lib/slashed-protocol');

module.exports = function (url) {
  if (!url || (typeof url !== 'object')) throw new TypeError(url + " is not an object");
  var auth = url.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = url.protocol || '',
  pathname = url.pathname || '',
  hash = url.hash || '',
  host = false,
  query = '';

  if (url.host) {
    host = auth + url.host;
  } else if (url.hostname) {
    host = auth + (url.hostname.indexOf(':') === -1 ?
        url.hostname :
        '[' + url.hostname + ']');
    if (url.port) {
      host += ':' + url.port;
    }
  }

  if (url.query &&
      (typeof url.query === 'object') &&
      Object.keys(url.query).length) {
    query = stringify(url.query);
  }

  var search = url.search || (query && ('?' + query)) || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (url.slashes ||
      ((!protocol || slashedProtocol[protocol]) && host !== false)) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function (match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};
