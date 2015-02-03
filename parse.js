'use strict';

var toASCII          = require('punycode2/to-ascii')
  , parse            = require('querystring2/parse')
  , format           = require('./format')
  , hostlessProtocol = require('./lib/hostless-protocol')
  , slashedProtocol  = require('./lib/slashed-protocol')
  , Url              = require('./lib/url');

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+\-]+:)/i
  , portPattern = /:[0-9]*$/

    // Special case for a simple path URL
  , simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
  , delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t']

    // RFC 2396: characters not allowed for various reasons.
  , unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims)

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
  , autoEscape = ['\''].concat(unwise)
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
  , nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape)
  , hostEndingChars = ['/', '?', '#']
  , hostnameMaxLen = 255
  , hostnamePartPattern = /^[+a-z0-9A-Z_\-]{0,63}$/
  , hostnamePartStart = /^([+a-z0-9A-Z_\-]{0,63})(.*)$/;

// protocols that can allow "unsafe" and "unwise" chars.
var unsafeProtocol = {
  javascript: true,
  'javascript:': true
};

var parseHost = function (obj) {
  var host = obj.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      obj.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) obj.hostname = host;
};

module.exports = function (url, parseQueryString, slashesDenoteHost) {
  if (url == null) throw new TypeError("Cannot user null or undefined");
  url = String(url);

  var result = new Url();
  // Copy chrome, IE, opera backslash-handling behavior.
  // Back slashes before the query string get converted to forward slashes
  // See: https://code.google.com/p/chromium/issues/detail?id=25916
  var queryIndex = url.indexOf('?'),
      splitter =
          (queryIndex !== -1 && queryIndex < url.indexOf('#')) ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, '/');
  url = uSplit.join(splitter);

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  if (!slashesDenoteHost && url.split('#').length === 1) {
    // Try fast path regexp
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      result.path = rest;
      result.href = rest;
      result.pathname = simplePath[1];
      if (simplePath[2]) {
        result.search = simplePath[2];
        if (parseQueryString) {
          result.query = parse(result.search.substr(1));
        } else {
          result.query = result.search.substr(1);
        }
      } else if (parseQueryString) {
        result.search = '';
        result.query = {};
      }
      return result;
    }
  }

  var proto = protocolPattern.exec(rest), slashes, lowerProto, i, l, p;
  if (proto) {
    proto = proto[0];
    lowerProto = proto.toLowerCase();
    result.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      result.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1, hec;
    for (i = 0; i < hostEndingChars.length; i++) {
      hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      result.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (i = 0; i < nonHostChars.length; i++) {
      hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1) hostEnd = rest.length;

    result.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    parseHost(result);

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    result.hostname = result.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = result.hostname[0] === '[' &&
        result.hostname[result.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = result.hostname.split(/\./), part, newpart, j, k, validParts, notHost, bit;
      for (i = 0, l = hostparts.length; i < l; i++) {
        part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          newpart = '';
          for (j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            validParts = hostparts.slice(0, i);
            notHost = hostparts.slice(i + 1);
            bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            result.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (result.hostname.length > hostnameMaxLen) {
      result.hostname = '';
    } else {
      // hostnames are always lower case.
      result.hostname = result.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a punycoded representation of "domain".
      // It only converts parts of the domain name that
      // have non-ASCII characters, i.e. it doesn't matter if
      // you call it with a domain that already is ASCII-only.
      result.hostname = toASCII(result.hostname);
    }

    p = result.port ? ':' + result.port : '';
    var h = result.hostname || '';
    result.host = h + p;
    result.href += result.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      result.hostname = result.hostname.substr(1, result.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  var ae, esc;
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (i = 0, l = autoEscape.length; i < l; i++) {
      ae = autoEscape[i];
      if (rest.indexOf(ae) === -1) continue;
      esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }

  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    result.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    result.search = rest.substr(qm);
    result.query = rest.substr(qm + 1);
    if (parseQueryString) {
      result.query = parse(result.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    result.search = '';
    result.query = {};
  }
  if (rest) result.pathname = rest;
  if (slashedProtocol[lowerProto] &&
      result.hostname && !result.pathname) {
    result.pathname = '/';
  }

  //to support http.request
  if (result.pathname || result.search) {
    p = result.pathname || '';
    var s = result.search || '';
    result.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  result.href = format(result);
  return result;
};
