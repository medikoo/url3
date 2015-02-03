# url3
## Modular and environment agnostic version of node.js [url](http://nodejs.org/api/url.html) package

Works same way as Node's `url` but provides individual functionalities as following distinct modules:

- `url3/format`
- `url3/parse`
- `url3/resolve`
- `url3/resolve-object`

Additionally `format` accepts only objects. So if you want to clean up potentially wonky url, you need to `format(parse(url))`. Same way `parse`, `resolve` and `resolveObject` accept only strings as input arguments

### Installation
#### NPM

In your project path:

	$ npm install url3

To port it to Browser or any other (non CJS) environment, use your favorite CJS bundler. No favorite yet? Try: [Browserify](http://browserify.org/), [Webmake](https://github.com/medikoo/modules-webmake) or [Webpack](http://webpack.github.io/)

## Tests [![Build Status](https://travis-ci.org/medikoo/url3.png)](https://travis-ci.org/medikoo/url3)

	$ npm test
