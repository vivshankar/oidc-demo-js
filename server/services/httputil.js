const axios = require('axios');
const querystring = require('querystring');
const debug = require('debug')('dunebank:consent');

/**
 * A class for making HTTP requests
 * @author Vivek Shankar <viv.shankar@gmail.com>
 */
class HTTPUtil {
  /**
    * Create a new {@link HTTPUtil} object.
    * @param {string} baseURL The base URL for the API, normally the tenant URL.
    */
  constructor(baseURL) {
    this._baseURL = baseURL;
    debug(`[${HTTPUtil.name}:constructor(baseURL, ` +
            `contentTypeHeader='json', acceptHeader='json')]`,
    'baseURL:', this._baseURL);
  }

  /**
    * Send a HTTP GET request.
    * @param {string} path The path on the base URL to send the request to.
    * @param {Object} headers The headers to be sent with the request.
    * @param {Object} params The URL parameters to be sent with the request.
    * @return {Promise<Object>} The response to the HTTP request.
    */
  async get(path, headers = {}, params = {}) {
    debug(`[${HTTPUtil.name}:get(path, headers={}, params={})]`,
        'path:', path);

    return await axios.get(this._baseURL + path, {params, headers});
  }

  /**
    * Send a HTTP POST request.
    * @param {string} path The path on the base URL to send the request to.
    * @param {Object} data The POST body to send with the request.
    * @param {Object} headers The headers to be sent with the request.
    * @param {Object} params The URL parameters to send with the request.
    * @return {Promise<Object>} The response to the HTTP request.
    */
  async post(path, data = {}, headers = {}, params = {}) {
    if (headers['content-type'] === 'application/x-www-form-urlencoded') {
      data = querystring.stringify(data);
    }

    debug(`[${HTTPUtil.name}:post(path, data={}, params={})]`,
        'path:', path);

    return await axios.post(this._baseURL + path, data, {params, headers});
  }
}

module.exports = HTTPUtil;