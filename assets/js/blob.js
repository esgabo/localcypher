// assets/js/blob.js
(function (root) {
  'use strict';

  var PREFIX = 'bk1.';

  function toBase64Url(str) {
    var b64 = (typeof btoa === 'function')
      ? btoa(unescape(encodeURIComponent(str)))
      : Buffer.from(str, 'utf8').toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64Url(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    if (typeof atob === 'function') {
      return decodeURIComponent(escape(atob(b64)));
    }
    return Buffer.from(b64, 'base64').toString('utf8');
  }

  function encodeBlob(payload) {
    return PREFIX + toBase64Url(JSON.stringify(payload));
  }

  function decodeBlob(blob) {
    if (typeof blob !== 'string' || blob.slice(0, PREFIX.length) !== PREFIX) {
      throw new Error('Unrecognized backup format');
    }
    var json;
    try {
      json = fromBase64Url(blob.slice(PREFIX.length));
      return JSON.parse(json);
    } catch (e) {
      throw new Error('Malformed backup data');
    }
  }

  function generateMatchId() {
    var bytes = new Uint8Array(2);
    (root.crypto || require('node:crypto').webcrypto).getRandomValues(bytes);
    return Array.from(bytes).map(function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('').toUpperCase();
  }

  var api = { encodeBlob: encodeBlob, decodeBlob: decodeBlob, generateMatchId: generateMatchId };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.encodeBlob = encodeBlob; root.decodeBlob = decodeBlob; root.generateMatchId = generateMatchId; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
