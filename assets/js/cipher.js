// assets/js/cipher.js
// Requires: blob.js (encodeBlob/decodeBlob/generateMatchId), hex.js (hexString/byteArray),
// and the vendored hash-wasm UMD exposing globalThis.hashwasm.argon2id.
(function (root) {
  'use strict';

  var DEFAULTS = { m: 19456, t: 2, p: 1 }; // OWASP Argon2id baseline
  var SALT_BYTES = 16;
  var IV_BYTES = 12;
  var KEY_BYTES = 32; // AES-256

  function randBytes(n) {
    var b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  async function deriveKey(passphrase, saltBytes, params) {
    var raw = await root.hashwasm.argon2id({
      password: passphrase,
      salt: saltBytes,
      parallelism: params.p,
      iterations: params.t,
      memorySize: params.m,   // KiB
      hashLength: KEY_BYTES,
      outputType: 'binary'
    });
    return root.crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  // params optional; falls back to DEFAULTS. Returns { blob, salt, iv, ct, id, params }.
  async function encrypt(message, passphrase, params) {
    var p = Object.assign({}, DEFAULTS, params || {});
    var salt = randBytes(SALT_BYTES);
    var iv = randBytes(IV_BYTES);
    var key = await deriveKey(passphrase, salt, p);
    var ctBuf = await root.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(message));
    var ct = new Uint8Array(ctBuf);
    var payload = {
      v: 1, kdf: 'argon2id', m: p.m, t: p.t, p: p.p,
      salt: root.hexString(salt), iv: root.hexString(iv),
      ct: root.hexString(ct), id: root.generateMatchId()
    };
    return {
      blob: root.encodeBlob(payload),
      salt: payload.salt, iv: payload.iv, ct: payload.ct, id: payload.id, params: p
    };
  }

  // Accepts a bk1 blob OR an explicit fields object {kdf,m,t,p,salt,iv,ct}.
  async function decrypt(blobOrFields, passphrase) {
    var f = (typeof blobOrFields === 'string') ? root.decodeBlob(blobOrFields) : blobOrFields;
    if (f.kdf && f.kdf !== 'argon2id') throw new Error('Unsupported KDF: ' + f.kdf);
    var salt = new Uint8Array(root.byteArray(f.salt));
    var iv = new Uint8Array(root.byteArray(f.iv));
    var ct = new Uint8Array(root.byteArray(f.ct));
    var key = await deriveKey(passphrase, salt, { m: f.m, t: f.t, p: f.p });
    try {
      var pt = await root.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
      return { output: new TextDecoder().decode(pt) };
    } catch (e) {
      return { error: e };
    }
  }

  root.cipher = { encrypt: encrypt, decrypt: decrypt, DEFAULTS: DEFAULTS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
