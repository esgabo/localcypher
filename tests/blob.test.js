// tests/blob.test.js
const test = require('node:test');
const assert = require('node:assert');
const { encodeBlob, decodeBlob, generateMatchId } = require('../assets/js/blob.js');

test('encodeBlob -> decodeBlob round-trips the payload', () => {
  const payload = { v: 1, kdf: 'argon2id', m: 19456, t: 2, p: 1, salt: 'a3f9', iv: '9b21', ct: '5e8c', id: '7F3A' };
  const blob = encodeBlob(payload);
  assert.ok(blob.startsWith('bk1.'), 'blob must start with bk1.');
  assert.deepStrictEqual(decodeBlob(blob), payload);
});

test('encodeBlob uses base64url (no +, /, or = chars)', () => {
  const blob = encodeBlob({ v: 1, kdf: 'argon2id', m: 19456, t: 2, p: 1, salt: 'ff', iv: 'ee', ct: 'dd', id: 'AAAA' });
  const body = blob.slice('bk1.'.length);
  assert.doesNotMatch(body, /[+/=]/);
});

test('decodeBlob rejects a bad prefix', () => {
  assert.throws(() => decodeBlob('xx9.abcd'), /unrecognized backup format/i);
});

test('decodeBlob rejects malformed base64url', () => {
  assert.throws(() => decodeBlob('bk1.@@@not-valid@@@'), /malformed backup/i);
});

test('generateMatchId returns 4 uppercase hex chars', () => {
  const id = generateMatchId();
  assert.match(id, /^[0-9A-F]{4}$/);
});
