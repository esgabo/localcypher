// tests/cipher-roundtrip.test.mjs
import test from 'node:test';
import assert from 'node:assert';
import { webcrypto as crypto } from 'node:crypto';

// Mirrors the AES-GCM steps cipher.js performs after key derivation.
async function aesEncrypt(message, rawKey, iv) {
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(message));
  return new Uint8Array(ct);
}
async function aesDecrypt(ctBytes, rawKey, iv) {
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ctBytes);
  return new TextDecoder().decode(pt);
}

test('AES-GCM-256 round-trips a UTF-8 message', async () => {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await aesEncrypt('correct horse 🐎', rawKey, iv);
  assert.strictEqual(await aesDecrypt(ct, rawKey, iv), 'correct horse 🐎');
});

test('wrong key fails decryption', async () => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await aesEncrypt('secret', crypto.getRandomValues(new Uint8Array(32)), iv);
  await assert.rejects(aesDecrypt(ct, crypto.getRandomValues(new Uint8Array(32)), iv));
});
