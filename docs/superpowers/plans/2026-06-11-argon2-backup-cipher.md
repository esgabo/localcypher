# Argon2id Backup Cipher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded-PBKDF2 web tool with an Argon2id-only, single-page printable backup cipher that produces a portable, domain-independent blob and QR.

**Architecture:** Pure client-side vanilla JS + Tailwind, no build step. Pure logic (blob encode/decode, match ID, diceware selection) lives in testable modules verified with Node's built-in `node --test`. Argon2id (vendored single-file `hash-wasm`) and AES-GCM (Web Crypto) provide the crypto; the UI is a single tabbed `index.html` with an `@media print` backup sheet.

**Tech Stack:** Vanilla JS (ES2020), Web Crypto (AES-GCM-256), vendored `hash-wasm` (Argon2id), vendored `qrcode-generator` (QR), Tailwind CSS v2 (CDN, retained), EFF diceware wordlist. Tests: `node --test` (built in, no install).

Spec: `docs/superpowers/specs/2026-06-11-argon2-backup-cipher-design.md`

---

## File Structure

**New:**
- `assets/js/blob.js` — pure: `encodeBlob(obj)`, `decodeBlob(str)`, `generateMatchId()`. Browser global + Node export. No crypto deps, so it is unit-testable in Node.
- `assets/js/diceware.js` — `generatePassphrase(words, deps)` pure word selection; ships with the EFF wordlist. Browser global + Node export.
- `assets/js/cipher.js` — Argon2id key derivation + AES-GCM encrypt/decrypt, composing `blob.js`. Browser-only (depends on vendored `hash-wasm` global + Web Crypto).
- `assets/js/vendor/hash-wasm-argon2.umd.min.js` — vendored Argon2id (hash-wasm).
- `assets/js/vendor/qrcode.min.js` — vendored standalone QR generator (qrcode-generator, no jQuery).
- `tests/blob.test.js` — Node tests for blob.js.
- `tests/diceware.test.js` — Node tests for diceware.js.
- `tests/cipher-roundtrip.test.mjs` — Node AES-GCM round-trip test (mocked KDF).

**Rewritten:**
- `index.html` — single tabbed app (Encrypt / Decrypt) + print sheet + page script.
- `README.md` — purpose, how it works, usage, security rationale.

**Removed:**
- `encrypt.html`, `decrypt.html`, `print.html`
- `assets/js/pbkdf2.js`, `assets/js/jquery.qrcode.js`, `assets/js/qrcode.js`

**Kept:**
- `assets/js/hex.js` — hex formatting for clear-text salt/IV/ciphertext display.

---

## Task 1: Pure blob format module (TDD)

**Files:**
- Create: `assets/js/blob.js`
- Test: `tests/blob.test.js`

- [ ] **Step 1: Write the failing test**

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/blob.test.js`
Expected: FAIL — `Cannot find module '../assets/js/blob.js'`.

- [ ] **Step 3: Write minimal implementation**

```js
// assets/js/blob.js
(function (root) {
  'use strict';

  var PREFIX = 'bk1.';

  function toBase64Url(str) {
    // str: a binary/UTF-8 string. Use btoa in browser, Buffer in Node.
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test tests/blob.test.js`
Expected: PASS — 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add assets/js/blob.js tests/blob.test.js
git commit -m "feat: add portable bk1 backup blob encode/decode"
```

---

## Task 2: Diceware passphrase generator (TDD)

**Files:**
- Create: `assets/js/diceware.js`
- Test: `tests/diceware.test.js`

- [ ] **Step 1: Write the failing test**

```js
// tests/diceware.test.js
const test = require('node:test');
const assert = require('node:assert');
const { generatePassphrase, EFF_WORDLIST } = require('../assets/js/diceware.js');

test('EFF_WORDLIST is the full 7776-word list', () => {
  assert.strictEqual(EFF_WORDLIST.length, 7776);
});

test('generatePassphrase returns the requested number of hyphenated words', () => {
  const phrase = generatePassphrase(5);
  assert.strictEqual(phrase.split('-').length, 5);
  phrase.split('-').forEach((w) => assert.ok(EFF_WORDLIST.includes(w)));
});

test('generatePassphrase uses injected randomness deterministically', () => {
  // deps.randomInt(maxExclusive) -> index; force first 3 words
  let calls = 0;
  const deps = { randomInt: () => [0, 1, 2][calls++] };
  const phrase = generatePassphrase(3, deps);
  assert.strictEqual(phrase, [EFF_WORDLIST[0], EFF_WORDLIST[1], EFF_WORDLIST[2]].join('-'));
});

test('generatePassphrase defaults to 5 words', () => {
  assert.strictEqual(generatePassphrase().split('-').length, 5);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/diceware.test.js`
Expected: FAIL — `Cannot find module '../assets/js/diceware.js'`.

- [ ] **Step 3: Obtain the EFF wordlist and write the module**

Download the official EFF large wordlist and transform it into a JS array literal:

```bash
curl -fsSL https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt -o /tmp/eff.txt
# File has lines like: "11111\tabacus". Keep only the word (2nd column).
node -e "const fs=require('fs');const words=fs.readFileSync('/tmp/eff.txt','utf8').trim().split('\n').map(l=>l.split('\t')[1]);if(words.length!==7776)throw new Error('expected 7776, got '+words.length);fs.writeFileSync('/tmp/words.json',JSON.stringify(words));console.log('ok',words.length)"
```

Then create `assets/js/diceware.js`, pasting the array from `/tmp/words.json` as `EFF_WORDLIST` (replace the `[...]` below with the file contents):

```js
// assets/js/diceware.js
(function (root) {
  'use strict';

  // Paste the contents of /tmp/words.json here (a 7776-element array of strings):
  var EFF_WORDLIST = [/* "abacus", "abdomen", ... 7776 words ... */];

  function defaultRandomInt(maxExclusive) {
    // Unbiased rejection sampling over a 32-bit range.
    var rng = root.crypto || require('node:crypto').webcrypto;
    var limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    var buf = new Uint32Array(1);
    var x;
    do { rng.getRandomValues(buf); x = buf[0]; } while (x >= limit);
    return x % maxExclusive;
  }

  function generatePassphrase(words, deps) {
    var n = words || 5;
    var randomInt = (deps && deps.randomInt) || defaultRandomInt;
    var out = [];
    for (var i = 0; i < n; i++) out.push(EFF_WORDLIST[randomInt(EFF_WORDLIST.length)]);
    return out.join('-');
  }

  var api = { generatePassphrase: generatePassphrase, EFF_WORDLIST: EFF_WORDLIST };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else { root.generatePassphrase = generatePassphrase; root.EFF_WORDLIST = EFF_WORDLIST; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test tests/diceware.test.js`
Expected: PASS — 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add assets/js/diceware.js tests/diceware.test.js
git commit -m "feat: add EFF diceware passphrase generator"
```

---

## Task 3: Vendor Argon2id (hash-wasm) and QR generator

**Files:**
- Create: `assets/js/vendor/hash-wasm-argon2.umd.min.js`
- Create: `assets/js/vendor/qrcode.min.js`

- [ ] **Step 1: Download the pinned vendored libraries**

```bash
mkdir -p assets/js/vendor
# hash-wasm Argon2 single-file UMD bundle (WASM embedded as base64), pinned version:
curl -fsSL https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/dist/argon2.umd.min.js -o assets/js/vendor/hash-wasm-argon2.umd.min.js
# qrcode-generator, standalone, no jQuery, pinned version:
curl -fsSL https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js -o assets/js/vendor/qrcode.min.js
```

- [ ] **Step 2: Verify the files are non-empty and self-contained**

Run: `wc -c assets/js/vendor/hash-wasm-argon2.umd.min.js assets/js/vendor/qrcode.min.js`
Expected: both sizes are clearly non-zero (hash-wasm bundle is large, ~100KB+; qrcode ~40KB).

Run: `node -e "globalThis.window=globalThis; require('./assets/js/vendor/hash-wasm-argon2.umd.min.js'); console.log('argon2id export:', typeof globalThis.hashwasm?.argon2id)"`
Expected: prints `argon2id export: function` (confirms the UMD global name `hashwasm.argon2id`; if the global differs, note the actual name for Task 4).

- [ ] **Step 3: Commit**

```bash
git add assets/js/vendor/hash-wasm-argon2.umd.min.js assets/js/vendor/qrcode.min.js
git commit -m "chore: vendor hash-wasm argon2id and qrcode-generator"
```

---

## Task 4: AES-GCM round-trip test harness (TDD, KDF mocked)

**Files:**
- Create: `tests/cipher-roundtrip.test.mjs`

This validates the AES-GCM + blob composition in Node with a mocked key (Argon2 itself is browser-verified in Task 6, since the vendored WASM targets the browser).

- [ ] **Step 1: Write the failing test**

```js
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
```

- [ ] **Step 2: Run test to verify it passes**

Run: `node --test tests/cipher-roundtrip.test.mjs`
Expected: PASS — 2 tests pass. (This is a reference harness confirming the exact AES-GCM parameters cipher.js will use.)

- [ ] **Step 3: Commit**

```bash
git add tests/cipher-roundtrip.test.mjs
git commit -m "test: AES-GCM-256 round-trip reference harness"
```

---

## Task 5: Cipher core module

**Files:**
- Create: `assets/js/cipher.js`

Browser-only (depends on vendored `hashwasm.argon2id` and Web Crypto). Composes `blob.js`. Verified in-browser in Task 6.

- [ ] **Step 1: Write the implementation**

```js
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
```

- [ ] **Step 2: Sanity-check it parses**

Run: `node -e "globalThis.crypto=require('node:crypto').webcrypto; globalThis.hexString=()=>''; globalThis.byteArray=()=>[]; globalThis.encodeBlob=()=>''; globalThis.decodeBlob=()=>({}); globalThis.generateMatchId=()=>'AAAA'; require('./assets/js/cipher.js'); console.log('cipher exports:', Object.keys(globalThis.cipher))"`
Expected: prints `cipher exports: [ 'encrypt', 'decrypt', 'DEFAULTS' ]` (parse/load check only; real crypto verified in browser).

- [ ] **Step 3: Commit**

```bash
git add assets/js/cipher.js
git commit -m "feat: add argon2id + aes-gcm cipher core"
```

---

## Task 6: Single-page tabbed app + print sheet (`index.html`)

**Files:**
- Create/Rewrite: `index.html`
- Delete: `encrypt.html`, `decrypt.html`, `print.html`, `assets/js/pbkdf2.js`, `assets/js/jquery.qrcode.js`, `assets/js/qrcode.js`

- [ ] **Step 1: Write `index.html`**

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Argon2id Backup Cipher</title>
  <link href="https://unpkg.com/@tailwindcss/forms@0.3.2/dist/forms.min.css" rel="stylesheet">
  <link href="https://unpkg.com/tailwindcss@^2/dist/tailwind.min.css" rel="stylesheet">
  <style>
    .tab-btn.active { background:#4f46e5; color:#fff; }
    .cut-line { border-top:2px dashed #cbd5e1; position:relative; }
    .cut-line::before { content:"\2702"; position:absolute; left:8px; top:-12px; background:#fff; padding:0 6px; color:#94a3b8; }
    @media print {
      body * { visibility:hidden; }
      #print-sheet, #print-sheet * { visibility:visible; }
      #print-sheet { position:absolute; inset:0; display:block !important; }
      .no-print { display:none !important; }
    }
  </style>
</head>
<body class="bg-gray-100 min-h-screen">
  <main class="max-w-3xl mx-auto p-4 sm:p-6">
    <div class="bg-white shadow rounded-md overflow-hidden no-print">
      <div class="px-6 pt-6">
        <h1 class="text-xl font-semibold text-gray-900">Argon2id Backup Cipher</h1>
        <p class="text-sm text-gray-500 mt-1">Encrypt a secret locally, print it as a backup, recover it later by scanning or pasting.</p>
        <div class="mt-4 flex gap-2">
          <button id="tab-encrypt" class="tab-btn active rounded-t-md px-4 py-2 text-sm font-medium bg-gray-200 text-gray-700">Encrypt</button>
          <button id="tab-decrypt" class="tab-btn rounded-t-md px-4 py-2 text-sm font-medium bg-gray-200 text-gray-700">Decrypt</button>
        </div>
      </div>

      <!-- ENCRYPT PANEL -->
      <section id="panel-encrypt" class="p-6 space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Message</label>
          <textarea id="enc-input" rows="3" class="mt-1 block w-full rounded-md border-gray-300 p-2 sm:text-sm"></textarea>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Passphrase</label>
          <div class="mt-1 flex gap-2">
            <input id="enc-pass" type="text" class="block w-full rounded-md border-gray-300 sm:text-sm">
            <button id="gen-pass" class="shrink-0 rounded-md bg-indigo-50 text-indigo-700 px-3 py-2 text-sm font-medium">Generate</button>
          </div>
          <p class="text-xs text-gray-500 mt-1">Generated passphrases use the EFF diceware list. Store the passphrase separately from the printed data.</p>
        </div>
        <details class="text-sm">
          <summary class="cursor-pointer text-indigo-600 font-medium">Advanced (Argon2id parameters)</summary>
          <div class="grid grid-cols-3 gap-3 mt-2">
            <label class="block">Memory (KiB)<input id="adv-m" type="number" value="19456" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
            <label class="block">Time<input id="adv-t" type="number" value="2" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
            <label class="block">Parallelism<input id="adv-p" type="number" value="1" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
          </div>
        </details>
        <button id="encrypt-btn" class="rounded-md bg-indigo-600 text-white px-4 py-2 text-sm font-medium hover:bg-indigo-700">Encrypt</button>

        <div id="enc-result" class="hidden border-t pt-4 space-y-3">
          <div><span class="text-xs font-medium text-gray-500">Ciphertext</span><p id="out-ct" class="text-sm text-gray-900 break-all"></p></div>
          <div><span class="text-xs font-medium text-gray-500">Salt</span><p id="out-salt" class="text-sm text-gray-900 break-all"></p></div>
          <div><span class="text-xs font-medium text-gray-500">IV</span><p id="out-iv" class="text-sm text-gray-900 break-all"></p></div>
          <div id="enc-qr"></div>
          <button id="print-btn" class="rounded-md bg-gray-800 text-white px-4 py-2 text-sm font-medium">Print backup</button>
        </div>
      </section>

      <!-- DECRYPT PANEL -->
      <section id="panel-decrypt" class="p-6 space-y-4 hidden">
        <div>
          <label class="block text-sm font-medium text-gray-700">Paste backup (bk1…)</label>
          <textarea id="dec-blob" rows="2" class="mt-1 block w-full rounded-md border-gray-300 p-2 sm:text-sm" placeholder="bk1...."></textarea>
          <p class="text-xs text-gray-500 mt-1">Pasting a backup fills the fields below automatically.</p>
        </div>
        <div class="grid grid-cols-3 gap-3">
          <label class="block text-sm">Memory<input id="dec-m" type="number" value="19456" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
          <label class="block text-sm">Time<input id="dec-t" type="number" value="2" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
          <label class="block text-sm">Parallelism<input id="dec-p" type="number" value="1" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></label>
        </div>
        <div><label class="block text-sm font-medium text-gray-700">Salt</label><input id="dec-salt" type="text" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></div>
        <div><label class="block text-sm font-medium text-gray-700">IV</label><input id="dec-iv" type="text" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></div>
        <div><label class="block text-sm font-medium text-gray-700">Ciphertext</label><textarea id="dec-ct" rows="2" class="mt-1 block w-full rounded-md border-gray-300 p-2 sm:text-sm"></textarea></div>
        <div><label class="block text-sm font-medium text-gray-700">Passphrase</label><input id="dec-pass" type="text" class="mt-1 block w-full rounded-md border-gray-300 sm:text-sm"></div>
        <button id="decrypt-btn" class="rounded-md bg-indigo-600 text-white px-4 py-2 text-sm font-medium hover:bg-indigo-700">Decrypt</button>
        <div><span class="text-xs font-medium text-gray-500">Message</span><p id="dec-out" class="text-sm text-gray-900 break-all"></p></div>
      </section>
    </div>

    <!-- PRINT SHEET -->
    <div id="print-sheet" class="hidden bg-white max-w-xl mx-auto mt-6 border rounded-md p-6 font-mono text-sm">
      <div class="flex justify-between items-start font-sans">
        <div><h2 class="text-base font-semibold">Encrypted Backup</h2><p class="text-xs text-gray-400">argon2id + AES-GCM · format v1</p></div>
        <span class="text-xs font-bold text-indigo-700 bg-indigo-50 rounded px-2 py-1">ID <span id="ps-id"></span></span>
      </div>
      <div class="flex gap-4 mt-4">
        <div class="flex-1 leading-relaxed break-all">
          <div><span class="text-gray-400">algorithm</span> argon2id</div>
          <div><span class="text-gray-400">params</span> <span id="ps-params"></span></div>
          <div><span class="text-gray-400">salt</span> <span id="ps-salt"></span></div>
          <div><span class="text-gray-400">iv</span> <span id="ps-iv"></span></div>
          <div><span class="text-gray-400">ciphertext</span> <span id="ps-ct"></span></div>
        </div>
        <div><div id="ps-qr"></div><p class="text-[9px] text-gray-400 text-center mt-1 font-sans">scan → paste to decrypt</p></div>
      </div>
      <div class="cut-line my-6"></div>
      <div class="flex justify-between items-center font-sans">
        <span class="text-sm font-semibold text-gray-700">Passphrase</span>
        <span class="text-xs font-bold text-indigo-700 bg-indigo-50 rounded px-2 py-1">ID <span id="ps-id2"></span></span>
      </div>
      <p id="ps-pass" class="text-base font-bold mt-2 break-all"></p>
      <p class="font-sans text-xs text-red-800 bg-red-50 border border-red-200 rounded p-2 mt-3">
        <strong>⚠ Store this half separately</strong> from the encrypted data above. Anyone with both can read your secret. Match the <strong>ID</strong> to pair them later.
      </p>
    </div>
  </main>

  <script src="./assets/js/hex.js"></script>
  <script src="./assets/js/blob.js"></script>
  <script src="./assets/js/diceware.js"></script>
  <script src="./assets/js/vendor/hash-wasm-argon2.umd.min.js"></script>
  <script src="./assets/js/vendor/qrcode.min.js"></script>
  <script src="./assets/js/cipher.js"></script>
  <script>
    var lastBlob = null, lastEnc = null;

    function show(panel) {
      document.getElementById('panel-encrypt').classList.toggle('hidden', panel !== 'encrypt');
      document.getElementById('panel-decrypt').classList.toggle('hidden', panel !== 'decrypt');
      document.getElementById('tab-encrypt').classList.toggle('active', panel === 'encrypt');
      document.getElementById('tab-decrypt').classList.toggle('active', panel === 'decrypt');
    }
    document.getElementById('tab-encrypt').onclick = function () { show('encrypt'); };
    document.getElementById('tab-decrypt').onclick = function () { show('decrypt'); };

    function renderQr(elId, text) {
      var el = document.getElementById(elId); el.innerHTML = '';
      var qr = qrcode(0, 'M'); qr.addData(text); qr.make();
      el.innerHTML = qr.createImgTag(4);
    }

    document.getElementById('gen-pass').onclick = function () {
      document.getElementById('enc-pass').value = generatePassphrase(5);
    };

    document.getElementById('encrypt-btn').onclick = async function () {
      var msg = document.getElementById('enc-input').value;
      var pass = document.getElementById('enc-pass').value;
      if (!msg || !pass) { alert('Enter a message and a passphrase'); return; }
      var params = {
        m: parseInt(document.getElementById('adv-m').value, 10),
        t: parseInt(document.getElementById('adv-t').value, 10),
        p: parseInt(document.getElementById('adv-p').value, 10)
      };
      lastEnc = await cipher.encrypt(msg, pass, params);
      lastBlob = lastEnc.blob;
      document.getElementById('out-ct').textContent = formatHexString(lastEnc.ct);
      document.getElementById('out-salt').textContent = formatHexString(lastEnc.salt);
      document.getElementById('out-iv').textContent = formatHexString(lastEnc.iv);
      renderQr('enc-qr', lastBlob);
      document.getElementById('enc-result').classList.remove('hidden');
    };

    document.getElementById('print-btn').onclick = function () {
      if (!lastEnc) return;
      document.getElementById('ps-id').textContent = lastEnc.id;
      document.getElementById('ps-id2').textContent = lastEnc.id;
      document.getElementById('ps-params').textContent = 'm=' + lastEnc.params.m + ', t=' + lastEnc.params.t + ', p=' + lastEnc.params.p;
      document.getElementById('ps-salt').textContent = lastEnc.salt;
      document.getElementById('ps-iv').textContent = lastEnc.iv;
      document.getElementById('ps-ct').textContent = lastEnc.ct;
      document.getElementById('ps-pass').textContent = document.getElementById('enc-pass').value;
      renderQr('ps-qr', lastBlob);
      document.getElementById('print-sheet').classList.remove('hidden');
      window.print();
    };

    document.getElementById('dec-blob').addEventListener('input', function () {
      var v = this.value.trim();
      if (v.slice(0, 4) !== 'bk1.') return;
      try {
        var f = decodeBlob(v);
        document.getElementById('dec-m').value = f.m;
        document.getElementById('dec-t').value = f.t;
        document.getElementById('dec-p').value = f.p;
        document.getElementById('dec-salt').value = formatHexString(f.salt);
        document.getElementById('dec-iv').value = formatHexString(f.iv);
        document.getElementById('dec-ct').value = formatHexString(f.ct);
      } catch (e) { /* ignore until valid */ }
    });

    document.getElementById('decrypt-btn').onclick = async function () {
      var pass = document.getElementById('dec-pass').value;
      var fields = {
        kdf: 'argon2id',
        m: parseInt(document.getElementById('dec-m').value, 10),
        t: parseInt(document.getElementById('dec-t').value, 10),
        p: parseInt(document.getElementById('dec-p').value, 10),
        salt: unformatHexString(document.getElementById('dec-salt').value),
        iv: unformatHexString(document.getElementById('dec-iv').value),
        ct: unformatHexString(document.getElementById('dec-ct').value)
      };
      if (!pass || !fields.ct) { alert('Enter a backup/ciphertext and a passphrase'); return; }
      var res = await cipher.decrypt(fields, pass);
      document.getElementById('dec-out').textContent = res.error ? 'Decryption failed' : res.output;
    };
  </script>
</body>
</html>
```

- [ ] **Step 2: Delete the obsolete files**

```bash
git rm encrypt.html decrypt.html print.html assets/js/pbkdf2.js assets/js/jquery.qrcode.js assets/js/qrcode.js
```

- [ ] **Step 3: Manual browser verification (full round-trip)**

Run a static server: `python3 -m http.server 8000`
Then in a browser at `http://localhost:8000/`:
1. Encrypt tab → type a message, click **Generate** (a hyphenated passphrase appears), click **Encrypt**. Confirm ciphertext/salt/IV and a QR appear.
2. Click **Print backup** → the print dialog shows the two-half sheet with matching IDs, params, QR, and passphrase + warning. Cancel the dialog.
3. Copy the blob: in the console run `copy(lastBlob)`. Switch to Decrypt tab, paste into **Paste backup** (fields auto-fill), enter the same passphrase, click **Decrypt** → original message appears.
4. Change the passphrase and Decrypt again → shows "Decryption failed".
5. Reload via `file://` (open `index.html` directly) and repeat step 1 to confirm it works fully offline.

Expected: all steps behave as described.

- [ ] **Step 4: Commit**

```bash
git add index.html
git commit -m "feat: single-page tabbed app with printable backup sheet"
```

---

## Task 7: Update README

**Files:**
- Rewrite: `README.md`

- [ ] **Step 1: Write the README**

```markdown
# pbkdf2

A simple, fully client-side web tool for encrypting a secret and **printing it as
a physical backup**, then recovering it later by scanning or pasting it back and
decrypting with a passphrase.

> Note: the project keeps its original `pbkdf2` name, but it now uses **Argon2id**
> (a memory-hard KDF) instead of PBKDF2.

## Purpose

For backing up sensitive text (recovery codes, seed phrases, passwords) on paper.
The ciphertext, salt, IV and KDF parameters are printed in clear text, so the
threat model is an attacker who physically obtains the printout and brute-forces
the passphrase offline. Argon2id (memory-hard) plus a strong generated passphrase
is what protects the secret.

## How it works

- **KDF:** Argon2id (vendored `hash-wasm`, runs in-browser via WebAssembly).
- **Cipher:** AES-GCM-256 (Web Crypto API).
- **Backup blob:** a portable, domain-independent string `bk1.<base64url-JSON>`
  containing the format version, Argon2 parameters, salt, IV, ciphertext and a
  short match ID. The QR code encodes this blob — not a URL — so backups are not
  tied to any deployment.
- Everything runs locally; the app works offline, including from `file://`.

## How to use it

1. **Encrypt:** enter your message, click **Generate** for a strong diceware
   passphrase (or type your own), optionally tune Argon2 parameters under
   **Advanced**, and click **Encrypt**.
2. **Print:** click **Print backup**. The sheet has two halves split by a cut line:
   the **top** holds the encrypted data + QR (keep with your records), the
   **bottom** holds the passphrase with a warning (cut off and store separately).
   A matching **ID** on both halves lets you re-pair them.
3. **Decrypt:** on the Decrypt tab, scan the QR and paste the blob (or paste it
   directly), enter the passphrase, and click **Decrypt**.

## Security notes

- Store the passphrase half separately from the encrypted data half.
- The passphrase is never stored in the blob or QR.
- Argon2id defaults follow the OWASP baseline (memory 19 MiB, time 2,
  parallelism 1); raise them for stronger protection.

Based on the [Web Crypto API examples](https://github.com/mdn/dom-examples/tree/master/web-crypto/derive-key).
Source on [GitHub](https://github.com/esgabo/pbkdf2).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for Argon2id backup cipher"
```

---

## Task 8: Final full-suite check

- [ ] **Step 1: Run all Node tests**

Run: `node --test tests/`
Expected: all tests across `blob.test.js`, `diceware.test.js`, `cipher-roundtrip.test.mjs` PASS.

- [ ] **Step 2: Confirm no stale references remain**

Run: `grep -rn "pbkdf2.js\|jquery\|qrcode.js\|PBKDF2" index.html assets/js || echo "clean"`
Expected: `clean` (no references to the removed files or PBKDF2 in app code; matches inside vendored files are fine if any appear, but app files should be clean).

- [ ] **Step 3: Confirm the working tree is committed**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

---

## Self-Review notes

- **Spec coverage:** Argon2id-only (T3,T5), configurable params/Advanced (T6), bk1 blob (T1,T5), diceware generator (T2,T6), single tabbed page (T6), printable two-half sheet w/ match ID + warning (T6), vanilla QR / jQuery removed (T3,T6), `pbkdf2.js`→`cipher.js` rename + file removals (T5,T6), README (T7). All spec sections map to tasks.
- **Type consistency:** `cipher.encrypt` returns `{blob,salt,iv,ct,id,params}`; `index.html` reads exactly those. Blob payload keys `{v,kdf,m,t,p,salt,iv,ct,id}` consistent across T1/T5/T6. `hex.js` helpers used: `hexString`/`byteArray` (cipher.js) and `formatHexString`/`unformatHexString` (index.html) — these exist in the current `hex.js` (verify in T6 Step 3; if names differ, adjust calls to match `hex.js`).
- **Placeholder scan:** the only intentional fill-in is the EFF wordlist array in T2, with exact generation commands provided.
