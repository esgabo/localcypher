# Argon2id Backup Cipher — Design

Date: 2026-06-11

## Purpose

A simple, dependency-light, fully client-side web tool for encrypting sensitive
data so it can be **printed and stored as a physical backup**, then later
recovered by scanning/typing it back into the app and decrypting with a
passphrase.

The threat model is an attacker who physically obtains the printed encrypted
data (ciphertext, salt, IV, and KDF parameters are all printed in clear text)
and runs an offline brute-force / dictionary attack against the passphrase.
Because there is no server and no rate limiting, the key-derivation function is
the entire security boundary. The tool therefore uses a memory-hard KDF
(Argon2id) and encourages strong generated passphrases.

All cryptography runs locally in the browser. The app works fully offline,
including when opened directly via `file://`.

## Scope of this change

The existing app uses **hardcoded PBKDF2** (100,000 iterations, SHA-256) with
AES-GCM-256, split across `encrypt.html`, `decrypt.html`, and `print.html`, with
a jQuery-based QR generator. This redesign:

1. Replaces PBKDF2 with **Argon2id only** (memory-hard, configurable params).
2. Consolidates the three pages into a **single tabbed page** (`index.html`).
3. Introduces a **portable, domain-independent backup blob** format.
4. Adds a **diceware passphrase generator**.
5. Adds a **printable backup sheet** with a cut line and match ID.
6. Removes jQuery in favor of a **vanilla QR generator**.
7. Refreshes the Tailwind styling.

No backward compatibility with old PBKDF2 backups — the user will migrate old
data manually. No convenience decrypt-link, no legacy URL parameters.

## Cryptography

- **KDF:** Argon2id, via a vendored single-file build of `hash-wasm` (MIT). The
  WASM is embedded as base64 in the JS file, so there is no separate `.wasm`
  binary, no build step, and no CDN — it works offline from `file://`.
- **Cipher:** AES-GCM-256 (Web Crypto API), unchanged.
- **Salt:** 16 random bytes (`crypto.getRandomValues`).
- **IV:** 12 random bytes (`crypto.getRandomValues`).
- **Argon2id default parameters (OWASP baseline):**
  - memory cost `m = 19456` KiB (19 MiB)
  - time cost `t = 2`
  - parallelism `p = 1`
  - hash length 32 bytes (256-bit AES key)
- Parameters are configurable on screen under an **Advanced** section and are
  always stored in the blob, so decryption never depends on the current UI
  settings.

## Portable blob format

A single self-describing, domain-independent text string:

```
bk1.<base64url(JSON)>
```

Where the JSON payload is:

```json
{
  "v": 1,
  "kdf": "argon2id",
  "m": 19456,
  "t": 2,
  "p": 1,
  "salt": "<hex>",
  "iv": "<hex>",
  "ct": "<hex>",
  "id": "7F3A"
}
```

- `bk1` = "backup format v1" prefix; the leading version tag lets the format
  evolve safely.
- `id` = short random match ID (e.g. 4 hex chars) used to pair the printed
  encrypted-data half with the printed passphrase half.
- The blob contains everything needed to decrypt **except the passphrase**.
- The QR code encodes exactly this blob string (not a URL), so the backup is
  not tied to any deployment domain.

## Passphrase generator

- Vendored **EFF diceware wordlist** (`assets/js/wordlist-eff.js`).
- Generates an N-word hyphenated passphrase (default 5 words) using
  `crypto.getRandomValues` for unbiased word selection.
- Word-based passphrases are chosen because the passphrase may need to be
  **retyped from paper** if the QR fails; words are far less error-prone to
  transcribe than random characters.
- The passphrase is never stored in the blob or QR — only printed on the
  separable bottom half of the backup sheet.

## Application structure

Single page, `index.html`, with two tabs toggled in vanilla JS. Tailwind
retained with refreshed styling.

### Encrypt tab
- Message textarea.
- Passphrase input + **Generate** button (diceware).
- **Advanced** disclosure: Argon2 memory / time / parallelism (prefilled with
  defaults).
- **Encrypt** button → derives key, encrypts, and displays:
  - ciphertext, salt, IV in clear text (hex, via `hex.js`)
  - the QR code of the blob
  - a **Print** button.

### Decrypt tab
- **Paste backup** field: accepts a `bk1.…` blob, parses it, and fills KDF type,
  params, salt, IV, and ciphertext.
- Manual salt / IV / ciphertext / params fields as a fallback.
- Passphrase input.
- **Decrypt** button → reproduces key from blob params, decrypts, shows the
  recovered message.

### Print view
Rendered (in-page or a generated print document) and triggered from the Encrypt
tab's Print button. Layout (validated via mockup):

- **Top half (keep with the data):** title + format tag, encrypted values in
  clear text (`algorithm: argon2id`, `params: m/t/p`, `salt`, `iv`,
  `ciphertext`) so any Argon2 + AES-GCM tool can decrypt, plus the **QR** of the
  blob for easy re-input.
- **Cut line** (✂, dashed) separating the two halves.
- **Bottom half (cut off, store separately):** the **passphrase** in large clear
  text + a prominent **WARNING** to store it apart from the data.
- A short **match ID** printed on both halves to re-pair them later.
- Print-specific styling via `@media print`.

## QR generation

Replace jQuery + `jquery.qrcode.js` with a small standalone **vanilla JS QR
generator**, vendored locally. It encodes the `bk1.…` blob string. jQuery is
removed from the project.

> Note: QR capacity is finite. For the intended payloads (passphrase-sized
> secrets, e.g. recovery codes / seed phrases) the blob is small and well within
> QR limits. Very large messages may exceed QR capacity; this is acceptable for
> the tool's purpose and out of scope to optimize.

## Files

**New / vendored:**
- `assets/js/cipher.js` — Argon2id key derivation + AES-GCM encrypt/decrypt,
  blob encode/decode, match-ID generation.
- `assets/js/hash-wasm.js` — vendored single-file Argon2id (hash-wasm).
- `assets/js/wordlist-eff.js` — vendored EFF diceware wordlist + generator.
- `assets/js/qrcode-vanilla.js` — vendored standalone QR generator (exact file
  name chosen at implementation time).

**Rewritten:**
- `index.html` — single tabbed app (Encrypt / Decrypt) + print view + page
  scripts.

**Removed:**
- `encrypt.html`, `decrypt.html`, `print.html`
- `assets/js/pbkdf2.js`
- `assets/js/jquery.qrcode.js`, `assets/js/qrcode.js`, and the jQuery dependency.

**Kept:**
- `assets/js/hex.js` — hex formatting for clear-text display of salt / IV /
  ciphertext.

## README

Update `README.md` to reflect the new design: the tool's **purpose** (printable
encrypted backups), **how it works** (Argon2id + AES-GCM, portable `bk1` blob,
QR), **how it's used** (encrypt → print → store passphrase separately → later
scan/paste + passphrase → decrypt), the security/threat-model rationale for
Argon2id and separate passphrase storage, and that everything runs locally and
offline.

## Out of scope

- Backward compatibility with old PBKDF2 backups.
- Convenience decrypt links / legacy URL parameters.
- Renaming the repository/directory.
- Optimizing QR capacity for very large messages.
