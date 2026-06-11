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
