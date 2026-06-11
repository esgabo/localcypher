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
  let calls = 0;
  const deps = { randomInt: () => [0, 1, 2][calls++] };
  const phrase = generatePassphrase(3, deps);
  assert.strictEqual(phrase, [EFF_WORDLIST[0], EFF_WORDLIST[1], EFF_WORDLIST[2]].join('-'));
});

test('generatePassphrase defaults to 5 words', () => {
  assert.strictEqual(generatePassphrase().split('-').length, 5);
});
