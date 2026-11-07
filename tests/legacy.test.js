import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CryptoJS, oldEncrypt, oldEncryptFile } from './helpers/old-share.js';
import { parseLegacyFragment, legacyPassHash, legacyDecrypt, parseFragment } from '../public/assets/js/app.js';

test('old link without a password', () => {
  const { secret, fragment } = oldEncrypt('Пароль от Wi-Fi: N7#qkV2m!Lp9xW4z');
  assert.equal(fragment.length, 32);
  assert.deepEqual(parseFragment('#' + fragment), { version: 1, fragment });
  const link = parseLegacyFragment(CryptoJS, '#' + fragment);
  assert.equal(link.hasPassword, false);
  assert.deepEqual(legacyDecrypt(CryptoJS, secret.data, link, false), { text: 'Пароль от Wi-Fi: N7#qkV2m!Lp9xW4z', file: null });
});

test('old link with a password', () => {
  const { secret, fragment } = oldEncrypt('admin / hunter2', 'correct horse');
  assert.equal(fragment.length, 11);
  const link = parseLegacyFragment(CryptoJS, fragment);
  assert.equal(link.hasPassword, true);
  assert.equal(legacyPassHash(CryptoJS, link, 'correct horse'), secret.passHash);
  assert.notEqual(legacyPassHash(CryptoJS, link, 'wrong'), secret.passHash);
  assert.equal(legacyDecrypt(CryptoJS, secret.data, link, false, 'correct horse').text, 'admin / hunter2');
  assert.throws(() => legacyDecrypt(CryptoJS, secret.data, link, false, 'wrong'), (e) => e.code === 'decrypt-failed');
});

test('old link with an attached file', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(4096));
  const { secret, fragment } = oldEncryptFile('see attachment', 'keys.bin', 'application/octet-stream', bytes, '');
  const out = legacyDecrypt(CryptoJS, secret.data, parseLegacyFragment(CryptoJS, fragment), true);
  assert.equal(out.text, 'see attachment');
  assert.equal(out.file.name, 'keys.bin');
  assert.equal(out.file.type, 'application/octet-stream');
  assert.deepEqual(out.file.data, bytes);
});

test('old fragments of other lengths are rejected', () => {
  assert.equal(parseLegacyFragment(CryptoJS, 'AbCdEfGhIjKlMn'), null);
});
