import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptSecret, decryptSecret, deriveKeys, parseFragment, formatFragment,
  randomSecret, toBase64, fromBase64, toBase64Url, fromBase64Url,
  EOCryptoError, PBKDF2_ITERATIONS, FORMAT_VERSION
} from '../public/assets/js/app.js';

async function roundTrip(content, password) {
  const enc = await encryptSecret(content, { password });
  const link = parseFragment('#' + enc.fragment);
  assert.equal(link.version, 2);
  const keys = await deriveKeys(link.secret, password);
  return { enc, link, keys, out: await decryptSecret(enc.data, keys) };
}

async function rejects(promise, code) {
  await assert.rejects(promise, (e) => e instanceof EOCryptoError && e.code === code);
}

test('text without a password', async () => {
  const { enc, link, out } = await roundTrip({ text: 'Wi-Fi: Home_5G\nПароль: N7#qkV2m!Lp9xW4z 🔑' });
  assert.match(enc.fragment, /^2\.[A-Za-z0-9_-]{43}$/);
  assert.equal(link.hasPassword, false);
  assert.equal(enc.passHash, null);
  assert.equal(enc.attach, false);
  assert.equal(enc.data[0], FORMAT_VERSION);
  assert.equal(out.text, 'Wi-Fi: Home_5G\nПароль: N7#qkV2m!Lp9xW4z 🔑');
  assert.equal(out.file, null);
});

test('file without text', async () => {
  const data = crypto.getRandomValues(new Uint8Array(65536));
  const { enc, out } = await roundTrip({ file: { name: 'server-access.pdf', type: 'application/pdf', data } });
  assert.equal(enc.attach, true);
  assert.equal(out.text, '');
  assert.equal(out.file.name, 'server-access.pdf');
  assert.equal(out.file.type, 'application/pdf');
  assert.equal(out.file.size, data.length);
  assert.deepEqual(out.file.data, data);
});

test('text and file together, with a password', async () => {
  const data = new TextEncoder().encode('API_KEY=sk-test-123\nDB_PASSWORD=secret\n');
  const { enc, link, keys, out } = await roundTrip({ text: 'Ключи для стенда', file: { name: '.env', type: '', data: data.buffer } }, 'maple-orbit-velvet');
  assert.match(enc.fragment, /^2p\.[A-Za-z0-9_-]{43}$/);
  assert.equal(link.hasPassword, true);
  assert.equal(enc.passHash.length, 32);
  assert.deepEqual(keys.passHash, enc.passHash);
  assert.equal(out.text, 'Ключи для стенда');
  assert.equal(out.file.name, '.env');
  assert.equal(out.file.type, 'application/octet-stream');
  assert.deepEqual(out.file.data, data);
});

test('wrong password gives a different check hash and does not decrypt', async () => {
  const enc = await encryptSecret({ text: 'secret' }, { password: 'right' });
  const { secret } = parseFragment(enc.fragment);
  const wrong = await deriveKeys(secret, 'wrong');
  assert.notDeepEqual(wrong.passHash, enc.passHash);
  await rejects(decryptSecret(enc.data, wrong), 'decrypt-failed');
});

test('password-protected data does not open without the password', async () => {
  const enc = await encryptSecret({ text: 'secret' }, { password: 'right' });
  await rejects(decryptSecret(enc.data, await deriveKeys(parseFragment(enc.fragment).secret)), 'decrypt-failed');
});

test('wrong link secret does not decrypt', async () => {
  const enc = await encryptSecret({ text: 'secret' });
  await rejects(decryptSecret(enc.data, await deriveKeys(randomSecret())), 'decrypt-failed');
});

test('damaged data is rejected', async () => {
  const enc = await encryptSecret({ text: 'secret', file: { name: 'a.bin', data: new Uint8Array([1, 2, 3]) } });
  const keys = await deriveKeys(parseFragment(enc.fragment).secret);
  for (const i of [1, 5, 13, enc.data.length - 1]) {
    const bad = enc.data.slice();
    bad[i] ^= 0x01;
    await rejects(decryptSecret(bad, keys), 'decrypt-failed');
  }
  const wrongVersion = enc.data.slice();
  wrongVersion[0] = 1;
  await rejects(decryptSecret(wrongVersion, keys), 'unsupported-version');
  await rejects(decryptSecret(enc.data.subarray(0, 20), keys), 'bad-format');
  await rejects(decryptSecret(new Uint8Array(0), keys), 'unsupported-version');
});

test('check hash depends on the link, not only on the password', async () => {
  const s1 = randomSecret();
  const s2 = randomSecret();
  const a = await deriveKeys(s1, 'same password');
  const b = await deriveKeys(s1, 'same password');
  const c = await deriveKeys(s2, 'same password');
  assert.deepEqual(a.passHash, b.passHash);
  assert.notDeepEqual(a.passHash, c.passHash);
});

test('knowing the check hash does not give the encryption key', async () => {
  // A server that tries the check hash in place of the password-derived key fails.
  const enc = await encryptSecret({ text: 'secret' }, { password: 'right' });
  const { secret } = parseFragment(enc.fragment);
  const subtle = crypto.subtle;
  const ikm = new Uint8Array([...secret, ...enc.passHash]);
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const raw = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('encrypt.one/v2/enc+password') }, base, 256);
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  await rejects(decryptSecret(enc.data, { key, hasPassword: true }), 'decrypt-failed');
  const other = await subtle.importKey('raw', enc.passHash, 'AES-GCM', false, ['decrypt']);
  await rejects(decryptSecret(enc.data, { key: other, hasPassword: true }), 'decrypt-failed');
});

test('unicode passwords are normalized', async () => {
  const enc = await encryptSecret({ text: 'secret' }, { password: 'ключ-é' });
  const keys = await deriveKeys(parseFragment(enc.fragment).secret, 'ключ-é');
  assert.equal((await decryptSecret(enc.data, keys)).text, 'secret');
});

test('nothing to encrypt', async () => {
  await rejects(encryptSecret({ text: '' }), 'empty');
  await rejects(encryptSecret({}), 'empty');
});

test('PBKDF2 uses the OWASP iteration count', () => {
  assert.equal(PBKDF2_ITERATIONS, 600000);
});

test('fragment parsing', () => {
  const secret = randomSecret();
  assert.deepEqual(parseFragment(formatFragment(secret, false)), { version: 2, hasPassword: false, secret });
  assert.deepEqual(parseFragment('#' + formatFragment(secret, true)), { version: 2, hasPassword: true, secret });
  assert.deepEqual(parseFragment('#AbCdEfGhIjK'), { version: 1, fragment: 'AbCdEfGhIjK' });
  assert.deepEqual(parseFragment('AbCdEfGhIjKlMnOpQrStUvWxYz012345'), { version: 1, fragment: 'AbCdEfGhIjKlMnOpQrStUvWxYz012345' });
  for (const bad of ['', '#', '2.short', '3.' + toBase64Url(secret), '2x.' + toBase64Url(secret), '#AbC+EfGhIjK', 'AbCdEfGhIjKl']) {
    assert.equal(parseFragment(bad), null, bad);
  }
});

test('base64 helpers', () => {
  const bytes = new Uint8Array(100001);
  for (let i = 0; i < bytes.length; i += 65536) crypto.getRandomValues(bytes.subarray(i, i + 65536));
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
  assert.throws(() => fromBase64Url('a+b'), EOCryptoError);
});
