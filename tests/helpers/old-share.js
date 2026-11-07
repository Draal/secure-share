// Encryption of the old public/js/share.js (before the redesign), kept to
// produce real v1 secrets in tests. Mirrors encrypt() from share.js line by line.
import { readFileSync } from 'node:fs';

// CryptoJS is a UMD script: run it with a CommonJS-like module object
const module = { exports: {} };
new Function('module', 'exports', readFileSync(new URL('../../public/assets/vendor/crypto-js.js', import.meta.url), 'utf8'))(module, module.exports);
export const CryptoJS = module.exports;

const urlHashFy = (text) => text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

function getRandomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** Returns what share.js posted to /p ({data, passHash?, att}) and the link fragment. */
export function oldEncrypt(text, passphrase) {
  let encText;
  let hash;
  const secret = {};
  if (!passphrase) {
    const h = getRandomBytes(16);
    passphrase = btoa(String.fromCharCode.apply(null, h));
    encText = CryptoJS.AES.encrypt(text, passphrase, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const k = CryptoJS.enc.Base64.parse(passphrase);
    k.concat(encText.salt);
    hash = urlHashFy(k.toString(CryptoJS.enc.Base64));
  } else {
    encText = CryptoJS.AES.encrypt(text, passphrase, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    hash = urlHashFy(encText.salt.toString(CryptoJS.enc.Base64));
    secret.passHash = CryptoJS.HmacSHA256(passphrase, hash).toString(CryptoJS.enc.Base64);
  }
  secret.data = encText.ciphertext.toString(CryptoJS.enc.Base64);
  return { secret, fragment: hash };
}

/** share.js packed an attached file as JSON {t, n, d: data URL}. */
export function oldEncryptFile(text, name, type, bytes, passphrase) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  const payload = JSON.stringify({ t: text, n: name, d: 'data:' + type + ';base64,' + btoa(bin) });
  const out = oldEncrypt(payload, passphrase);
  out.secret.att = true;
  return out;
}
