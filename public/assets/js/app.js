/* encrypt.one — all client code in one ES module.

   1. Encryption, format v2 (exported for the tests)
   2. Old links, format v1 (LEGACY-V1)
   3. QR code
   4. Password generator
   5. UI widgets
   6. Pages: creating a link, the sender view (/m/), the recipient page (/s/)

   UI texts come from data attributes in the markup, so this file holds no
   strings in the site languages. Sections 1–4 do not touch the DOM, and the
   DOM code runs only in a browser, so Node can import the module in tests.
*/

/* ========== 1. Encryption, format v2 ==========

   Uses only Web Crypto (globalThis.crypto).

   Link fragment:  #2.<S>   no password
                   #2p.<S>  with a password for opening
   S is a random 32-byte link secret in unpadded base64url. It never leaves
   the browsers of the sender and the recipient.

   Key derivation (HKDF and PBKDF2 use SHA-256):
     no password:   encKey   = HKDF(S, info "encrypt.one/v2/enc")
     with password: salt     = HKDF(S, info "encrypt.one/v2/pbkdf2-salt", 16 bytes)
                    PK       = PBKDF2(password, salt, 600 000 iterations)
                    passHash = HKDF(PK, info "encrypt.one/v2/auth")          -> sent to the server
                    encKey   = HKDF(S || PK, info "encrypt.one/v2/enc+password")
   passHash and encKey come from separate HKDF branches: knowing passHash
   gives neither PK nor encKey, and the server never sees S, so it cannot
   even start guessing passwords.

   Stored data:  [0x02][IV, 12 bytes][AES-256-GCM ciphertext + 16-byte tag]
   AAD:          "encrypt.one/v2" + one byte, 1 when a password is used
   Plaintext:    [header length, u32 big-endian][header JSON][file bytes]
   Header:       {"v":2,"text":"…","file":{"name":"…","type":"…","size":N}|null}
*/

export const FORMAT_VERSION = 2;
export const PBKDF2_ITERATIONS = 600000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
export const SECRET_BYTES = 32;

const IV_BYTES = 12;
const TAG_BYTES = 16;
const SALT_BYTES = 16;
const INFO = {
  enc: 'encrypt.one/v2/enc',
  encPassword: 'encrypt.one/v2/enc+password',
  salt: 'encrypt.one/v2/pbkdf2-salt',
  auth: 'encrypt.one/v2/auth'
};

export class EOCryptoError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'EOCryptoError';
    // empty, password-required, bad-format, unsupported-version, decrypt-failed
    this.code = code;
  }
}

function webcrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle || !c.getRandomValues) {
    throw new EOCryptoError('unsupported', 'Web Crypto API is not available');
  }
  return c;
}

const encoder = new TextEncoder();

function utf8(s) {
  return encoder.encode(s);
}

function fromUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) {
    throw new EOCryptoError('bad-format', 'Invalid UTF-8');
  }
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new EOCryptoError('bad-format', 'Expected bytes');
}

/* ---------- base64 ---------- */

export function toBase64(bytes) {
  bytes = toBytes(bytes);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromBase64(s) {
  let bin;
  try {
    bin = atob(s);
  } catch (e) {
    throw new EOCryptoError('bad-format', 'Invalid base64');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new EOCryptoError('bad-format', 'Invalid base64url');
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

/* ---------- link fragment ---------- */

export function randomSecret() {
  return webcrypto().getRandomValues(new Uint8Array(SECRET_BYTES));
}

export function formatFragment(secret, hasPassword) {
  return FORMAT_VERSION + (hasPassword ? 'p' : '') + '.' + toBase64Url(secret);
}

const V2_FRAGMENT = /^2(p?)\.([A-Za-z0-9_-]{43})$/;
// Old share.js links: base64url of an 8-byte salt (with a password) or of
// a 16-byte key plus the salt (without one).
const V1_FRAGMENT = /^(?:[A-Za-z0-9_-]{11}|[A-Za-z0-9_-]{32})$/;

/**
 * Parses the part of the link after "#".
 * Returns {version: 2, hasPassword, secret}, {version: 1, fragment} for old
 * links, or null when the fragment is not a valid key.
 */
export function parseFragment(fragment) {
  const f = String(fragment || '').replace(/^#/, '');
  const m = V2_FRAGMENT.exec(f);
  if (m) {
    const secret = fromBase64Url(m[2]);
    if (secret.length !== SECRET_BYTES) return null;
    return { version: 2, hasPassword: m[1] === 'p', secret };
  }
  if (V1_FRAGMENT.test(f)) return { version: 1, fragment: f };
  return null;
}

/* ---------- key derivation ---------- */

async function hkdf(ikm, info, bits) {
  const subtle = webcrypto().subtle;
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const out = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) },
    key,
    bits
  );
  return new Uint8Array(out);
}

async function pbkdf2(password, salt) {
  const subtle = webcrypto().subtle;
  const key = await subtle.importKey('raw', utf8(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  const out = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return new Uint8Array(out);
}

/**
 * Derives the encryption key and, with a password, the server check hash.
 * PBKDF2 runs once here, so the recipient can send passHash and later
 * decrypt with the same result.
 * @returns {Promise<{key: CryptoKey, passHash: Uint8Array|null, hasPassword: boolean}>}
 */
export async function deriveKeys(secret, password) {
  secret = toBytes(secret);
  if (secret.length !== SECRET_BYTES) throw new EOCryptoError('bad-format', 'Link secret must be 32 bytes');
  const hasPassword = typeof password === 'string' && password !== '';
  let ikm = secret;
  let info = INFO.enc;
  let passHash = null;
  if (hasPassword) {
    const salt = await hkdf(secret, INFO.salt, SALT_BYTES * 8);
    const pk = await pbkdf2(password, salt);
    passHash = await hkdf(pk, INFO.auth, 256);
    ikm = concat(secret, pk);
    info = INFO.encPassword;
  }
  const raw = await hkdf(ikm, info, 256);
  const key = await webcrypto().subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { key, passHash, hasPassword };
}

function aad(hasPassword) {
  return concat(utf8('encrypt.one/v2'), new Uint8Array([hasPassword ? 1 : 0]));
}

/* ---------- package ---------- */

function pack(text, file) {
  const header = utf8(JSON.stringify({
    v: FORMAT_VERSION,
    text,
    file: file ? { name: file.name, type: file.type, size: file.data.length } : null
  }));
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, header.length);
  return concat(len, header, file ? file.data : new Uint8Array(0));
}

function unpack(plain) {
  if (plain.length < 4) throw new EOCryptoError('bad-format', 'Package is too short');
  const len = new DataView(plain.buffer, plain.byteOffset, 4).getUint32(0);
  if (4 + len > plain.length) throw new EOCryptoError('bad-format', 'Header is out of bounds');
  let header;
  try {
    header = JSON.parse(fromUtf8(plain.subarray(4, 4 + len)));
  } catch (e) {
    throw new EOCryptoError('bad-format', 'Invalid header');
  }
  if (!header || header.v !== FORMAT_VERSION || typeof header.text !== 'string') {
    throw new EOCryptoError('bad-format', 'Invalid header');
  }
  const rest = plain.subarray(4 + len);
  let file = null;
  if (header.file) {
    const f = header.file;
    if (typeof f.name !== 'string' || typeof f.type !== 'string' || f.size !== rest.length) {
      throw new EOCryptoError('bad-format', 'File does not match its header');
    }
    file = { name: f.name, type: f.type, size: f.size, data: rest };
  } else if (rest.length) {
    throw new EOCryptoError('bad-format', 'Unexpected trailing data');
  }
  return { text: header.text, file };
}

/**
 * Encrypts text and an optional file as one package.
 * @param {{text?: string, file?: {name: string, type?: string, data: Uint8Array|ArrayBuffer}|null}} content
 * @param {{password?: string, secret?: Uint8Array}} [options] secret is for tests
 * @returns {Promise<{fragment: string, data: Uint8Array, passHash: Uint8Array|null, attach: boolean}>}
 */
export async function encryptSecret(content, options = {}) {
  const text = content && typeof content.text === 'string' ? content.text : '';
  let file = null;
  if (content && content.file) {
    file = {
      name: String(content.file.name || 'file'),
      type: String(content.file.type || 'application/octet-stream'),
      data: toBytes(content.file.data)
    };
  }
  if (!text && !file) throw new EOCryptoError('empty', 'Nothing to encrypt');

  const secret = options.secret ? toBytes(options.secret) : randomSecret();
  const keys = await deriveKeys(secret, options.password);
  const iv = webcrypto().getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = await webcrypto().subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(keys.hasPassword), tagLength: TAG_BYTES * 8 },
    keys.key,
    pack(text, file)
  );
  return {
    fragment: formatFragment(secret, keys.hasPassword),
    data: concat(new Uint8Array([FORMAT_VERSION]), iv, new Uint8Array(sealed)),
    passHash: keys.passHash,
    attach: !!file
  };
}

/**
 * Decrypts stored data with keys from deriveKeys().
 * @returns {Promise<{text: string, file: {name: string, type: string, size: number, data: Uint8Array}|null}>}
 */
export async function decryptSecret(data, keys) {
  data = toBytes(data);
  if (!data.length || data[0] !== FORMAT_VERSION) {
    throw new EOCryptoError('unsupported-version', 'Unknown data format');
  }
  if (data.length < 1 + IV_BYTES + TAG_BYTES) throw new EOCryptoError('bad-format', 'Data is too short');
  let plain;
  try {
    plain = await webcrypto().subtle.decrypt(
      { name: 'AES-GCM', iv: data.subarray(1, 1 + IV_BYTES), additionalData: aad(keys.hasPassword), tagLength: TAG_BYTES * 8 },
      keys.key,
      data.subarray(1 + IV_BYTES)
    );
  } catch (e) {
    throw new EOCryptoError('decrypt-failed', 'Wrong key or damaged data');
  }
  return unpack(new Uint8Array(plain));
}

/* ========== 2. Old links, format v1 ==========

   LEGACY-V1: remove this section, public/assets/vendor/crypto-js.js and the
   v1 branch of the recipient page 8 days after the redesign launch (the
   maximum storage time of old links is 7 days). Launch date: TODO.

   Old links have no version prefix in the fragment:
     11 chars: base64url of an 8-byte salt; the secret has a password
     32 chars: base64url of a 16-byte random key + the 8-byte salt
   Data is CryptoJS.AES (OpenSSL EVP_BytesToKey, AES-256-CBC, PKCS#7) of the
   text, or of JSON {t: text, n: file name, d: data URL} when a file was
   attached. The server check hash is HmacSHA256(password, salt string).
   CryptoJS 3.1.8 is loaded lazily and passed in.
*/

function urlHashFy(text) {
  return text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Same as base64KeyDecode in share.js, including the extra "=".
function base64KeyDecode(CryptoJS, key) {
  return CryptoJS.enc.Base64.parse(key.replace(/-/g, '+').replace(/_/g, '/') + '=');
}

/**
 * Splits an old fragment into the salt and, for links without a password,
 * the passphrase that was generated by share.js.
 * @returns {{hasPassword: boolean, salt: object, passphrase: string|null}|null}
 */
export function parseLegacyFragment(CryptoJS, fragment) {
  const parts = base64KeyDecode(CryptoJS, String(fragment).replace(/^#/, ''));
  if (parts.sigBytes === 8) {
    return { hasPassword: true, salt: parts, passphrase: null };
  }
  if (parts.sigBytes === 24) {
    const hex = parts.toString(CryptoJS.enc.Hex);
    return {
      hasPassword: false,
      passphrase: CryptoJS.enc.Hex.parse(hex.substring(0, 32)).toString(CryptoJS.enc.Base64),
      salt: CryptoJS.enc.Hex.parse(hex.substring(32))
    };
  }
  return null;
}

/** Base64 check hash the old server stored for a password-protected secret. */
export function legacyPassHash(CryptoJS, link, password) {
  const hash = urlHashFy(link.salt.toString(CryptoJS.enc.Base64));
  return CryptoJS.HmacSHA256(password, hash).toString(CryptoJS.enc.Base64);
}

function dataURLToBytes(dataURL) {
  const comma = dataURL.indexOf(',');
  if (comma === -1) return null;
  const header = dataURL.slice(5, comma);
  const semicolon = header.indexOf(';');
  const type = semicolon === -1 ? header : header.slice(0, semicolon);
  const bin = atob(dataURL.slice(comma + 1));
  const data = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
  return { type: type || 'application/octet-stream', data };
}

/**
 * Decrypts base64 data of an old secret.
 * @returns {{text: string, file: {name: string, type: string, size: number, data: Uint8Array}|null}}
 */
export function legacyDecrypt(CryptoJS, dataBase64, link, attach, password) {
  const passphrase = link.hasPassword ? password : link.passphrase;
  let plain;
  try {
    plain = CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(
      CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(dataBase64), salt: link.salt }),
      passphrase,
      { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    ));
  } catch (e) {
    plain = '';
  }
  if (!plain) {
    const err = new Error('Wrong key or damaged data');
    err.code = 'decrypt-failed';
    throw err;
  }
  if (!attach) return { text: plain, file: null };

  const d = JSON.parse(plain);
  const file = d.d ? dataURLToBytes(d.d) : null;
  return {
    text: d.t || '',
    file: file ? { name: d.n || 'download', type: file.type, size: file.data.length, data: file.data } : null
  };
}

/* ========== 3. QR code ==========
   ISO/IEC 18004, byte mode, error correction level M, versions 1–10 (up to
   213 bytes), which covers secret links with room to spare. */

// Error correction level M: [EC codewords per block, blocks, data codewords per block] groups.
const EC_M = [
  null,
  [10, [[1, 16]]],
  [16, [[1, 28]]],
  [26, [[1, 44]]],
  [18, [[2, 32]]],
  [24, [[2, 43]]],
  [16, [[4, 27]]],
  [18, [[4, 31]]],
  [22, [[2, 38], [2, 39]]],
  [22, [[3, 36], [2, 37]]],
  [26, [[4, 43], [1, 44]]]
];
const ALIGNMENT = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
const FORMAT_BITS_M = 0; // EC level M in the format information

/* ---------- Reed–Solomon over GF(256), polynomial 0x11D ---------- */

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = new Array(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    divisor.forEach((coef, i) => { result[i] ^= gfMul(coef, factor); });
  }
  return result;
}

/* ---------- data codewords ---------- */

function dataCapacity(version) {
  const [, groups] = EC_M[version];
  return groups.reduce((n, [blocks, size]) => n + blocks * size, 0);
}

function encodeData(bytes, version) {
  const bits = [];
  const put = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4); // byte mode
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capacityBits = dataCapacity(version) * 8;
  put(0, Math.min(4, capacityBits - bits.length));
  while (bits.length % 8) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let pad = 0xec; out.length < dataCapacity(version); pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

function addErrorCorrection(data, version) {
  const [ecLen, groups] = EC_M[version];
  const divisor = rsDivisor(ecLen);
  const blocks = [];
  let offset = 0;
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      const d = data.slice(offset, offset + size);
      offset += size;
      blocks.push({ data: d, ec: rsRemainder(d, divisor) });
    }
  }
  const out = [];
  const maxData = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < maxData; i++) for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
  for (let i = 0; i < ecLen; i++) for (const b of blocks) out.push(b.ec[i]);
  return out;
}

/* ---------- matrix ---------- */

class Matrix {
  constructor(version) {
    this.size = version * 4 + 17;
    this.dark = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.fixed = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
  }

  set(x, y, dark) {
    this.dark[y][x] = dark;
    this.fixed[y][x] = true;
  }
}

function drawFunctionPatterns(m, version) {
  const n = m.size;
  for (let i = 0; i < n; i++) {
    m.set(6, i, i % 2 === 0);
    m.set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= n || y >= n) continue;
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        m.set(x, y, dist !== 2 && dist !== 4);
      }
    }
  }
  const pos = ALIGNMENT[version];
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === pos.length - 1) || (i === pos.length - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          m.set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }
  drawFormat(m, 0); // reserve the area, real bits come after masking
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      m.set(a, b, dark);
      m.set(b, a, dark);
    }
  }
}

function drawFormat(m, mask) {
  const data = (FORMAT_BITS_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) === 1;
  const n = m.size;
  for (let i = 0; i <= 5; i++) m.set(8, i, bit(i));
  m.set(8, 7, bit(6));
  m.set(8, 8, bit(7));
  m.set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) m.set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) m.set(n - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) m.set(8, n - 15 + i, bit(i));
  m.set(8, n - 8, true); // dark module
}

function drawCodewords(m, codewords) {
  const n = m.size;
  let i = 0;
  const total = codewords.length * 8;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? n - 1 - vert : vert;
        if (m.fixed[y][x]) continue;
        m.dark[y][x] = i < total && ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
        i++;
      }
    }
  }
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
];

function applyMask(m, mask) {
  const f = MASKS[mask];
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      if (!m.fixed[y][x] && f(x, y)) m.dark[y][x] = !m.dark[y][x];
    }
  }
}

// Penalty rules N1–N4 of the standard, used to pick the mask.
function penalty(m) {
  const n = m.size;
  const d = m.dark;
  let score = 0;
  const line = (get) => {
    let s = 0;
    for (let a = 0; a < n; a++) {
      let run = 1;
      for (let b = 1; b < n; b++) {
        if (get(a, b) === get(a, b - 1)) {
          run++;
        } else {
          if (run >= 5) s += run - 2;
          run = 1;
        }
      }
      if (run >= 5) s += run - 2;
      const row = [];
      for (let b = 0; b < n; b++) row.push(get(a, b) ? 1 : 0);
      const str = row.join('');
      for (const p of ['10111010000', '00001011101']) {
        for (let k = str.indexOf(p); k !== -1; k = str.indexOf(p, k + 1)) s += 40;
      }
    }
    return s;
  };
  score += line((a, b) => d[a][b]);
  score += line((a, b) => d[b][a]);
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = d[y][x];
      if (c === d[y][x + 1] && c === d[y + 1][x] && c === d[y + 1][x + 1]) score += 3;
    }
  }
  let dark = 0;
  for (const row of d) for (const c of row) if (c) dark++;
  const total = n * n;
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
  return score;
}

/**
 * Builds the module matrix for text: an array of rows of booleans (true = dark).
 */
function qrMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  while (version <= 10 && Math.floor((dataCapacity(version) * 8 - 4 - (version < 10 ? 8 : 16)) / 8) < bytes.length) version++;
  if (version > 10) throw new Error('Text is too long for a QR code');

  const codewords = addErrorCorrection(encodeData(bytes, version), version);
  let best = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const m = new Matrix(version);
    drawFunctionPatterns(m, version);
    drawCodewords(m, codewords);
    applyMask(m, mask);
    drawFormat(m, mask);
    const score = penalty(m);
    if (score < bestScore) {
      best = m;
      bestScore = score;
    }
  }
  return best.dark;
}

/** SVG of the code with a 4-module quiet zone, as a data: URL for <img src>. */
function qrDataURL(text) {
  const modules = qrMatrix(text);
  const n = modules.length;
  const size = n + 8;
  let path = '';
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (modules[y][x]) path += 'M' + (x + 4) + ' ' + (y + 4) + 'h1v1h-1z';
    }
  }
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" shape-rendering="crispEdges">' +
    '<rect width="' + size + '" height="' + size + '" fill="#FFFFFF"/><path fill="#161A23" d="' + path + '"/></svg>';
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

/* ========== 4. Password generator ==========
   Randomness comes only from crypto.getRandomValues, sampled without bias:
   values beyond the largest multiple of the range are rejected. */

const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!#$%&*+-=?@^_'
};
// Look-alike characters: 0 and O, 1, l and I, and o
const SIMILAR = /[0Oo1lI]/g;
const UINT32_RANGE = 0x100000000;

/** Uniform integer in [0, max). */
export function randomInt(max) {
  const limit = UINT32_RANGE - (UINT32_RANGE % max);
  const buf = new Uint32Array(1);
  do {
    webcrypto().getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

const pick = (chars) => chars[randomInt(chars.length)];
const repeat = (n, fn) => Array.from({ length: n }, fn).join('');

function charsets(opts) {
  return Object.keys(CHARSETS)
    .filter((name) => opts[name])
    .map((name) => (opts.noSimilar ? CHARSETS[name].replace(SIMILAR, '') : CHARSETS[name]));
}

/**
 * Password with at least one character from every selected set.
 * Regenerating from scratch until that holds keeps the distribution uniform.
 * @param {{length: number, upper?: boolean, lower?: boolean, digits?: boolean, symbols?: boolean, noSimilar?: boolean}} opts
 */
export function password(opts) {
  const sets = charsets(opts);
  if (!sets.length) throw new RangeError('No character sets selected');
  const all = sets.join('');
  const length = Math.max(opts.length, sets.length);
  let out;
  do {
    out = repeat(length, () => pick(all));
  } while (!sets.every((set) => [...out].some((ch) => set.includes(ch))));
  return out;
}

/** Exact entropy in bits: log2 of the number of passwords that contain every selected set (inclusion-exclusion). */
export function passwordEntropy(opts) {
  const sets = charsets(opts);
  const total = sets.join('').length;
  const length = Math.max(opts.length, sets.length);
  let share = 0;
  for (let mask = 0; mask < 1 << sets.length; mask++) {
    let missing = 0;
    let excluded = 0;
    sets.forEach((set, i) => {
      if (mask & (1 << i)) {
        missing += set.length;
        excluded++;
      }
    });
    share += (excluded % 2 ? -1 : 1) * ((total - missing) / total) ** length;
  }
  return length * Math.log2(total) + Math.log2(share);
}

const phrase = (words, list) => Array.from({ length: words }, () => list[randomInt(list.length)]).join('-');
const pin = (digits) => repeat(digits, () => pick(CHARSETS.digits));

// 1 weak, 2 fair, 3 strong, 4 very strong
const strengthLevel = (bits) => (bits >= 80 ? 4 : bits >= 60 ? 3 : bits >= 36 ? 2 : 1);

/* ========== 5. UI widgets ==========
   Each widget finds its elements by data attributes and does nothing when
   they are not on the page. */

const PREFILL_KEY = 'encrypt-one:prefill'; // sessionStorage: generator page -> form
const BANNER_KEY = 'encrypt-one:lang-banner-closed'; // localStorage
const THEME_KEY = 'encrypt-one:theme'; // localStorage, read early by theme.js
const DESTROYED_KEY = 'encrypt-one:destroyed:'; // localStorage: secrets destroyed from this browser

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const pageLang = () => document.documentElement.lang;
// Hashed asset URLs come from data attributes on <body>
const assetURL = (name) => document.body.dataset[name];

function storage(type) {
  try {
    const s = window[type];
    s.getItem('_');
    return s;
  } catch (e) {
    return null; // disabled or blocked
  }
}

function announce(text) {
  const region = $('[data-live-region]');
  if (!region) return;
  region.textContent = '';
  setTimeout(() => { region.textContent = text; }, 50);
}

function onOutside(container, callback) {
  document.addEventListener('pointerdown', (event) => {
    if (!container.contains(event.target)) callback();
  });
}

const scripts = {};
function loadScript(src) {
  scripts[src] ||= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    script.onload = resolve;
    script.onerror = () => {
      delete scripts[src];
      reject(new Error('Cannot load ' + src));
    };
    document.head.append(script);
  });
  return scripts[src];
}

const loadWordlist = () => loadScript(assetURL('wordlist')).then(() => window.EFF_WORDLIST);
// LEGACY-V1: CryptoJS is loaded only for links made by the old share.js
const loadCryptoJS = () => loadScript(assetURL('cryptojs')).then(() => window.CryptoJS);

function formatSize(bytes) {
  const units = ['byte', 'kilobyte', 'megabyte', 'gigabyte'];
  let i = 0;
  let value = bytes;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return new Intl.NumberFormat(pageLang(), { style: 'unit', unit: units[i], unitDisplay: 'short', maximumFractionDigits: i ? 1 : 0 }).format(value);
}

// Accordion: one item open at a time
function initAccordion(accordion) {
  const buttons = $$('[aria-controls]', accordion);
  buttons.forEach((button) => button.addEventListener('click', () => {
    const open = button.getAttribute('aria-expanded') !== 'true';
    for (const other of buttons) {
      const expanded = other === button && open;
      other.setAttribute('aria-expanded', String(expanded));
      document.getElementById(other.getAttribute('aria-controls')).hidden = !expanded;
    }
  }));
}

// Toggle button that reveals a panel
function initTogglePanel(button) {
  const panel = document.getElementById(button.getAttribute('aria-controls'));
  button.addEventListener('click', () => {
    const pressed = button.getAttribute('aria-pressed') !== 'true';
    button.setAttribute('aria-pressed', String(pressed));
    panel.hidden = !pressed;
    if (pressed) $('input, textarea', panel)?.focus();
  });
}

// Dropdown with role=listbox
function initSelect(select) {
  const button = $('[aria-haspopup="listbox"]', select);
  const list = $('[role="listbox"]', select);
  const options = $$('[role="option"]', list);
  const input = $('[data-select-input]', select);

  function open() {
    list.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    (options.find((o) => o.getAttribute('aria-selected') === 'true') || options[0]).focus();
  }

  function close(returnFocus) {
    if (list.hidden) return;
    list.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    if (returnFocus) button.focus();
  }

  function choose(option) {
    options.forEach((o) => o.setAttribute('aria-selected', String(o === option)));
    $('[data-select-value]', select).textContent = option.textContent.trim();
    input.value = option.dataset.value;
    close(true);
  }

  button.addEventListener('click', () => (list.hidden ? open() : close(false)));
  button.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      open();
    }
  });
  list.addEventListener('click', (event) => {
    const option = event.target.closest('[role="option"]');
    if (option) choose(option);
  });
  list.addEventListener('keydown', (event) => {
    const i = options.indexOf(document.activeElement);
    const focus = (n) => options[Math.max(0, Math.min(n, options.length - 1))].focus();
    const keys = {
      ArrowDown: () => focus(i + 1),
      ArrowUp: () => focus(i - 1),
      Home: () => focus(0),
      End: () => focus(options.length - 1),
      Enter: () => i !== -1 && choose(options[i]),
      ' ': () => i !== -1 && choose(options[i]),
      Escape: () => close(true)
    };
    if (event.key === 'Tab') close(false);
    if (keys[event.key]) {
      event.preventDefault();
      keys[event.key]();
    }
  });
  onOutside(select, () => close(false));
}

function initLanguageMenu(container) {
  const button = $('button[aria-controls]', container);
  const menu = document.getElementById(button.getAttribute('aria-controls'));

  function positionMenu() {
    menu.style.removeProperty('--lang-menu-shift');
    menu.style.removeProperty('--lang-menu-space');
    const buttonRect = button.getBoundingClientRect();
    const available = container.classList.contains('lang--up')
      ? buttonRect.top - 18 : window.innerHeight - buttonRect.bottom - 18;
    menu.style.setProperty('--lang-menu-space', Math.max(0, available) + 'px');
    if (!window.matchMedia('(max-width: 700px)').matches) return;
    const rect = menu.getBoundingClientRect();
    const shift = rect.left < 12 ? 12 - rect.left : Math.min(0, window.innerWidth - 12 - rect.right);
    menu.style.setProperty('--lang-menu-shift', shift + 'px');
  }

  function setOpen(open, returnFocus) {
    menu.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    if (open) positionMenu();
    if (!open && returnFocus) button.focus();
  }

  button.addEventListener('click', () => {
    const open = menu.hidden;
    setOpen(open);
    if (open) $('a', menu).focus();
  });
  $('[data-lang-close]', menu).addEventListener('click', () => setOpen(false, true));
  container.addEventListener('keydown', (event) => {
    if (menu.hidden) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false, true);
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      const links = $$('a, [data-lang-close]', menu);
      const i = links.indexOf(document.activeElement);
      event.preventDefault();
      links[event.key === 'ArrowDown' ? Math.min(i + 1, links.length - 1) : Math.max(i - 1, 0)].focus();
    }
  });
  container.addEventListener('focusout', (event) => {
    if (event.relatedTarget && !container.contains(event.relatedTarget)) setOpen(false);
  });
  onOutside(container, () => setOpen(false));
  window.addEventListener('resize', () => { if (!menu.hidden) positionMenu(); });
}

const savedLanguage = () => (document.cookie.match(/(?:^|;\s*)lang=([^;]+)/) || [])[1];

// Picking a language saves it in the "lang" cookie, like the old site did.
// On /s/ and /m/ the address stays the same, so the #key part is carried over.
function initLanguageChoice(link) {
  link.addEventListener('click', () => {
    const secure = location.protocol === 'https:' ? '; secure' : '';
    document.cookie = 'lang=' + encodeURIComponent(link.dataset.langChoice) + '; path=/; max-age=' + 5 * 365 * 24 * 3600 + '; samesite=lax' + secure;
    if (link.pathname === location.pathname) link.hash = location.hash;
  });
}

// "This page is available in your language": shown when the browser language
// is another site language and the visitor has not chosen a language yet.
// To preview the layout: ?lang-banner=en or ?lang-banner=uk
function initLanguageBanner(banner) {
  const local = storage('localStorage');
  const forced = new URLSearchParams(location.search).get('lang-banner');
  if (!forced && (savedLanguage() || local?.getItem(BANNER_KEY))) return;
  const preferred = (forced || navigator.languages?.[0] || navigator.language || '').split('-')[0].toLowerCase();
  const link = preferred !== pageLang() && $(`[data-lang-banner-link="${preferred}"]`, banner);
  if (!link) return;
  $$('[data-lang-banner-link]', banner).forEach((a) => { a.hidden = a !== link; });
  banner.hidden = false;
  $('[data-lang-banner-close]', banner).addEventListener('click', () => {
    banner.hidden = true;
    local?.setItem(BANNER_KEY, '1');
  });
}

// Theme switcher: system, light or dark. "system" removes the saved choice.
// Both footers may hold a switcher, so all buttons on the page are updated.
function showTheme(theme) {
  $$('[data-theme-choice]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.themeChoice === theme)));
}

function initThemeSwitch(group) {
  showTheme(document.documentElement.dataset.theme || 'system');
  $$('[data-theme-choice]', group).forEach((button) => button.addEventListener('click', () => {
    const theme = button.dataset.themeChoice;
    const local = storage('localStorage');
    if (theme === 'system') {
      delete document.documentElement.dataset.theme;
      local?.removeItem(THEME_KEY);
    } else {
      document.documentElement.dataset.theme = theme;
      local?.setItem(THEME_KEY, theme);
    }
    showTheme(theme);
  }));
}

// File attach and drag-and-drop. The chosen file is kept in zone.file.
function initDropzone(zone) {
  const input = $('[data-file-input]', zone);
  const pickButton = $('[data-file-pick]', zone);
  const card = $('[data-file-card]', zone);
  let depth = 0;

  function show(file) {
    if (!file) return;
    $('[data-file-name]', card).textContent = file.name;
    $('[data-file-size]', card).textContent = formatSize(file.size);
    card.hidden = false;
    zone.file = file;
    announce(file.name);
  }

  const hasFiles = (event) => [...(event.dataTransfer?.types || [])].includes('Files');
  const dragOver = (on) => zone.classList.toggle('is-dragover', on);

  pickButton.addEventListener('click', () => input.click());
  input.addEventListener('change', () => show(input.files[0]));
  $('[data-file-remove]', card).addEventListener('click', () => {
    card.hidden = true;
    zone.file = null;
    input.value = '';
    pickButton.focus();
  });
  zone.addEventListener('dragenter', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth++;
    dragOver(true);
  });
  zone.addEventListener('dragover', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  });
  zone.addEventListener('dragleave', () => {
    depth = Math.max(depth - 1, 0);
    if (!depth) dragOver(false);
  });
  zone.addEventListener('drop', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth = 0;
    dragOver(false);
    show(event.dataTransfer.files[0]);
  });
  // A file dropped outside the field must not replace the page
  for (const type of ['dragover', 'drop']) {
    window.addEventListener(type, (event) => {
      if (!zone.contains(event.target)) event.preventDefault();
    });
  }
}

// "Suggest" a passphrase for an input
function initPhraseButton(button) {
  const target = document.getElementById(button.dataset.generatePhrase);
  button.addEventListener('click', async () => {
    target.value = phrase(4, await loadWordlist());
    target.focus();
    target.select();
  });
}

function copyFallback(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.readOnly = true;
  area.className = 'visually-hidden';
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  if (!ok) throw new Error('Copy failed');
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    copyFallback(text);
  }
}

function selectContents(node) {
  if (typeof node.select === 'function') return node.select();
  const range = document.createRange();
  range.selectNodeContents(node);
  getSelection().removeAllRanges();
  getSelection().addRange(range);
}

function initCopyButton(button) {
  let timer = 0;
  button.addEventListener('click', async () => {
    const source = $(button.dataset.copy);
    const text = source.tagName === 'INPUT' || source.tagName === 'TEXTAREA' ? source.value : source.textContent;
    try {
      await copyText(text.trim());
    } catch (e) {
      return selectContents(source); // so it can be copied by hand
    }
    button.classList.add('is-copied');
    const done = $('.copy-btn__done', button);
    if (done) announce(done.textContent.trim());
    clearTimeout(timer);
    timer = setTimeout(() => button.classList.remove('is-copied'), 2000);
  });
}

function initDialog(dialog) {
  $$(`[data-dialog-open="${dialog.id}"]`).forEach((button) => button.addEventListener('click', () => dialog.showModal()));
  $$('[data-dialog-close]', dialog).forEach((button) => button.addEventListener('click', () => dialog.close()));
  // A click on the backdrop closes the dialog
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
}

// Generator widget: the generator page and the compact dialog of the form
function initGenerator(root) {
  const field = (name) => $(`[data-gen="${name}"]`, root);
  const output = $('[data-gen-output]', root);
  const meter = $('[data-gen-meter]', root);
  const tabs = $$('[role="tab"]', root);
  const sets = ['upper', 'lower', 'digits', 'symbols'].map(field);
  let mode = 'password';

  async function generate() {
    let value;
    let bits;
    if (mode === 'password') {
      const opts = { length: +field('length').value, noSimilar: field('noSimilar').checked };
      for (const box of sets) opts[box.dataset.gen] = box.checked;
      value = password(opts);
      bits = passwordEntropy(opts);
    } else if (mode === 'phrase') {
      const list = await loadWordlist().catch(() => null);
      if (!list || mode !== 'phrase') return;
      const words = +field('words').value;
      value = phrase(words, list);
      bits = words * Math.log2(list.length);
    } else {
      const digits = +field('pinDigits').value;
      value = pin(digits);
      bits = digits * Math.log2(10);
    }
    output.textContent = value;
    const level = strengthLevel(bits);
    meter.dataset.level = level;
    $('[data-gen-meter-label]', meter).textContent = meter.getAttribute(mode === 'pin' ? 'data-label-pin' : 'data-label-' + level);
    $('[data-gen-meter-bits]', meter).textContent = meter.dataset.bits.replace('{bits}', Math.round(bits));
  }

  // At least one character set stays selected: the last checked box is locked
  function lockLastSet() {
    const checked = sets.filter((box) => box.checked);
    for (const box of sets) box.disabled = checked.length === 1 && box.checked;
  }

  function selectTab(tab, focus) {
    for (const t of tabs) {
      const selected = t === tab;
      t.setAttribute('aria-selected', String(selected));
      t.tabIndex = selected ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
    }
    mode = tab.dataset.mode;
    if (focus) tab.focus();
    generate();
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (event) => {
      const next = {
        ArrowRight: tabs[(i + 1) % tabs.length],
        ArrowLeft: tabs[(i - 1 + tabs.length) % tabs.length],
        Home: tabs[0],
        End: tabs[tabs.length - 1]
      }[event.key];
      if (next) {
        event.preventDefault();
        selectTab(next, true);
      }
    });
  });
  for (const input of ['length', 'words', 'pinDigits'].map(field)) {
    const value = $(`[data-range-value="${input.id}"]`, root);
    input.addEventListener('input', () => {
      value.textContent = input.value;
      generate();
    });
    value.textContent = input.value;
  }
  for (const box of [...sets, field('noSimilar')]) {
    box.addEventListener('change', () => {
      lockLastSet();
      generate();
    });
  }
  $('[data-gen-regenerate]', root).addEventListener('click', generate);

  lockLastSet();
  generate();
  return { generate, value: () => output.textContent };
}

// Generator page: "Send as a one-time link" hands the value to the home page form
function initGeneratorPage(root) {
  const generator = initGenerator(root);
  $('[data-gen-send]').addEventListener('click', () => {
    storage('sessionStorage')?.setItem(PREFILL_KEY, generator.value());
  });
}

// Form: the compact generator dialog inserts the value at the cursor
function initGeneratorDialog(dialog) {
  const generator = initGenerator($('[data-generator]', dialog));
  const field = $('#secret-text');
  $(`[data-dialog-open="${dialog.id}"]`).addEventListener('click', generator.generate);
  $('[data-gen-insert]', dialog).addEventListener('click', () => {
    field.setRangeText(generator.value(), field.selectionStart, field.selectionEnd, 'end');
    dialog.close();
    field.focus();
  });
}

// A password from the generator page prefills the form
function prefillForm(form) {
  const session = storage('sessionStorage');
  const value = session?.getItem(PREFILL_KEY);
  if (!value) return;
  session.removeItem(PREFILL_KEY);
  const field = $('#secret-text', form);
  field.value = value;
  field.focus();
}

/* ========== 6. Pages ========== */

class APIError extends Error {
  constructor(code, status, body) {
    super(body?.message || code);
    this.code = code;
    this.status = status;
    this.serverMessage = body?.message;
  }
}

async function api(path, payload) {
  let res;
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, lang: pageLang() }),
      cache: 'no-store'
    });
  } catch (e) {
    throw new APIError('network', 0);
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = json.error || {};
    throw new APIError(err.code || 'server_error', res.status, err);
  }
  return json;
}

function showView(root, name) {
  $$('[data-view]', root).forEach((v) => { v.hidden = v.dataset.view !== name; });
}

function setError(box, text) {
  $('span', box).textContent = text || '';
  box.hidden = !text;
}

const recipientLink = (id, fragment) => location.origin + '/s/' + id + '#' + fragment;

// Sender view ("link is ready"): on /m/ and in place of the form after creating
class ManageView {
  constructor(container) {
    this.container = container;
    this.box = $('.manage', container);
    this.state = null;
    this.timer = 0;
    this.onAnother = null;

    $('[data-destroy]', container).addEventListener('click', () => this.destroy());
    $('[data-another]', container).addEventListener('click', () => this.onAnother?.());
    $('[data-dialog-open="qr-dialog"]', container)?.addEventListener('click', () => this.fillQR());
  }

  set(state) {
    this.state = state;
    this.render();
  }

  destroyedHere() {
    return !!storage('localStorage')?.getItem(DESTROYED_KEY + this.state.id);
  }

  render() {
    const s = this.state;
    const c = this.container;
    clearTimeout(this.timer);
    document.title = this.box.dataset.title;

    let view = 'alive';
    if (this.destroyedHere()) view = 'destroyed';
    else if (s.expires && Date.now() >= s.expires * 1000) view = 'expired';
    showView(c, view);

    // Link, share buttons and QR code need the recipient link, which is
    // known only in the tab that created it.
    const hasLink = !!s.link;
    $$('[data-link-group], [data-share-group]', c).forEach((g) => { g.hidden = !hasLink; });
    $$('[data-link-unavailable]', c).forEach((n) => { n.hidden = hasLink; });
    $$('.link-box.is-inactive', c).forEach((b) => { b.closest('.result__group').hidden = !hasLink; });
    if (hasLink) {
      const hash = s.link.indexOf('#');
      $$('[data-link-base]', c).forEach((e) => { e.textContent = s.link.slice(0, hash); });
      $$('[data-link-key]', c).forEach((e) => { e.textContent = s.link.slice(hash); });
      this.fillShare();
    }

    const expires = $('[data-expires]', c);
    expires.closest('.status-item').hidden = !s.expires;
    if (s.expires) {
      const date = new Date(s.expires * 1000);
      expires.setAttribute('datetime', date.toISOString());
      expires.textContent = new Intl.DateTimeFormat(pageLang(), { dateStyle: 'long', timeStyle: 'short' }).format(date);
    }
    $('[data-destroy]', c).hidden = !s.token;
    $('[data-another-wrap]', c).hidden = !this.onAnother;
    setError($('[data-manage-error]', c), '');

    if (view === 'alive' && s.expires) {
      const ms = s.expires * 1000 - Date.now();
      if (ms < 0x7fffffff) this.timer = setTimeout(() => this.render(), ms + 500);
    }
  }

  fillShare() {
    const link = this.state.link;
    const grid = $('[data-share-text]', this.container);
    const message = grid.dataset.shareText;
    const e = encodeURIComponent;
    $('[data-share="telegram"]', grid).href = 'https://t.me/share/url?url=' + e(link) + '&text=' + e(message);
    $('[data-share="whatsapp"]', grid).href = 'https://wa.me/?text=' + e(message + ' ' + link);
    $('[data-share="mail"]', grid).href = 'mailto:?subject=' + e(grid.dataset.shareSubject) + '&body=' + e(message + ' ' + link);
  }

  fillQR() {
    const dialog = $('#qr-dialog');
    const link = this.state.link;
    if (!link) return;
    $('[data-link-text]', dialog).textContent = link;
    const img = $('[data-qr-image]', dialog);
    if (img.dataset.for === link) return;
    img.src = qrDataURL(link);
    img.dataset.for = link;
  }

  async destroy() {
    const s = this.state;
    if (!confirm(this.box.dataset.msgDestroyConfirm)) return;
    const button = $('[data-destroy]', this.container);
    button.disabled = true;
    try {
      await api('/api/secrets/' + s.id + '/destroy', { token: s.token });
      storage('localStorage')?.setItem(DESTROYED_KEY + s.id, '1');
      this.render();
    } catch (e) {
      setError($('[data-manage-error]', this.container), e.serverMessage || this.box.dataset.msgDestroyError);
    } finally {
      button.disabled = false;
    }
  }
}

// Home page form: create a link
function initForm(form) {
  const compose = $('[data-compose]');
  const manageContainer = $('[data-manage]');
  const manage = new ManageView(manageContainer);
  const msg = (name) => form.getAttribute('data-msg-' + name);
  const errorBox = $('[data-form-error]', form);
  const submit = $('[data-submit]', form);
  const submitLabel = $('[data-submit-label]', form);
  const idleLabel = submitLabel.textContent;
  let last = null; // {content, password, ttl}: kept in memory for "get another link"

  function busy(on) {
    submit.disabled = on;
    submitLabel.textContent = on ? msg('submitting') : idleLabel;
  }

  async function createLink({ content, password, ttl }) {
    const enc = await encryptSecret(content, { password });
    const res = await api('/api/secrets', {
      data: toBase64(enc.data),
      passHash: enc.passHash ? toBase64(enc.passHash) : '',
      attach: enc.attach,
      ttl
    });
    return { id: res.id, token: res.token, expires: res.expires, link: recipientLink(res.id, enc.fragment) };
  }

  // The address bar keeps the page address on purpose: people used to copy it
  // instead of the generated link, and the recipient got nothing.
  function showManage(state) {
    manage.set(state);
    compose.hidden = true;
    manageContainer.hidden = false;
    scrollTo(0, 0);
    const title = $('[data-view="alive"] h1', manageContainer);
    title.tabIndex = -1;
    title.focus({ preventScroll: true });
    announce(title.textContent);
  }

  manage.onAnother = async () => {
    const button = $('[data-another]', manageContainer);
    button.disabled = true;
    try {
      showManage(await createLink(last));
    } catch (e) {
      setError($('[data-manage-error]', manageContainer), e.code === 'network' ? msg('network') : e.serverMessage || e.message);
    } finally {
      button.disabled = false;
    }
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError(errorBox, '');
    const text = $('#secret-text', form).value;
    const file = $('[data-dropzone]', form).file;
    const protect = $('[data-toggle-panel][aria-pressed="true"]', form);
    const password = protect ? $('#open-password', form).value : '';
    const ttl = $('[name="ttl"]', form).value;

    if (!text.trim() && !file) return setError(errorBox, msg('empty'));
    if (file && file.size > Number(form.dataset.maxFileSize)) return setError(errorBox, msg('file-too-large'));
    if (protect && !password) return setError(errorBox, msg('password-empty'));

    busy(true);
    try {
      const content = { text, file: null };
      if (file) content.file = { name: file.name, type: file.type, data: new Uint8Array(await file.arrayBuffer()) };
      last = { content, password, ttl };
      showManage(await createLink(last));
    } catch (e) {
      let error = e.serverMessage;
      if (e.code === 'network') error = msg('network');
      else if (!error) error = e instanceof EOCryptoError || e instanceof TypeError ? msg('crypto') : e.message;
      setError(errorBox, error);
    } finally {
      busy(false);
    }
  });
}

// /m/<id>#<token>.<expires>. Opened directly, this page does not know the
// recipient link; it can still show the expiry and destroy the secret.
function initManagePage(container) {
  const m = /^#([A-Za-z0-9_-]{43})\.(\d{1,12})$/.exec(location.hash);
  new ManageView(container).set({
    id: location.pathname.split('/').pop(),
    token: m ? m[1] : '',
    expires: m ? Number(m[2]) : 0,
    link: null
  });
}

// /s/<id>#<key>: recipient
function initRecipient(root) {
  const id = location.pathname.split('/').pop();
  const link = parseFragment(location.hash);
  const msg = (name) => root.getAttribute('data-msg-' + name);

  function view(name) {
    showView(root, name);
    root.classList.toggle('recipient--center', name !== 'revealed');
    const h1 = $(`[data-view="${name}"] h1`, root);
    if (h1) announce(h1.textContent);
  }

  function fail(text) {
    $('[data-error-text]', root).textContent = text;
    view('error');
  }

  if (!link) return fail(msg('bad-link'));
  const needsPassword = link.version === 2 ? link.hasPassword : link.fragment.length === 11;
  view(needsPassword ? 'password' : 'intro');

  // Derives the server check hash and a decrypt function for v2 or v1 links
  async function prepare(password) {
    if (link.version === 2) {
      const keys = await deriveKeys(link.secret, password);
      return {
        passHash: keys.passHash ? toBase64(keys.passHash) : '',
        decrypt: (res) => decryptSecret(fromBase64(res.data), keys)
      };
    }
    const CryptoJS = await loadCryptoJS();
    const old = parseLegacyFragment(CryptoJS, link.fragment);
    if (!old) throw new APIError('bad_link', 0);
    return {
      passHash: old.hasPassword ? legacyPassHash(CryptoJS, old, password) : '',
      decrypt: async (res) => legacyDecrypt(CryptoJS, res.data, old, res.attach, password)
    };
  }

  function showSecret(secret) {
    const box = $('#secret-value', root);
    box.textContent = secret.text;
    box.hidden = !secret.text;
    box.nextElementSibling.hidden = !secret.text; // copy button
    const card = $('[data-file-card]', root);
    card.hidden = !secret.file;
    if (secret.file) {
      $('[data-file-name]', card).textContent = secret.file.name;
      $('[data-file-size]', card).textContent = formatSize(secret.file.size);
      const url = URL.createObjectURL(new Blob([secret.file.data], { type: secret.file.type || 'application/octet-stream' }));
      $('[data-file-download]', card).onclick = () => {
        const a = document.createElement('a');
        a.href = url;
        a.download = secret.file.name || 'download';
        document.body.append(a);
        a.click();
        a.remove();
      };
    }
    // The key has done its job: drop it from the address bar and history
    history.replaceState(null, '', location.pathname);
    view('revealed');
  }

  function showUnlockError(text) {
    const input = $('#unlock-password', root);
    const box = $('[data-unlock-error]', root);
    $('[data-unlock-error-text]', box).textContent = text;
    box.hidden = false;
    input.setAttribute('aria-invalid', 'true');
    input.setAttribute('aria-describedby', 'unlock-error unlock-hint');
    input.select();
  }

  async function reveal(password, button) {
    const label = $('span', button);
    const idle = label.textContent;
    button.disabled = true;
    label.textContent = msg('revealing');
    try {
      let prepared;
      try {
        prepared = await prepare(password);
      } catch (e) {
        return fail(e.code === 'bad_link' ? msg('bad-link') : msg('decrypt'));
      }
      const res = await api('/api/secrets/' + id + '/reveal', { passHash: prepared.passHash });
      let secret;
      try {
        secret = await prepared.decrypt(res);
      } catch (e) {
        return fail(msg('decrypt'));
      }
      showSecret(secret);
    } catch (e) {
      if (e.code === 'password_required') return view('password');
      if (e.code === 'wrong_password' || (e.code === 'rate_limited' && password)) return showUnlockError(e.serverMessage);
      if (e.status === 404) return view('gone');
      if (e.code === 'network') return fail(msg('network'));
      if (e.code === 'rate_limited') return fail(msg('rate-limit'));
      fail(e.serverMessage || msg('network'));
    } finally {
      button.disabled = false;
      label.textContent = idle;
    }
  }

  $('[data-reveal]', root).addEventListener('click', (event) => reveal('', event.currentTarget));
  $('[data-unlock]', root).addEventListener('submit', (event) => {
    event.preventDefault();
    const input = $('#unlock-password', root);
    if (!input.value) {
      showUnlockError(msg('password-empty'));
      return;
    }
    reveal(input.value, $('button[type="submit"]', event.currentTarget));
  });
}

/* ---------- start ---------- */

const widgets = {
  '[data-accordion]': initAccordion,
  '[data-toggle-panel]': initTogglePanel,
  '[data-select]': initSelect,
  '[data-lang]': initLanguageMenu,
  '[data-lang-choice]': initLanguageChoice,
  '[data-lang-banner]': initLanguageBanner,
  '[data-theme-switch]': initThemeSwitch,
  '[data-dropzone]': initDropzone,
  '[data-generate-phrase]': initPhraseButton,
  '[data-copy]': initCopyButton,
  'dialog': initDialog,
  '#generator-dialog': initGeneratorDialog,
  '[data-generator-page]': initGeneratorPage,
  '[data-secret-form]': (form) => {
    prefillForm(form);
    initForm(form);
  },
  '[data-recipient]': initRecipient,
  '[data-manage-page]': initManagePage
};

if (typeof document !== 'undefined') {
  for (const [selector, init] of Object.entries(widgets)) $$(selector).forEach(init);
}
