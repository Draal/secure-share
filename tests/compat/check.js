// Compatibility check helper.
//   node check.js store <old server URL>  > links.json   stores secrets through the old /p
//   node check.js open  <new server URL>  < links.json   opens them through the new API
import { oldEncrypt, oldEncryptFile, CryptoJS } from '../helpers/old-share.js';
import { parseLegacyFragment, legacyPassHash, legacyDecrypt } from '../../public/assets/js/app.js';

const [mode, base] = process.argv.slice(2);

function fail(msg) {
  console.error('FAIL: ' + msg);
  process.exit(1);
}

async function store() {
  const fileBytes = new TextEncoder().encode('DB_PASSWORD=from-the-old-site\n');
  const cases = [
    { name: 'text', text: 'Старая ссылка: Wi-Fi Home_5G / N7#qkV2m!Lp9xW4z', make: () => oldEncrypt('Старая ссылка: Wi-Fi Home_5G / N7#qkV2m!Lp9xW4z') },
    { name: 'password', text: 'admin / hunter2', password: 'correct horse', make: () => oldEncrypt('admin / hunter2', 'correct horse') },
    { name: 'file', text: 'see the attachment', file: '.env', make: () => oldEncryptFile('see the attachment', '.env', 'text/plain', fileBytes, '') }
  ];
  const out = [];
  for (const c of cases) {
    const { secret, fragment } = c.make();
    // Exactly what share.js posted with jQuery: a form with data, passHash, att.
    const form = new URLSearchParams();
    for (const [k, v] of Object.entries(secret)) form.append(k, String(v));
    const res = await fetch(base + '/p', { method: 'POST', body: form });
    if (!res.ok) fail(c.name + ': old /p answered ' + res.status);
    const { id } = await res.json();
    out.push({ name: c.name, id, fragment, attach: !!secret.att, text: c.text, password: c.password || '', file: c.file || '' });
  }
  console.log(JSON.stringify(out));
}

async function reveal(id, passHash) {
  const res = await fetch(base + '/api/secrets/' + id + '/reveal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passHash })
  });
  return { status: res.status, body: await res.json() };
}

async function open() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const links = JSON.parse(input);
  for (const l of links) {
    const page = await fetch(base + '/s/' + l.id);
    if (page.status !== 200) fail(l.name + ': recipient page answered ' + page.status);
    const link = parseLegacyFragment(CryptoJS, l.fragment);
    if (!link || link.hasPassword !== !!l.password) fail(l.name + ': fragment ' + l.fragment + ' is not recognized');
    if (l.password) {
      const wrong = await reveal(l.id, legacyPassHash(CryptoJS, link, 'wrong'));
      if (wrong.status !== 403) fail(l.name + ': wrong password answered ' + wrong.status);
    }
    const res = await reveal(l.id, l.password ? legacyPassHash(CryptoJS, link, l.password) : '');
    if (res.status !== 200) fail(l.name + ': reveal answered ' + res.status + ' ' + JSON.stringify(res.body));
    const secret = legacyDecrypt(CryptoJS, res.body.data, link, res.body.attach, l.password);
    if (secret.text !== l.text) fail(l.name + ': text ' + JSON.stringify(secret.text));
    if (l.file && (!secret.file || secret.file.name !== l.file)) fail(l.name + ': file is missing');
    const again = await reveal(l.id, '');
    if (again.status !== 404) fail(l.name + ': second reveal answered ' + again.status);
    console.log('ok  ' + l.name + ': opened by the new server, then gone');
  }
}

if (mode === 'store') await store();
else if (mode === 'open') await open();
else fail('usage: check.js store|open <base URL>');
