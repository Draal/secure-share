# Encrypt.One

[encrypt.one](https://encrypt.one) shares passwords, API keys and files with one-time links.
The secret is encrypted in the sender's browser, the server stores only ciphertext, and the
recipient opens the link once, after which the data is deleted.

Created by [Final Level](https://final-level.com/).

## How it works

- **All client code** is one ES module, `public/assets/js/app.js`: encryption, old links,
  QR code, password generator, UI widgets and the pages. The passphrase word list and
  CryptoJS are separate files loaded only when needed; `theme.js` is a few lines in <head>
  that apply the saved light or dark theme before the page is drawn.
- **Encryption (format v2)** — Web Crypto only. AES-256-GCM with a random 32-byte link
  secret that lives only in the link fragment (`#2.<key>`, or `#2p.<key>` with a password).
  Text and file are encrypted as one package, file metadata included. With a password,
  PBKDF2-SHA256 (600 000 iterations, salt derived from the link) feeds two separate HKDF
  branches: one gives the check hash the server compares, the other, together with the link
  secret, gives the key.
- **Old links** (no version prefix in the fragment) are decrypted with CryptoJS 3.1.8
  (`public/assets/vendor/crypto-js.js`), loaded only for such links. Marked `LEGACY-V1` for
  removal 8 days after the launch.
- **Server** — Go, `html/template`, the storage interface of `storage/` unchanged.
  Viewing `/s/<id>` never touches the storage: the ciphertext is handed out only by
  `POST /api/secrets/<id>/reveal`, so link preview bots cannot consume a secret.

## Pages and API

| Address | What |
|---|---|
| `/`, `/ru/`, `/uk/` | Home: create a link |
| `/password-generator/`, `/how-it-works/`, `/privacy/` (and under `/ru/`, `/uk/`) | Pages |
| `/s/<id>#<key>` | Recipient page (no language in the path, `noindex`) |
| `/m/<id>#<token>.<expires>` | Sender page: expiry and destroy (`noindex`). After creating a link the form shows this view in place and keeps the page address, so nobody copies the browser address instead of the link |
| `POST /api/secrets` | Create: `{data, passHash?, attach, ttl: 1h\|1d\|3d\|7d, lang?}` → `{id, expires, token}` |
| `POST /api/secrets/<id>/reveal` | `{passHash?, lang?}` → `{data, attach}`; the secret is deleted after delivery; the third wrong password deletes it |
| `POST /api/secrets/<id>/destroy` | `{token, lang?}`; the token is `HMAC-SHA256(MANAGE_TOKEN_SECRET, id)` |
| `/sitemap.xml`, `/robots.txt` | For search engines |

Language: English lives at `/`, Russian at `/ru/`, Ukrainian at `/uk/`. Only `/` redirects
(302 with `Vary: Accept-Language`): to the saved choice from the `lang` cookie, or, without
one, to `/ru/` or `/uk/` when `Accept-Language` starts with `ru` or `uk`. Old `?lang=` links
get a 301 to the language address.

## Run locally

Requirements: Go 1.22+, Node 20+ for the JavaScript tests and the package build.

```sh
USE_HASHING=1 SITE_URL=http://localhost:8080 go run .
```

Open http://localhost:8080/. Without `STORAGE_TYPE=disk` secrets live in memory and are
lost on restart.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN` | `:8080` | Listen address |
| `STORAGE_TYPE` | memory | `disk` to keep secrets on disk |
| `DISK_STORAGE_PATHS` | — | Storage directories for `disk`, separated by `:` |
| `MAX_FILE_SIZE` | `5242880` | Upload limit in bytes |
| `USE_HASHING` | off | Content hashes in asset URLs (`site.1a2b3c4d.css`); turn on in production |
| `USE_MINIFIED` | off | Use `*.min.*` next to an asset when it exists (made by `package.sh`) |
| `SITE_URL` | `https://encrypt.one` | **New.** Absolute URL for canonical, hreflang, sitemap and OG |
| `MANAGE_TOKEN_SECRET` | random | **New.** At least 32 bytes. Key of the sender page tokens. Without it a random key is used and `/m/` links stop working after a restart |

## Tests

```sh
go test -race ./...      # handlers, routes, languages, SEO markup, API, limits
npm test                 # encryption v2 and old-link decryption (node --test)
tests/compat/run.sh      # builds the old server, stores secrets with it, opens them with the new one
```

Manual checks before the launch (link previews, Lighthouse, headers behind the proxy, old
links): [docs/MANUAL-CHECKS.md](docs/MANUAL-CHECKS.md).

## Build a package

```sh
GOOS=linux GOARCH=amd64 ./package.sh encryptone
```

The script runs the Go tests, minifies JS and CSS (terser, clean-css) into `*.min.*` files,
adds `.gz` copies of text assets and packs the binary, `translation/` and `public/` into
`pkgs/`. Templates are compiled into the binary.

In production nginx serves `public/` itself and passes everything else to Go. Asset URLs
carry a content hash that nginx strips, the same way the Go server does locally:

```nginx
location /assets/ {
    root /path/to/public;
    rewrite "^(.+)\.[0-9a-f]+(\.[a-z]+)$" $1$2 break;
    gzip_static on;
    expires max;
}
```

## Layout

```
main.go, handler.go     server start, routing, security headers
lang.go, pages.go       languages, redirects, pages, SEO data, JSON-LD
api.go, limits.go       secrets API, rate limits, wrong password counter
static.go               local static files, robots, sitemap
templates/              layout, pages and a few shared blocks in partials/ (html/template)
translation/            go-i18n strings: en-us, ru-ru, uk-uk
public/assets/          site.css, fonts, images, js/app.js, the word list, vendor/crypto-js.js
config/                 asset URLs, languages, upload limit
storage/                memory and disk storage (unchanged)
tests/                  Node tests and the compatibility check
docs/                   design mockups, manual checks
```
