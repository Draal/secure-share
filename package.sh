#!/bin/sh
# Builds the server binary and packs it with translations and static files.
# In production nginx serves public/, so CSS and JS are minified here and
# text assets get .gz copies for gzip_static. Run the server with
# USE_MINIFIED=1 USE_HASHING=1.
# Usage: ./package.sh encryptone

set -e

go test ./...
GOOS=linux GOARCH=amd64 go build -o $1

npm ci
bin=node_modules/.bin
assets=public/assets
find public \( -name '*.min.*' -o -name '*.gz' \) -delete
$bin/terser $assets/js/app.js --module -c -m -o $assets/js/app.min.js
$bin/terser $assets/js/eff-wordlist.js -c -m -o $assets/js/eff-wordlist.min.js
$bin/terser $assets/vendor/crypto-js.js -c -m -o $assets/vendor/crypto-js.min.js
$bin/cleancss -O1 -o $assets/css/site.min.css $assets/css/site.css
find $assets \( -name '*.js' -o -name '*.css' -o -name '*.svg' \) -exec gzip -9 -k -f {} \;

release=1
githash=`git rev-parse --short HEAD`
gitnum=`git rev-list v$release..HEAD --count`
ver=${release}.${gitnum}-${githash}
mkdir -p pkgs
rm -f pkgs/*
archive=pkgs/$1.$branch$ver.tar
tar -cf $archive $1 translation public
gzip $archive
