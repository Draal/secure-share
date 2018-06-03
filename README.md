# Encrypt.One

The main goal of `https://encrypt.one` is to make sensitive information sharing
safe and secure. it was achieved by using full client-side encryption model.

Created by [Final Level](https://final-level.com/).

## Advantages

- Before information is sent to the server it is encrypted (by AES 256) in your browser with a randomly generated key or your passphrase by [crypto-js](https://github.com/brix/crypto-js).

- The server receives your information encrypted and cannot decrypt it, because the link or the passphrase never send to the server.

- After you send the link and the passphrase via any kind of communication, the recipient browser decrypts it and the information is deleted from the server.


## Prerequisites

- [Go 1.7](http://golang.org/doc/install)
- [npm](https://www.npmjs.com/)

## Setup

- Ensure that `GOPATH` is set.

```sh
  npm -i
  GOOS=linux GOARCH=amd64 ./package.sh encryptone
```

## Run
- Ensure that `STORAGE_TYPE` is set to disk and storage variables (eg. `DISK_STORAGE_PATHS`) if you want to store your data permanently.
- Set `USE_HASHING=1` for assets hashing
