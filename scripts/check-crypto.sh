#!/usr/bin/env bash
#
# Check which parts of the Go standard library AAMM-NG uses for security.
#
# AAMM-NG has no TLS and no public-key cryptography. The only cryptography
# it uses is password hashing for the multi-user portal: PBKDF2-HMAC-SHA256
# (crypto/pbkdf2 and crypto/sha256) and a constant-time compare
# (crypto/subtle).
#
# This script fails if:
#   1. our own code imports any other crypto package, or net/http, or
#      golang.org/x/crypto; or
#   2. a command links TLS, X.509, public-key crypto, a cipher package, a
#      legacy hash, crypto/rand or net/http.
#
# Note: any use of the Go standard library hashing links the Go FIPS 140
# module (crypto/internal/fips140/...). That module contains AES and other
# code that AAMM-NG never calls. This cannot be avoided with the standard
# library, and this script does not forbid it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

allowed=" crypto/pbkdf2 crypto/sha256 crypto/subtle "
forbidden_deps='^(crypto/(tls|x509|rsa|ecdsa|ecdh|ed25519|elliptic|dsa|des|rc4|aes|rand|md5|sha1)|net/http|vendor/golang.org/x/crypto|golang.org/x/crypto)(/|$)'

status=0

echo "=== direct imports in AAMM-NG packages ==="

while read -r package imports; do
    for import in $imports; do
        case "$import" in
            crypto | crypto/* | golang.org/x/crypto | golang.org/x/crypto/* | net/http | net/http/*)
                if [[ "$allowed" != *" $import "* ]]; then
                    echo "::error::$package imports $import, which is not allowed"
                    status=1
                fi
                ;;
        esac
    done
done < <(go list -f '{{.ImportPath}} {{join .Imports " "}}' ./...)

echo "=== dependencies of the commands ==="

for command in aamm-ng aamm-ng-web; do
    if go list -deps "./cmd/${command}" | grep -E "$forbidden_deps"; then
        echo "::error::${command} links TLS, public-key crypto, a cipher package, a legacy hash, crypto/rand or net/http" >&2
        status=1
    fi
done

if [[ "$status" -eq 0 ]]; then
    echo "crypto check passed."
fi

exit "$status"
