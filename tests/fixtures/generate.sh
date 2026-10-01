#!/bin/sh
# Regenerate root.pem, chain.pem and identity.p12 for the leaf key in key.pem.
# The certificates are valid from now on, and the CA keys are temporary and
# discarded. The fixtures are replaced only once all of them were generated.
# Update the dates in README.md afterwards.
set -eu
cd "$(dirname "$0")"

# macOS rejects TLS server certificates valid for more than 825 days.
leaf_days=825
ca_days=36500

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/ext.cnf" <<'CNF'
[root]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/root.key"
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/intermediate.key"

openssl req -new -key "$work/root.key" -subj "/CN=tcp-stream test root" -out "$work/root.csr"
openssl x509 -req -in "$work/root.csr" -key "$work/root.key" -sha256 -days "$ca_days" \
    -extfile "$work/ext.cnf" -extensions root -out "$work/root.pem"

openssl req -new -key "$work/intermediate.key" -subj "/CN=tcp-stream test intermediate" \
    -out "$work/intermediate.csr"
openssl x509 -req -in "$work/intermediate.csr" -CA "$work/root.pem" -CAkey "$work/root.key" -sha256 \
    -days "$ca_days" \
    -extfile "$work/ext.cnf" -extensions intermediate -out "$work/intermediate.pem"

openssl req -new -key key.pem -subj "/CN=localhost" -out "$work/leaf.csr"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/intermediate.pem" -CAkey "$work/intermediate.key" \
    -sha256 -days "$leaf_days" \
    -extfile "$work/ext.cnf" -extensions leaf -out "$work/leaf.pem"

cat "$work/leaf.pem" "$work/intermediate.pem" "$work/root.pem" > "$work/chain.pem"

# Legacy PKCS#12 encryption keeps the bundle readable by every native-tls platform,
# without OpenSSL's legacy provider.
cat "$work/intermediate.pem" "$work/root.pem" > "$work/ca.pem"
openssl pkcs12 -export -inkey key.pem -in "$work/leaf.pem" -certfile "$work/ca.pem" \
    -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
    -passout "pass:test password" -out "$work/identity.p12"

mv "$work/root.pem" "$work/chain.pem" "$work/identity.p12" .
