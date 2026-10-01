The test identity is `localhost`, signed by an intermediate CA and a root CA.
`chain.pem` contains the leaf, intermediate, and root in that order. `root.pem`
is the trust anchor and `key.pem` is the leaf's test-only PKCS#8 private key.
The certificates allow server and client TLS authentication, so the tests use
local connections without the system trust store. The root and intermediate are
valid until 2126, but the leaf only from 2026-11-01 to 2029-02-03: macOS rejects
TLS server certificates valid for more than 825 days. Before the leaf expires,
run `tests/fixtures/generate.sh` to issue a new root, intermediate, leaf and
`identity.p12`, valid from that day, and update these dates. It keeps
`key.pem`, so the encrypted copies of that key stay valid.

`identity.p12` contains the same leaf key and certificate chain with the password
`test password`. Native TLS tests use PKCS#12 because that format is supported
on all native-tls platforms, including iOS. Its legacy encryption is solely for
test fixture compatibility.

`legacy-encrypted-key.pem` contains the same test-only PKCS#8 private key with
legacy PEM encryption: the `PRIVATE KEY` label, `Proc-Type` / `DEK-Info` headers,
AES-128-CBC, and an IV of sixteen `0x07` bytes. Its password is `fixture password`.
It exercises Native TLS's password-prompt guard; it must be rejected before
calling the platform importer.

`encrypted-key.pem` encrypts the same test-only key as PKCS#8
`EncryptedPrivateKeyInfo`, using PBES2 / AES-256-CBC and the password
`fixture password`. It was generated with `openssl pkcs8 -topk8 -v2 aes-256-cbc`.
Tests also relabel it as `PRIVATE KEY` to exercise content validation and append
it to valid PEM inputs to verify that extra objects never reach the importer.
