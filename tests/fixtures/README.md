# Test fixtures

## `test_api_key.pkcs8.der.b64`

A throwaway 2048-bit RSA key generated solely to produce deterministic OCI
request-signing vectors. It is not, and never was, associated with any Oracle
Cloud tenancy, and nothing in this repository or its CI uses it to reach a real
OCI endpoint.

It is stored as base64-encoded PKCS#8 DER rather than PEM so that repository
secret scanning is not triggered by a key that is deliberately public. Tests
re-encode it to PEM in a temporary directory when they need a key file on disk.

Expected values derived from this key, used by the signer tests:

- fingerprint: `8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c`
- the signature vectors in `src/auth/signer.rs`, which were produced
  independently with `openssl dgst -sha256 -sign` rather than by this crate.
