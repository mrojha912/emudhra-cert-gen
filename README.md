# emudhra-cert-gen

Interactive tool that lists local CA certificates (`*crt.pem`), derives the matching
secp384r1 private key from a scalar `d`, and issues a TLS leaf certificate (CSR + cert +
full chain) signed by the selected CA.

## Contents

- [cert-gen.py](cert-gen.py) — main CLI: list CA certs, match private key, issue a leaf cert
- `EM-*-CA-*.crt.pem` — eMudhra issuing CA certificates (public certs only)
- [root.pem](root.pem) — root CA certificate used for the chain

## Requirements

- Python 3.10+
- `cryptography`

```sh
pip install cryptography
```

## Usage

```sh
python3 cert-gen.py [folder] [-r] [-o OUT_DIR] [--root ROOT_PEM]
```

| Argument | Description |
|---|---|
| `folder` | Folder to scan for `*crt.pem` files (default: current directory) |
| `-r`, `--recursive` | Also scan subfolders |
| `-o`, `--out-dir` | Output folder for issued certificates (default: `./issued`) |
| `--root` | Path to the root CA cert (default: `root.pem` in the scanned folder) |

Flow:

1. Lists all `*crt.pem` files with size and modification time.
2. Prompts to select a CA certificate.
3. Derives secp384r1 private keys from scalar `d` (starting at the value returned by
   `read_scalar()`, incrementing up to 256 attempts) and matches the public key hash
   against the selected certificate.
4. Verifies the selected cert is a CA, optionally verifies the root and includes it in
   the chain.
5. Prompts for a domain (or `*.wildcard`), generates a fresh P-384 key + CSR, and signs
   it with the CA (SHA-384, 365-day validity, `serverAuth` EKU).

### Output

Written to `<out-dir>/<domain>/` (wildcards become `wildcard.example.com`):

| File | Contents |
|---|---|
| `key.pem` | Leaf private key (PKCS#8, unencrypted, mode `0600`) |
| `csr.pem` | Certificate signing request |
| `crt.pem` | Issued leaf certificate |
| `fullchain.pem` | Leaf + issuing CA (+ root if included) |

Existing files are never overwritten; the run aborts instead.

## Exit codes

- `0` — success (or no crt.pem files found)
- `1` — usage/validation error
- `2` — no matching private key found for the selected certificate

## Warning

Private keys are derived from small sequential scalars for testing purposes. **Do not use
issued certificates or keys in production.**
