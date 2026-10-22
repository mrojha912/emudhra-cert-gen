#!/usr/bin/env python3
"""List *crt.pem files, select one, and check it matches a private key derived from scalar d."""

import argparse
import getpass
import hashlib
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LEAF_VALIDITY_DAYS = 365
MAX_ATTEMPTS = 256
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def get_private_key(d_value: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(d_value, ec.SECP384R1())


def public_key_hash(public_key) -> str:
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def read_scalar() -> int:
    raw = 1
    return raw


def match_private_key(cert: x509.Certificate) -> ec.EllipticCurvePrivateKey | None:
    cert_hash = public_key_hash(cert.public_key())
    d_value = read_scalar()
    if d_value is None:
        return None
    print(f"\nCertificate public key SHA-256: {cert_hash}")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            private_key = get_private_key(d_value)
        except ValueError as e:
            print(f"Attempt {attempt}: invalid scalar for secp384r1: {e}", file=sys.stderr)
        else:
            key_hash = public_key_hash(private_key.public_key())
            print(f"Attempt {attempt}: private key SHA-256: {key_hash}")
            if cert_hash == key_hash:
                print("\nRESULT: MATCH - private key corresponds to the certificate.")
                return private_key
        d_value += 1
    print(f"\nRESULT: NOT MATCHED - no matching private key after {MAX_ATTEMPTS} attempts.")
    return None


def read_domain() -> str | None:
    while True:
        try:
            domain = input("\nEnter domain for TLS issuance (e.g. example.com or *.example.com), 'q' to quit: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        domain = domain.strip().lower().rstrip(".")
        if domain == "q":
            return None
        if len(domain) <= 253 and DOMAIN_RE.match(domain):
            return domain
        print("Invalid domain name.")


def generate_csr(domain: str) -> tuple[ec.EllipticCurvePrivateKey, x509.CertificateSigningRequest]:
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(leaf_key, hashes.SHA384())
    )
    return leaf_key, csr


def sign_csr(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    now = datetime.now(timezone.utc)
    not_after = min(now + timedelta(days=LEAF_VALIDITY_DAYS), issuer_cert.not_valid_after_utc)
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(san, critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
        .sign(issuer_key, hashes.SHA384())
    )
    cert.verify_directly_issued_by(issuer_cert)
    return cert


def write_outputs(
    out_dir: Path,
    leaf_key: ec.EllipticCurvePrivateKey,
    csr: x509.CertificateSigningRequest,
    leaf_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    root_cert: x509.Certificate | None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    files = {
        "key": (out_dir / "key.pem", leaf_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        "csr": (out_dir / "csr.pem", csr.public_bytes(pem)),
        "cert": (out_dir / "crt.pem", leaf_cert.public_bytes(pem)),
        "chain": (out_dir / "fullchain.pem", b"".join(
            c.public_bytes(pem) for c in (leaf_cert, issuer_cert, root_cert) if c is not None)),
    }
    existing = [str(p) for p, _ in files.values() if p.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite: {', '.join(existing)}")
    for name, (path, data) in files.items():
        mode = 0o600 if name == "key" else 0o644
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return {name: path for name, (path, _) in files.items()}


def find_crt_pem_files(folder: Path, recursive: bool) -> list[Path]:
    pattern = "**/*crt.pem" if recursive else "*crt.pem"
    return sorted(p for p in folder.glob(pattern) if p.is_file())


def choose_file(files: list[Path]) -> Path | None:
    while True:
        try:
            choice = input(f"\nSelect a file [1-{len(files)}] or 'q' to quit: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if choice.lower() == "q":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print(f"Invalid choice. Enter a number between 1 and {len(files)}.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Display list of available crt.pem files in a folder.")
    parser.add_argument("folder", nargs="?", default=".", help="Folder to scan (default: current directory)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Include subfolders")
    parser.add_argument("-o", "--out-dir", default="issued", help="Output folder for issued certs (default: ./issued)")
    parser.add_argument("--root", help="Root CA certificate (default: root.pem in the scanned folder)")
    args = parser.parse_args()

    folder = Path(args.folder).expanduser().resolve()
    if not folder.is_dir():
        print(f"Error: '{folder}' is not a valid directory.", file=sys.stderr)
        return 1

    files = find_crt_pem_files(folder, args.recursive)
    if not files:
        print(f"No crt.pem files found in {folder}")
        return 0

    print(f"crt.pem files in {folder}:\n")
    print(f"{'No.':<5}{'File':<60}{'Size (bytes)':>14}  Modified")
    print("-" * 100)
    for i, f in enumerate(files, 1):
        stat = f.stat()
        modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{i:<5}{str(f.relative_to(folder)):<60}{stat.st_size:>14}  {modified}")
    print(f"\nTotal: {len(files)} file(s)")

    selected = choose_file(files)
    if selected is None:
        print("No file selected.")
        return 1
    print(f"\nSelected: {selected}")

    try:
        cert = x509.load_pem_x509_certificate(selected.read_bytes())
    except ValueError as e:
        print(f"Error: could not load certificate: {e}", file=sys.stderr)
        return 1
    print(f"Subject: {cert.subject.rfc4514_string()}")

    private_key = match_private_key(cert)
    if private_key is None:
        print("Exiting: no matching private key.")
        return 2

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        print("Error: selected certificate is not a CA certificate; cannot issue.", file=sys.stderr)
        return 1

    root_cert = None
    try:
        include_root = input("\nInclude root certificate in fullchain.pem? [y/N]: ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return 1
    if include_root:
        root_path = Path(args.root).expanduser().resolve() if args.root else folder / "root.pem"
        try:
            root_cert = x509.load_pem_x509_certificate(root_path.read_bytes())
            cert.verify_directly_issued_by(root_cert)
        except OSError as e:
            print(f"Error: could not read root certificate: {e}", file=sys.stderr)
            return 1
        except (ValueError, TypeError, InvalidSignature) as e:
            print(f"Error: {root_path} is not a valid issuer of the selected certificate: {e!r}", file=sys.stderr)
            return 1
        print(f"Root:    {root_cert.subject.rfc4514_string()} (verified issuer)")

    domain = read_domain()
    if domain is None:
        print("No domain entered.")
        return 1

    leaf_key, csr = generate_csr(domain)
    try:
        leaf_cert = sign_csr(csr, cert, private_key)
        out_dir = Path(args.out_dir).expanduser().resolve() / domain.replace("*", "wildcard")
        paths = write_outputs(out_dir, leaf_key, csr, leaf_cert, cert, root_cert)
    except (ValueError, FileExistsError) as e:
        print(f"Error: issuance failed: {e}", file=sys.stderr)
        return 1

    print(f"\nIssued certificate for {domain}")
    print(f"  Serial:  {leaf_cert.serial_number:x}")
    print(f"  Valid:   {leaf_cert.not_valid_before_utc} -> {leaf_cert.not_valid_after_utc}")
    for name, path in paths.items():
        print(f"  {name:<8} {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
