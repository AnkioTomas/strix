"""Self-signed certificate bootstrap so the node can serve HTTPS with zero setup."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
from pathlib import Path


def _sans(extra: str) -> list[str]:
    names = {"localhost", "127.0.0.1", socket.gethostname()}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            names.add(info[4][0])
    except OSError:
        pass
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        names.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    names.update(s.strip() for s in extra.split(",") if s.strip())
    return sorted(n for n in names if ":" not in n)


def ensure_self_signed(directory: Path, extra_sans: str = "") -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_path, key_path = directory / "node.crt", directory / "node.key"
    if cert_path.is_file() and key_path.is_file():
        return str(cert_path), str(key_path)
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "strix-node")])
    alt: list[x509.GeneralName] = []
    for san in _sans(extra_sans):
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(san)))
        except ValueError:
            alt.append(x509.DNSName(san))
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)
