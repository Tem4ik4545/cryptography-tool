from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.x509 import load_pem_x509_certificate
import os


def calculate_file_hash(file_path: str) -> str:

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize().hex()


def sign_file(file_path: str, private_key: bytes) -> bytes:

    file_hash = bytes.fromhex(calculate_file_hash(file_path))

    private_key_obj = load_pem_private_key(private_key, password=None, backend=default_backend())

    signature = private_key_obj.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_file_signature(file_path: str, signature: bytes, certificate: bytes) -> bool:

    file_hash = bytes.fromhex(calculate_file_hash(file_path))

    cert = load_pem_x509_certificate(certificate, backend=default_backend())
    public_key = cert.public_key()

    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

