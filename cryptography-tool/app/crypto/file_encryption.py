from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os


def aes_encrypt_file(input_path: str, output_path: str, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, "wb") as f:
        f.write(iv + encrypted_data)


def aes_decrypt_file(input_path: str, output_path: str, key: bytes):
    with open(input_path, "rb") as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_path, "wb") as f:
        f.write(decrypted_data)


def rsa_encrypt_file(input_path: str, output_path: str, public_key: bytes):
    # Если ключ в байтах, пропускаем encode()
    if isinstance(public_key, str):
        public_key = public_key.encode()

    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted_data = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_path, "wb") as f:
        f.write(encrypted_data)



def rsa_decrypt_file(input_path: str, output_path: str, private_key: bytes):
    try:
        # Проверяем, является ли ключ строкой, и конвертируем при необходимости
        if isinstance(private_key, str):
            private_key = private_key.encode()

        private_key_obj = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

        with open(input_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = private_key_obj.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

    except Exception as e:
        raise ValueError(f"RSA Decryption Error: {str(e)}")

