from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os


def aes_encrypt_text(text: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + encrypted_data).hex()


def aes_decrypt_text(encrypted_hex: str, key: bytes) -> str:
    encrypted_data = bytes.fromhex(encrypted_hex)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()


from cryptography.hazmat.primitives import serialization

def rsa_encrypt_text(text: str, public_key_bytes: bytes) -> str:
    """
    Шифрование текста с использованием RSA публичного ключа.
    """
    # Загружаем публичный ключ из байтов в объект
    public_key = serialization.load_pem_public_key(
        public_key_bytes,  # Уже в формате bytes
        backend=default_backend()
    )
    print(public_key)
    # Шифруем текст
    encrypted_data = public_key.encrypt(
        text.encode('utf-8'),  # Преобразуем текст в байты
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(encrypted_data)
    return encrypted_data.hex()  # Возвращаем шифрованные данные в виде HEX строки





def rsa_decrypt_text(encrypted_hex: str, private_key_bytes: bytes) -> str:
    """
    Расшифровка текста с использованием RSA приватного ключа.
    """
    # Загружаем приватный ключ из байтов в объект
    private_key = serialization.load_pem_private_key(
        private_key_bytes,  # Уже в формате bytes
        password=None,      # Без пароля
        backend=default_backend()
    )

    # Декодируем шифрованный текст из HEX в байты
    encrypted_data = bytes.fromhex(encrypted_hex)

    # Расшифровываем текст
    decrypted_data = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')  # Возвращаем расшифрованный текст в строке


