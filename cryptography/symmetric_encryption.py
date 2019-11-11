import os

import getpass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

backend = default_backend()

def derive_key(password):
    # if algo == "3DES":
    #     ks = 8
    # elif algo == "AES-128"
    #     ks = 16
    # elif algo == "ChaCha20"
    #     ks = 16

    salt = os.urandom(16)
    print("Salt:", salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    key = kdf.derive(password.encode("UTF-8"))
    print("Key:", key)

    return salt, key
    
def verify_key(password, salt, key):
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )

    if kdf.verify(password.encode("UTF-8"), key) is None:
        print("Password same: True")

def sym_encrypt(key, algo, text):
    if algo == "3DES":
        algorithm = algorithms.TripleDES(key)
    elif algo == "AES-128":
        algorithm = algorithms.AES(key)
    elif algo == "ChaCha20":
        algorithm = algorithms.ChaCha20(key)
    else:
        raise(Exception("Algo not found"))

    bs = int(algorithm.block_size / 8)
    print("Block size:", bs)
    missing_bytes = bs - (len(text) % bs)
    if missing_bytes == 0:
        missing_bytes = 16

    print("Padding size:", missing_bytes)

    padding = bytes([missing_bytes] * missing_bytes)
    text += padding

    cipher = Cipher(algorithm, modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    cryptogram = encryptor.update(text) + encryptor.finalize()
    print("Cryptogram:", cryptogram)

    return cryptogram

def sym_decrypt(key, algo, cryptogram):
    if algo == "3DES":
        algorithm = algorithms.TripleDES(key)
    elif algo == "AES-128":
        algorithm = algorithms.AES(key)
    elif algo == "ChaCha20":
        algorithm = algorithms.ChaCha20(key)
    else:
        raise(Exception("Algo not found"))
    
    cipher = Cipher(algorithm, modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    text = decryptor.update(cryptogram) + decryptor.finalize()

    padding_size = text[-1]
    if padding_size >= len(text):
        raise(Exception("Invalid padding. Larger than text"))
    elif padding_size > algorithm.block_size / 8:
        raise(Exception("Invalid padding. Larger than block size"))

    ntext = text[:-padding_size]
    print("Decrypted text:", ntext)

    return ntext


password = getpass.getpass("Password: ")
salt, key = derive_key(password)
verify_key(password, salt, key)

print()

text = input("Text: ")
ct = sym_encrypt(key, "AES-128", text.encode("UTF-8"))
sym_decrypt(key, "AES-128", ct)
