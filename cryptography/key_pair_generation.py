
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_private_key_bytes(password, private_key=None):
    if private_key is None:
        private_key = generate_private_key()
    pem = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    return pem

def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def generate_public_key_bytes(public_key=None):
    if public_key is None:
        public_key = generate_public_key(private_key)
    pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def generate_rsa_pair():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    return generate_private_key_bytes(private_key), generate_public_key_bytes(public_key)

password = 'mypassword'

k, k_pub = generate_rsa_pair()

private_key_file = open('private_key', 'wb')
private_key_file.write(k)
private_key_file.close()

public_key_file = open('public_key', 'wb')
public_key_file.write(k_pub)
public_key_file.close()
