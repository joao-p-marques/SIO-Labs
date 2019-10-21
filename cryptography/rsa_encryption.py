
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def encrypt(text, key_text):
    key = load_pem_public_key(key_text, backend=default_backend())
    if isinstance(key, rsa.RSAPublicKey):
        return key.encrypt(text, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

key_file_name = 'public_key'
f = open(key_file_name, 'rb')
public_key = f.read()
f.close()

file_name_to_encrypt = 'test.txt'
f = open(file_name_to_encrypt, 'rb')
text = f.read()
f.close()

output_file_name = 'encrypted_test.txt'
f = open(output_file_name, 'wb')

encrypted_text = encrypt(text, public_key)

f.write(encrypted_text)
f.close()
