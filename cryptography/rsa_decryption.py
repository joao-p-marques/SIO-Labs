
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def decrypt(text, key_text, password):
    key = load_pem_private_key(key_text, password=password, backend=default_backend())
    if isinstance(key, rsa.RSAPrivateKey):
        return key.decrypt(text, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

key_file_name = 'private_key'
f = open(key_file_name, 'rb')
private_key = f.read()
f.close()

password = b'mypassword'

file_name_to_decrypt = 'encrypted_test.txt'
f = open(file_name_to_decrypt, 'rb')
text = f.read()
f.close()

output_file_name = 'decrypted_test.txt'
f = open(output_file_name, 'wb')

decrypted_text = decrypt(text, private_key, password)

f.write(decrypted_text)
f.close()
