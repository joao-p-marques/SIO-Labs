
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# key = load_pem_private_key(pem_data, password=None, backend=default_backend())

# if isinstance(key, rsa.RSAPrivateKey):
#     signature = sign_with_rsa_key(key, message)
# elif isinstance(key, dsa.DSAPrivateKey):
#     signature = sign_with_dsa_key(key, message)
# else:
#     raise TypeError

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

print(private_key)
