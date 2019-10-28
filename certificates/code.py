
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from os import scandir
import datetime

def load_certificate(file_name): 
    with open(file_name, 'rb') as f:
        pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    print(f"Loaded {cert}")
    print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"Signature {cert.signature}")

for entry in scandir('/etc/ssl/certs'):
    print(entry.name)
    if not 'trust' in entry.name and 'crt' in entry.name:
        load_certificate(entry)
