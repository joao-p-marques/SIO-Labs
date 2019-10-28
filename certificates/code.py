
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from os import scandir
import datetime

def load_certificate(file_name): 
    now = datetime.datetime.now()

    with open(file_name, 'rb') as f:
        pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    print(f"Loaded {cert.serial_number}")
    print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}", end="")

    if cert.not_valid_after > now:
        print(" EXPIRED", end="")

    print()

def build_issuers(chain, cert):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in roots:
        print("Chain completed")
        return True



for entry in scandir('/etc/ssl/certs'):
    # print(entry.name)
    if entry.is_dir():
        continue
    if not 'trust' in entry.name:# and 'crt' in entry.name:
        load_certificate(entry)
