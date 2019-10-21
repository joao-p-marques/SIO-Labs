
import sys
import hashlib

def encrypt(hash_func_name, text):
    if hash_func_name == "MD5":
        func = hashlib.md5()
    elif hash_func_name == "SHA-256":
        func = hashlib.sha256()
    elif hash_func_name == "SHA-384":
        func = hashlib.sha384()
    elif hash_func_name == "SHA-512":
        func = hashlib.sha512()
    elif hash_func_name == "BLAKE-2":
        func = hashlib.blake2b()
    else:
        raise(Exception("Function not found"))
    
    func.update(text.encode())
    return func.hexdigest()

hash_func_name = sys.argv[1]

file_name = sys.argv[2]
f = open(file_name, 'r')
text = f.read()
f.close()

print(encrypt(hash_func_name, text))


