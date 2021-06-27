import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
 
def password_hash_generate(prov_pass, element):
    password_provided = prov_pass
    password = password_provided.encode() 
    salt = element
    salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    return(key.decode())

print("Please input desired password")
prov_pass = str(input())
print("Please input site salt")
element = str(input())
print()
print("Hashing password")
print("...")
print(password_hash_generate(prov_pass, element))
print()
print("Press Enter to close program")
input()
