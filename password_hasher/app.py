import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from frontend.lib import password_handler

def main():
    print("Please input desired password")
    prov_pass = str(input())
    print("Please input site salt")
    element = str(input())
    print()
    print("Hashing password")
    print("...")
    print(password_handler.password_hash_generate(prov_pass, element))
    print()
    print("Press Enter to close program")
    input()

if __name__ == '__main__':
    main()