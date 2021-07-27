import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = b"IAMRATULPASSWORD"
salt = os.urandom(16)

# Encryption Part
# kdf generation
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length=32,
    salt=salt,
    iterations=100000
)

# generate key from password
key = base64.urlsafe_b64encode(kdf.derive(password))

with open("key.key", "wb") as key_file:
    key_file.write(key)

with open('./book.epub', "rb") as file:
    # read all file data
    book = file.read()

F = Fernet(key)

encryptedData = F.encrypt(book)

# write the encrypted file
with open('encrypted.epub', "wb") as file:
    file.write(encryptedData)

# data = F.decrypt(encryptedData)

# Decrypt part
with open('encrypted.epub', "rb") as file:
    # read the encrypted data
    encrypted_data = file.read()

# decrypt data
decrypted_data = F.decrypt(encrypted_data)

# write the original file
with open('decrypted.epub', "wb") as file:
    file.write(decrypted_data)


