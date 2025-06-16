from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

def encrypt_password(plain_password):
    key = current_app.config.get("ENCRYPTION_KEY")
    if not key:
        raise ValueError("Missing ENCRYPTION_KEY in config.")
    fernet = Fernet(key.encode())
    return fernet.encrypt(plain_password.encode())

def decrypt_password(encrypted_password):
    key = current_app.config.get("ENCRYPTION_KEY")
    if not key:
        raise ValueError("Missing ENCRYPTION_KEY in config.")
    fernet = Fernet(key.encode())
    try:
        return fernet.decrypt(encrypted_password).decode()
    except InvalidToken:
        return "Decryption failed"
