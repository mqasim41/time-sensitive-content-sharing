# --------------------
# Utility Functions
# --------------------
import hashlib
import secrets
import string
from cryptography.fernet import Fernet


def generate_otp(length=6):
    """Generate a random 6-digit OTP using secrets (secure)."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def create_sha256_hash(message):
    """Create a SHA-256 hash for a given message (string)."""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def encrypt_data(plaintext):
    """Encrypt plaintext using Fernet (symmetric encryption)."""
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted = f.encrypt(plaintext.encode('utf-8'))
    return key, encrypted

def decrypt_data(key, encrypted_data):
    """Attempt to decrypt data and handle errors."""
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_data).decode('utf-8')
    except Exception:
        return None