import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

def load_or_generate_key():
    """Load the encryption key or generate one if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

KEY = load_or_generate_key()
fernet = Fernet(KEY)

def encrypt_file(file_path):
    """Encrypts a file in place."""
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            
        encrypted_data = fernet.encrypt(file_data)
        
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Encryption error: {e}")
        return False

def decrypt_file(file_path, output_path=None):
    """Decrypts a file. If output_path is provided, writes decrypted data there,
    otherwise returns the decrypted data as bytes."""
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
            
        decrypted_data = fernet.decrypt(encrypted_data)
        
        if output_path:
            with open(output_path, "wb") as file:
                file.write(decrypted_data)
            return True
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        return None
