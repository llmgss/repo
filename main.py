import os
import shutil
import json
import base64
import secrets
import string
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# Install dependency: pip install cryptography

# Utilities
def generate_key(passphrase: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, dklen=32))

def random_string(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

# Encryption and Decryption
def encrypt_file(filepath, fernet):
    with open(filepath, 'rb') as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(filepath, 'wb') as file:
        file.write(encrypted)

def decrypt_file(filepath, fernet):
    with open(filepath, 'rb') as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filepath, 'wb') as file:
        file.write(decrypted)

# Core functions
def encrypt_directory(root_folder, passphrase):
    salt = secrets.token_bytes(16)
    key = generate_key(passphrase, salt)
    fernet = Fernet(key)
    mappings = {}

    encrypted_root = f'encrypted_{random_string()}'
    os.makedirs(encrypted_root, exist_ok=True)

    for dirpath, dirnames, filenames in os.walk(root_folder):
        rel_path = os.path.relpath(dirpath, root_folder)
        obfuscated_dir = random_string()
        mappings[rel_path] = obfuscated_dir

        target_dir = os.path.join(encrypted_root, obfuscated_dir)
        os.makedirs(target_dir, exist_ok=True)

        for filename in filenames:
            if filename.lower().endswith(('.md', '.png')):
                obfuscated_file = random_string()
                original_file_relative = os.path.normpath(os.path.join(rel_path, filename))
                mappings[original_file_relative] = obfuscated_file

                src_file_path = os.path.join(dirpath, filename)
                dest_file_path = os.path.join(target_dir, obfuscated_file)
                shutil.copy2(src_file_path, dest_file_path)
                encrypt_file(dest_file_path, fernet)

    mapping_path = os.path.join(encrypted_root, 'structure.enc')
    with open(mapping_path, 'wb') as file:
        file.write(salt + fernet.encrypt(json.dumps(mappings).encode()))

    print(f"Encrypted folder created at '{encrypted_root}'")

def decrypt_directory(encrypted_root, output_folder, passphrase):
    mapping_path = os.path.join(encrypted_root, 'structure.enc')
    with open(mapping_path, 'rb') as file:
        salt = file.read(16)
        encrypted_mapping = file.read()

    key = generate_key(passphrase, salt)
    fernet = Fernet(key)
    mappings = json.loads(fernet.decrypt(encrypted_mapping).decode())

    reverse_dir_mappings = {v: k for k, v in mappings.items() if not os.path.splitext(k)[1]}

    for obfuscated_name in os.listdir(encrypted_root):
        if obfuscated_name == 'structure.enc':
            continue

        obfuscated_dir_path = os.path.join(encrypted_root, obfuscated_name)
        original_rel_dir = reverse_dir_mappings.get(obfuscated_name, '')

        for obfuscated_file in os.listdir(obfuscated_dir_path):
            original_rel_file = next((orig for orig, obf in mappings.items() if obf == obfuscated_file), None)
            if original_rel_file:
                dest_path = os.path.join(output_folder, original_rel_file)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                src_file_path = os.path.join(obfuscated_dir_path, obfuscated_file)
                shutil.copy2(src_file_path, dest_path)
                decrypt_file(dest_path, fernet)

    print(f"Decrypted files created at '{output_folder}'")

# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Encrypt/Decrypt directory')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('input_folder', help='Input folder path')
    parser.add_argument('output_folder', nargs='?', help='Output folder for decrypted files')

    args = parser.parse_args()

    passphrase = input('Enter passphrase: ')

    if args.action == 'encrypt':
        encrypt_directory(args.input_folder, passphrase)
    elif args.action == 'decrypt':
        if not args.output_folder:
            raise ValueError("output_folder is required for decrypt action")
        decrypt_directory(args.input_folder, args.output_folder, passphrase)

