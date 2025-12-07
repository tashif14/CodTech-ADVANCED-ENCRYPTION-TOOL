#!/usr/bin/env python3
"""
aes_encryptor.py

Advanced Encryption Tool (AES-256-GCM) with password-based key derivation.

Features:
- AES-256 in GCM mode (authenticated encryption)
- PBKDF2-HMAC-SHA256 key derivation from password with random salt
- Per-file random nonce (IV)
- CLI: encrypt / decrypt / genkey
- Secure defaults: 32-byte key, 16-byte salt, 12-byte nonce, 200000 PBKDF2 iterations
- Simple file format: MAGIC(4) | VERSION(1) | salt_len(1) | salt | nonce_len(1) | nonce | ciphertext...
  (AESGCM ciphertext contains the authentication tag)
- Note: This implementation reads the entire file into memory before encryption/decryption.
  For very large files, consider implementing streaming encryption (e.g., AES-CTR + HMAC).
"""

import argparse
import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# ====== Configuration / Parameters (secure defaults) ======
SALT_SIZE = 16             # bytes
NONCE_SIZE = 12            # recommended for AES-GCM
KEY_SIZE = 32              # 32 bytes = 256 bits for AES-256
PBKDF2_ITERATIONS = 200_000
MAGIC = b'AEG1'            # Magic bytes to identify our file format
VERSION = b'\x01'          # version 1

# ====== Helpers ======
def derive_key_from_password(password: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS, length: int = KEY_SIZE) -> bytes:
    """
    Derive a symmetric key from a password using PBKDF2-HMAC-SHA256.
    - password: bytes (UTF-8)
    - salt: random bytes
    - iterations: PBKDF2 iteration count
    - length: desired key length in bytes
    """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                     iterations=iterations, backend=default_backend())
    return kdf.derive(password)


def encrypt_file(input_path: str, output_path: str, password: bytes = None, key: bytes = None):
    """
    Encrypt input_path and write to output_path.
    Provide either a password (bytes) or a raw key (bytes). If both provided, key takes precedence.
    """
    # Read plaintext
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Prepare salt and key
    if key is None:
        # Use password-based key derivation
        if password is None:
            raise ValueError("Either password or key must be provided")
        salt = os.urandom(SALT_SIZE)
        key = derive_key_from_password(password, salt)
    else:
        # If a raw key is provided, we still include an empty salt to keep header consistent
        salt = b''

    # Create AESGCM cipher and nonce
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    # Optional associated_data can include filename or metadata (protect authenticity)
    # We'll include the original filename as associated data to bind the ciphertext to the filename.
    associated_data = os.path.basename(input_path).encode('utf-8')

    # Encrypt — AESGCM returns ciphertext || tag
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    # Build file header and write: MAGIC | VERSION | salt_len| salt | nonce_len | nonce | ad_len | ad | ciphertext
    # Store lengths so parsing is robust.
    header = bytearray()
    header += MAGIC
    header += VERSION
    header += len(salt).to_bytes(1, 'big')
    header += salt
    header += len(nonce).to_bytes(1, 'big')
    header += nonce
    header += len(associated_data).to_bytes(2, 'big')   # allow up to 65535 bytes for associated data
    header += associated_data

    with open(output_path, 'wb') as out:
        out.write(bytes(header))
        out.write(ciphertext)

    print(f"[+] Encrypted '{input_path}' -> '{output_path}'")
    if salt:
        print(f"    [i] Salt (base64): {base64.b64encode(salt).decode()}")
    print(f"    [i] Nonce (base64): {base64.b64encode(nonce).decode()}")
    print(f"    [i] Associated data (filename): {associated_data.decode('utf-8', errors='ignore')}")


def decrypt_file(input_path: str, output_path: str, password: bytes = None, key: bytes = None):
    """
    Decrypt input_path and write plaintext to output_path.
    Provide either a password (bytes) or a raw key (bytes). If both provided, key takes precedence.
    """
    with open(input_path, 'rb') as f:
        data = f.read()

    # Parse header
    pos = 0
    if data[pos:pos+4] != MAGIC:
        raise ValueError("File is not in the expected encrypted format (magic mismatch)")
    pos += 4

    version = data[pos:pos+1]
    pos += 1
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    salt_len = data[pos]
    pos += 1
    salt = data[pos:pos+salt_len]
    pos += salt_len

    nonce_len = data[pos]
    pos += 1
    nonce = data[pos:pos+nonce_len]
    pos += nonce_len

    ad_len = int.from_bytes(data[pos:pos+2], 'big')
    pos += 2
    associated_data = data[pos:pos+ad_len]
    pos += ad_len

    ciphertext = data[pos:]

    # Derive key if needed
    if key is None:
        if password is None:
            raise ValueError("Either password or key must be provided for decryption")
        if not salt:
            raise ValueError("Encrypted data lacks salt required for password-derived keys")
        key = derive_key_from_password(password, salt)

    # Decrypt
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as e:
        raise ValueError("Decryption failed: incorrect key/password or data tampered") from e

    # Write plaintext
    with open(output_path, 'wb') as out:
        out.write(plaintext)

    print(f"[+] Decrypted '{input_path}' -> '{output_path}'")
    print(f"    [i] Associated data (filename): {associated_data.decode('utf-8', errors='ignore')}")


def generate_key_file(output_key_path: str):
    """
    Generate a random 32-byte key and save it to a file (base64-encoded).
    """
    key = os.urandom(KEY_SIZE)
    with open(output_key_path, 'wb') as f:
        f.write(base64.b64encode(key))
    # set restrictive permissions when possible (POSIX)
    try:
        os.chmod(output_key_path, 0o600)
    except Exception:
        pass
    print(f"[+] Generated key file: {output_key_path}")
    print("    Keep this file safe. Anyone with this key can decrypt files encrypted with it.")


# ====== CLI ======
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced AES-256-GCM Encryption Tool")
    sub = parser.add_subparsers(dest='cmd', required=True)

    enc = sub.add_parser('encrypt', help='Encrypt a file')
    enc.add_argument('input', help='Path to plaintext input file')
    enc.add_argument('output', help='Path for encrypted output file')
    enc.add_argument('--password', action='store_true', help='Prompt for a password (default)')
    enc.add_argument('--key-file', help='Use raw key from base64 key file instead of password')

    dec = sub.add_parser('decrypt', help='Decrypt a file')
    dec.add_argument('input', help='Path to encrypted input file')
    dec.add_argument('output', help='Path for decrypted output file')
    dec.add_argument('--password', action='store_true', help='Prompt for a password (default)')
    dec.add_argument('--key-file', help='Use raw key from base64 key file instead of password')

    gk = sub.add_parser('genkey', help='Generate a random AES-256 key and save to file')
    gk.add_argument('key_out', help='Path to write base64-encoded key')

    return parser.parse_args()


def load_key_from_file(key_file_path: str) -> bytes:
    """
    Load a base64-encoded key from file and return raw bytes.
    """
    with open(key_file_path, 'rb') as f:
        b64 = f.read().strip()
    return base64.b64decode(b64)


def main():
    args = parse_args()

    try:
        if args.cmd == 'genkey':
            generate_key_file(args.key_out)
            return

        if args.cmd == 'encrypt':
            # Determine key source
            if args.key_file:
                key = load_key_from_file(args.key_file)
                encrypt_file(args.input, args.output, key=key)
            else:
                # Prompt for password securely (no echo)
                pwd = getpass.getpass("Enter encryption password: ").encode('utf-8')
                pwd_confirm = getpass.getpass("Confirm password: ").encode('utf-8')
                if not constant_time.bytes_eq(pwd, pwd_confirm):
                    print("[!] Passwords do not match. Aborting.")
                    return
                encrypt_file(args.input, args.output, password=pwd)

        elif args.cmd == 'decrypt':
            if args.key_file:
                key = load_key_from_file(args.key_file)
                decrypt_file(args.input, args.output, key=key)
            else:
                pwd = getpass.getpass("Enter decryption password: ").encode('utf-8')
                decrypt_file(args.input, args.output, password=pwd)

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == '__main__':
    main()
