#!/usr/bin/env python3
"""
Advanced File Encryption Module

This module implements secure file encryption using ChaCha20-Poly1305 for symmetric encryption
and RSA-OAEP for key encryption. It includes digital signatures for integrity verification.

Features:
    - Hybrid encryption (ChaCha20-Poly1305 + RSA-OAEP)
    - Digital signatures using RSA-PSS
    - Metadata management
    - Multi-user support
"""

# Import required libraries
import os  # For file operations
import argparse  # For command line argument parsing
import json  # For metadata handling
from Crypto.Cipher import ChaCha20_Poly1305, PKCS1_OAEP  # For encryption
from Crypto.PublicKey import RSA  # For RSA key operations
from Crypto.Random import get_random_bytes  # For secure random generation
from Crypto.Hash import SHA256  # For hashing
from Crypto.Signature import pkcs1_15  # For digital signatures
from typing import Tuple  # For type hints

class AdvancedEncryption:
    def __init__(self, public_key_file: str, private_key_file: str, user_label: str):
        """
        Initialize encryption handler with user keys.
        Args:
            public_key_file (str): Path to user's public key file
            private_key_file (str): Path to user's private key file
            user_label (str): Identifier for the user (e.g., 'user1', 'user2')
        """
        self.public_key_file = public_key_file
        self.private_key_file = private_key_file
        self.user_label = user_label
        self._load_keys()

    def _load_keys(self) -> None:
        """
        Load RSA keys from PEM files.
        Loads both public and private keys needed for encryption and signing.
        """
        # Load public and private keys from PEM files
        with open(self.public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())
        with open(self.private_key_file, 'rb') as f:
            self.private_key = RSA.import_key(f.read())

    def encrypt_file(self, input_file: str, output_file: str) -> Tuple[str, str]:
        """
        Encrypt a file using hybrid encryption scheme.
        
        Process:
        1. Generate random key for ChaCha20-Poly1305
        2. Encrypt file data with ChaCha20-Poly1305
        3. Encrypt symmetric key with RSA-OAEP
        4. Create digital signature
        5. Package everything with metadata
        
        Args:
            input_file (str): Path to the file to encrypt
            output_file (str): Path where encrypted file will be saved
        
        Returns:
            Tuple[str, str]: (output_file_path, file_id)
        """
        print(f"\nProcessing encryption for {self.user_label}...")
        
        # Step 1: Read the input file
        with open(input_file, 'rb') as f:
            data = f.read()

        # Step 2: Generate encryption parameters
        key = get_random_bytes(32)  # 256-bit key for ChaCha20-Poly1305
        nonce = get_random_bytes(12)  # 96-bit nonce (number used once)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        # Step 3: Add authenticated data and encrypt
        cipher.update(b"header")  # Add header as authenticated data
        ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt and get auth tag
        
        # Step 4: Debug information
        print(f"Debug - Original data length: {len(data)}")
        print(f"Debug - Encrypted lengths: key={len(key)}, "
              f"nonce={len(nonce)}, tag={len(tag)}, "
              f"ciphertext={len(ciphertext)}")

        # Step 5: Encrypt the symmetric key with RSA-OAEP
        rsa_cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_key = rsa_cipher.encrypt(key)
        
        # Step 6: Verify RSA encrypted key length
        if len(encrypted_key) != 384:  # 3072 bits = 384 bytes
            raise ValueError(
                f"Unexpected RSA encrypted key length: {len(encrypted_key)} bytes "
                f"(expected 384)"
            )

        # Step 7: Create metadata for tracking and verification
        file_id = ''.join(hex(x)[2:] for x in get_random_bytes(8))
        metadata = {
            "file_id": file_id,
            "algorithm": "ChaCha20-Poly1305",
            "mode": "AEAD",  # Authenticated Encryption with Associated Data
            "key_encryption": "RSA-OAEP",
            "hash_algorithm": "SHA256",
            "user": self.user_label,
            "key_size": len(key) * 8,
            "rsa_size": self.public_key.size_in_bits()
        }

        # Step 8: Package the encrypted data
        metadata_bytes = json.dumps(metadata).encode()
        metadata_length_bytes = len(metadata_bytes).to_bytes(4, 'big')
        
        # Step 9: Assemble the final encrypted package
        encrypted_data = bytearray()
        encrypted_data.extend(metadata_length_bytes)  # 4 bytes for metadata length
        encrypted_data.extend(metadata_bytes)         # Variable length metadata
        encrypted_data.extend(encrypted_key)          # 384 bytes encrypted key
        encrypted_data.extend(nonce)                  # 12 bytes nonce
        encrypted_data.extend(tag)                    # 16 bytes authentication tag
        encrypted_data.extend(ciphertext)             # Variable length ciphertext

        # Step 10: Create and save digital signature
        h = SHA256.new(encrypted_data)
        signature = pkcs1_15.new(self.private_key).sign(h)

        # Step 11: Save the encrypted file
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        # Step 12: Save the signature in a separate file
        signature_file = f"{output_file}.{self.user_label}.sig"
        with open(signature_file, 'wb') as f:
            f.write(signature)

        return output_file, file_id

def encrypt_files(input_file: str, public_key_file_user1: str,
                 private_key_file_user1: str, public_key_file_user2: str,
                 private_key_file_user2: str) -> None:
    """
    Encrypt a file for two users with their respective keys.
    Creates two separate encrypted files, one for each user.
    
    Args:
        input_file: File to encrypt
        public_key_file_user1: Path to User 1's public key
        private_key_file_user1: Path to User 1's private key
        public_key_file_user2: Path to User 2's public key
        private_key_file_user2: Path to User 2's private key
    """
    # Step 1: Process encryption for User 1
    print("\nProcessing encryption for User 1...")
    encryptor1 = AdvancedEncryption(
        public_key_file_user1, private_key_file_user1, "user1"
    )
    output_file1, file_id1 = encryptor1.encrypt_file(
        input_file, f"{input_file}.user1.enc"
    )
    
    # Step 2: Process encryption for User 2
    print("\nProcessing encryption for User 2...")
    encryptor2 = AdvancedEncryption(
        public_key_file_user2, private_key_file_user2, "user2"
    )
    output_file2, file_id2 = encryptor2.encrypt_file(
        input_file, f"{input_file}.user2.enc"
    )

    # Step 3: Print success message with details
    print(f"""\nEncryption completed successfully:
    User 1:
    - Encrypted file: {output_file1}
    - File ID: {file_id1}
    - Signature created
    
    User 2:
    - Encrypted file: {output_file2}
    - File ID: {file_id2}
    - Signature created
    
    Algorithm: ChaCha20-Poly1305 with RSA-OAEP key encryption""")

def main() -> None:
    """
    Parse command line arguments and execute file encryption.
    Handles the command-line interface for the encryption process.
    """
    # Step 1: Set up command line argument parser
    parser = argparse.ArgumentParser(
        description="Encrypt and sign a file using ChaCha20-Poly1305 and RSA "
                   "for two users"
    )
    
    # Step 2: Define required arguments
    parser.add_argument(
        "input_file",
        help="Input file to encrypt and sign"
    )
    parser.add_argument(
        "public_key_file_user1",
        help="RSA Public Key file for User 1"
    )
    parser.add_argument(
        "private_key_file_user1",
        help="RSA Private Key file for User 1"
    )
    parser.add_argument(
        "public_key_file_user2",
        help="RSA Public Key file for User 2"
    )
    parser.add_argument(
        "private_key_file_user2",
        help="RSA Private Key file for User 2"
    )
    
    # Step 3: Parse arguments and execute encryption
    args = parser.parse_args()
    encrypt_files(
        args.input_file,
        args.public_key_file_user1,
        args.private_key_file_user1,
        args.public_key_file_user2,
        args.private_key_file_user2
    )

if __name__ == "__main__":
    main()