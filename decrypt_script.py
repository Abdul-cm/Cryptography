#!/usr/bin/env python3
"""
Advanced File Decryption Module

This module implements secure file decryption for files encrypted with the
corresponding encryption module. It handles hybrid encryption schemes and
verifies digital signatures.

Features:
    - Hybrid decryption (ChaCha20-Poly1305 + RSA-OAEP)
    - Digital signature verification
    - Metadata parsing and validation
    - Multi-user support
"""

# Import required libraries
import os  # For file operations
import argparse  # For command line argument parsing
import json  # For metadata handling
from Crypto.Cipher import ChaCha20_Poly1305, PKCS1_OAEP  # For decryption
from Crypto.PublicKey import RSA  # For RSA key operations
from Crypto.Hash import SHA256  # For hashing
from Crypto.Signature import pkcs1_15  # For signature verification
from typing import Tuple, Dict, Any  # For type hints

class AdvancedDecryption:
    def __init__(self, private_key_file: str, public_key_file: str):
        """
        Initialize decryption handler with user keys.
        
        Args:
            private_key_file (str): Path to user's private key file for decryption
            public_key_file (str): Path to user's public key file for signature verification
        """
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self._load_keys()

    def _load_keys(self) -> None:
        """
        Load RSA keys from PEM files.
        Private key for decryption, public key for signature verification.
        """
        with open(self.private_key_file, 'rb') as f:
            self.private_key = RSA.import_key(f.read())
        with open(self.public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())

    def verify_and_decrypt(self, encrypted_file: str, signature_file: str,
                       user_label: str) -> Tuple[str, Dict[str, Any]]:
        """
        Verify signature and decrypt file.
        
        Process:
        1. Read encrypted file and signature
        2. Verify digital signature
        3. Extract and decrypt symmetric key
        4. Decrypt file contents
        5. Verify data integrity
        
        Args:
            encrypted_file (str): Path to encrypted file
            signature_file (str): Path to signature file
            user_label (str): Identifier for the user
        
        Returns:
            Tuple[str, Dict[str, Any]]: (output_filename, metadata)
        """
        print(f"\nVerifying signature for {user_label}...")
        
        # Step 1: Read the encrypted file and signature
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        with open(signature_file, 'rb') as f:
            signature = f.read()

        # Step 2: Verify digital signature
        try:
            h = SHA256.new(encrypted_data)  # Create hash of encrypted data
            pkcs1_15.new(self.public_key).verify(h, signature)  # Verify signature
            print(f"Signature verified successfully for {user_label}")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Signature verification failed for {user_label}: {str(e)}")

        print(f"Decrypting file for {user_label}...")
        return self._decrypt_file(encrypted_data)

    def _decrypt_file(self, encrypted_data: bytes) -> Tuple[str, Dict[str, Any]]:
        """
        Decrypt the file data using hybrid decryption scheme.
        
        Process:
        1. Extract metadata and components
        2. Decrypt symmetric key using RSA
        3. Decrypt file data using ChaCha20-Poly1305
        4. Verify data integrity with Poly1305
        
        Args:
            encrypted_data (bytes): Raw encrypted data package
        
        Returns:
            Tuple[str, Dict[str, Any]]: (output_filename, metadata)
        """
        try:
            # Step 1: Extract metadata
            metadata_length = int.from_bytes(encrypted_data[:4], 'big')
            metadata_bytes = encrypted_data[4:4+metadata_length]
            metadata = json.loads(metadata_bytes.decode())
            
            # Step 2: Calculate positions for encrypted components
            pos = 4 + metadata_length  # Start after metadata
            
            # Step 3: Extract components with exact lengths
            encrypted_key = encrypted_data[pos:pos+384]  # RSA-encrypted key (384 bytes)
            pos += 384
            nonce = encrypted_data[pos:pos+12]  # ChaCha20 nonce (12 bytes)
            pos += 12
            tag = encrypted_data[pos:pos+16]  # Poly1305 tag (16 bytes)
            pos += 16
            ciphertext = encrypted_data[pos:]  # Remaining data is ciphertext

            # Step 4: Debug information
            print(f"Debug - Decryption lengths: encrypted_key={len(encrypted_key)}, "
                  f"nonce={len(nonce)}, tag={len(tag)}, "
                  f"ciphertext={len(ciphertext)}")

            # Step 5: Decrypt the symmetric key using RSA-OAEP
            rsa_cipher = PKCS1_OAEP.new(self.private_key)
            key = rsa_cipher.decrypt(encrypted_key)

            # Step 6: Decrypt file data using ChaCha20-Poly1305
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(b"header")  # Add same authenticated data as during encryption
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            # Step 7: Save decrypted data to file
            output_filename = metadata['file_id'] + '_decrypted.txt'
            with open(output_filename, 'wb') as f:
                f.write(plaintext)

            return output_filename, metadata
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

def process_decryption(filename_user: str, private_key_file: str,
                      public_key_file: str, signature_file: str,
                      user_label: str) -> bool:
    """
    Process decryption for a single user's file.
    
    Args:
        filename_user (str): Path to encrypted file
        private_key_file (str): Path to user's private key
        public_key_file (str): Path to user's public key
        signature_file (str): Path to signature file
        user_label (str): Identifier for the user
    
    Returns:
        bool: True if decryption successful
    """
    try:
        # Step 1: Create decryptor instance
        decryptor = AdvancedDecryption(private_key_file, public_key_file)
        
        # Step 2: Verify signature and decrypt file
        output_file, metadata = decryptor.verify_and_decrypt(
            filename_user, signature_file, user_label
        )
        
        # Step 3: Print success message with details
        print(f"""
Decryption successful for {user_label}:
- Output file: {output_file}
- File ID: {metadata['file_id']}
- Algorithm: {metadata['algorithm']}
- Mode: {metadata['mode']}""")
        
        return True
    except Exception as e:
        print(f"Error processing {user_label}'s file: {str(e)}")
        return False

def main() -> None:
    """
    Parse command line arguments and execute file decryption.
    Handles the command-line interface for the decryption process.
    """
    # Step 1: Set up command line argument parser
    parser = argparse.ArgumentParser(
        description="Verify and decrypt files encrypted with "
                   "ChaCha20-Poly1305 and RSA"
    )
    
    # Step 2: Define required arguments
    parser.add_argument(
        "filename_user1",
        help="Encrypted file for User 1"
    )
    parser.add_argument(
        "private_key_file_user1",
        help="RSA Private Key file for User 1"
    )
    parser.add_argument(
        "public_key_file_user1",
        help="RSA Public Key file for User 1"
    )
    parser.add_argument(
        "signature_file_user1",
        help="Signature file for User 1"
    )
    parser.add_argument(
        "filename_user2",
        help="Encrypted file for User 2"
    )
    parser.add_argument(
        "private_key_file_user2",
        help="RSA Private Key file for User 2"
    )
    parser.add_argument(
        "public_key_file_user2",
        help="RSA Public Key file for User 2"
    )
    parser.add_argument(
        "signature_file_user2",
        help="Signature file for User 2"
    )

    # Step 3: Parse arguments
    args = parser.parse_args()

    # Step 4: Process User 1's file
    success1 = process_decryption(
        args.filename_user1,
        args.private_key_file_user1,
        args.public_key_file_user1,
        args.signature_file_user1,
        "User 1"
    )

    # Step 5: Process User 2's file
    success2 = process_decryption(
        args.filename_user2,
        args.private_key_file_user2,
        args.public_key_file_user2,
        args.signature_file_user2,
        "User 2"
    )

    # Step 6: Print final status
    if success1 and success2:
        print("\nAll files processed successfully!")
    else:
        print("\nSome files could not be processed. Please check the error "
              "messages above.")

if __name__ == "__main__":
    main()
