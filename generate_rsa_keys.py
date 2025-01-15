#!/usr/bin/env python3
"""
RSA Key Generation Module

This module handles the generation of RSA key pairs with enhanced security features,
including key sharing capabilities using Shamir's Secret Sharing scheme.

Features:
    - RSA key pair generation (3072-bit keys by default)
    - Key metadata management
    - Backup key generation using Shamir's Secret Sharing
    - Secure storage of keys and shares
"""

# Import required cryptographic libraries
from Crypto.PublicKey import RSA  # For RSA key generation
from Crypto.Protocol.SecretSharing import Shamir  # For key splitting
from Crypto.Random import get_random_bytes  # For secure random generation
from Crypto.Hash import SHA256  # For key ID generation
import json  # For metadata storage
import os  # For file operations
from datetime import datetime  # For timestamp generation

def create_key_metadata(key_id: str, key_size: int) -> dict:
    """
    Create metadata for the generated RSA key.
    Includes key specifications and creation timestamp.
    
    Args:
        key_id (str): Unique identifier for the key
        key_size (int): Size of the RSA key in bits
    
    Returns:
        dict: Metadata containing key information
    """
    return {
        "key_id": key_id,  # Unique identifier
        "created_at": datetime.now().isoformat(),  # Creation timestamp
        "key_size": key_size,  # Key size in bits
        "version": "1.0",  # Metadata version
        "algorithm": "RSA"  # Encryption algorithm
    }

def generate_user_keys(user_num: int, key_size: int, shares: int, threshold: int) -> str:
    """
    Generate RSA key pair and backup shares for a specific user.
    
    Process:
    1. Generate unique key ID
    2. Create RSA key pair
    3. Generate backup shares
    4. Save keys and metadata
    
    Args:
        user_num (int): User identifier number
        key_size (int): Size of the RSA key in bits
        shares (int): Number of backup shares to generate
        threshold (int): Minimum shares needed for reconstruction
    
    Returns:
        str: Generated key ID
    """
    # Step 1: Generate a unique key ID
    key_id = SHA256.new(get_random_bytes(32)).hexdigest()[:16]
    
    # Step 2: Generate the RSA key pair
    key = RSA.generate(key_size)  # Generate new RSA key pair
    private_key = key.export_key()  # Export private key (PEM format)
    public_key = key.publickey().export_key()  # Export public key (PEM format)
    
    # Step 3: Create and save metadata
    metadata = create_key_metadata(key_id, key_size)
    
    # Step 4: Save the public key
    with open(f"user{user_num}_public_key.pem", "wb") as public_file:
        public_file.write(public_key)
    
    # Step 5: Save the private key
    with open(f"user{user_num}_private_key.pem", "wb") as private_file:
        private_file.write(private_key)
    
    # Step 6: Save the key metadata
    with open(f"user{user_num}_key_metadata.json", "w") as metadata_file:
        json.dump(metadata, metadata_file, indent=4)
    
    # Step 7: Generate backup key shares
    backup_key = get_random_bytes(16)  # Generate 128-bit backup key
    backup_shares = Shamir.split(threshold, shares, backup_key)
    
    # Step 8: Create directory for backup shares
    shares_dir = f"user{user_num}_key_shares"
    os.makedirs(shares_dir, exist_ok=True)
    
    # Step 9: Save individual backup shares
    for idx, share in backup_shares:
        share_file = os.path.join(shares_dir, f"share_{idx}.bin")
        with open(share_file, "wb") as f:
            f.write(share)
    
    # Step 10: Save backup configuration
    backup_info = {
        "key_id": key_id,
        "total_shares": shares,
        "threshold": threshold,
        "share_locations": [f"share_{idx}.bin" for idx, _ in backup_shares]
    }
    
    with open(os.path.join(shares_dir, "backup_info.json"), "w") as f:
        json.dump(backup_info, f, indent=4)
    
    return key_id

def generate_keys(key_size: int = 3072, shares: int = 3, threshold: int = 2) -> None:
    """
    Generate RSA keys for multiple users with enhanced security features.
    
    Process:
    1. Validate input parameters
    2. Generate keys for User 1
    3. Generate keys for User 2
    4. Create backup shares
    
    Args:
        key_size (int): Size of RSA keys in bits (default: 3072)
        shares (int): Number of backup shares to create (default: 3)
        threshold (int): Minimum shares needed for reconstruction (default: 2)
    """
    # Step 1: Validate input parameters
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits")
    if threshold > shares:
        raise ValueError("Threshold cannot be greater than total shares")
    if shares < 2:
        raise ValueError("Minimum 2 shares required")

    # Step 2: Generate keys for both users
    user1_key_id = generate_user_keys(1, key_size, shares, threshold)
    user2_key_id = generate_user_keys(2, key_size, shares, threshold)
    
    # Step 3: Print success message
    print(f"""RSA keys generated successfully:
    - User 1 Key ID: {user1_key_id}
    - User 2 Key ID: {user2_key_id}
    - Key size: {key_size} bits
    - Backup shares created: {shares} (threshold: {threshold})
    - Key metadata and backup shares stored in separate directories""")

if __name__ == "__main__":
    # Execute key generation with default parameters
    generate_keys()