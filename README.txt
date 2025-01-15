1. File Encryption (Main Components):

   - Symmetric Encryption: ChaCha20-Poly1305
     * Key Size: 256-bit (32 bytes)
     * Nonce Size: 96-bit (12 bytes)
     * Built-in authentication with Poly1305
   
   - Asymmetric Encryption: RSA-OAEP
     * Key Size: 3072 bits
     * Used for encrypting the symmetric key
   
   - Digital Signatures: RSA with PKCS1_15
     * Hash Algorithm: SHA-256
     * Used for file integrity and authenticity

2. Encryption Process (Step by Step):
   1. Generate random 256-bit key for ChaCha20-Poly1305
   2. Generate 96-bit nonce
   3. Encrypt file data using ChaCha20-Poly1305
   4. Encrypt the symmetric key using RSA-OAEP
   5. Create metadata (includes file ID, algorithms used)
   6. Sign the entire package using RSA-PKCS1_15

3. Decryption Process (Step by Step):
   1. Verify the digital signature using RSA-PKCS1_15
   2. Extract metadata and encrypted components
   3. Decrypt the symmetric key using RSA-OAEP
   4. Use ChaCha20-Poly1305 to decrypt the file
   5. Verify data integrity using Poly1305

4. Security Features:
   - Hybrid encryption combining:
     * Speed of ChaCha20-Poly1305 for file data
     * Security of RSA for key exchange
   - Authenticated encryption (AEAD) with Poly1305
   - Digital signatures for integrity verification
   - Secure random number generation
   - Multi-user support with separate key pairs

Commands to run:
python encrypt_script.py abc.txt user1_public_key.pem user1_private_key.pem user2_public_key.pem user2_private_key.pem
python decrypt_script.py abc.txt.user1.enc user1_private_key.pem user1_public_key.pem abc.txt.user1.enc.user1.sig abc.txt.user2.enc user2_private_key.pem user2_public_key.pem abc.txt.user2.enc.user2.sig

Acknowledgments:
This implementation is based on:
- Code examples and concepts provided in lecture materials and lab sessions
- Reference implementations from GitHub projects, which were studied, modified, and refactored to create this enhanced version with additional features and security improvements
