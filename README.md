# pass-cli

A secure password manager implemented in Python with SQLite3, Argon2 key derivation, and Fernet encryption. The manager securely stores and retrieves credentials, encrypting all sensitive data.

## Features
- Master password protection with Argon2id key derivation
- Securely stores credentials with encryption
- Generates strong passwords
- Searches stored credentials
- Supports updating and deleting stored credentials
- Prevents brute force attacks with login attempt limits
- Uses OS keyring to store encryption keys securely

## Installation

Ensure you have Python installed (version 3.7+ recommended). Install required dependencies:

```sh
pip install cryptography keyring
```

## Usage

Run the password manager:

```sh
python password_manager.py
```

### Features & Commands

1. **Generate Random Password**  
   Securely generates a strong password of user-specified length.
2. **Set Master Password**  
   Required to encrypt/decrypt stored credentials.
3. **Save App Credentials**  
   Encrypts and stores credentials for an application or website.
4. **Show App Credentials**  
   Decrypts and displays stored credentials.
5. **Search Item**  
   Searches stored credentials by app/site name.
6. **Change Master Password**  
   Re-encrypts all stored credentials with a new master password.
7. **Modify an App's Credentials (Update/Delete)**  
   Allows modification or removal of stored credentials.
8. **Exit**  
   Closes the password manager.

## Security Measures
- **Argon2id Key Derivation**: Prevents brute-force attacks.
- **Fernet Encryption**: Encrypts all sensitive data.
- **OS Keyring Storage**: Secures the encryption key outside the database.
- **Login Attempt Locking**: Prevents repeated failed login attempts.
- **Salt Encryption**: Protects the master key derivation process.

## Acknowledgments
Special thanks to [snoorabbits69](https://github.com/snoorabbits69/) and [Cosmic Predator](https://github.com/CosmicPredator) for their suggestions on improving this project!


