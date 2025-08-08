# Password Manager

## Overview

This is a command-line password manager written in Go. It securely stores passwords for various sites using AES-GCM encryption with a master password. The passwords are saved in a JSON file (`passwords.json`) and can only be accessed by providing the correct master password.

## Features

- **Secure Storage**: Passwords are encrypted using AES-GCM with a key derived from the master password using PBKDF2.
- **Master Password**: A single master password is used to encrypt and decrypt all stored credentials.
- **Command-Line Interface**: Simple menu-driven interface to add, view, or exit the program.
- **Persistent Storage**: Passwords are stored in a JSON file (`passwords.json`) and loaded on program startup.

## Prerequisites

- Go 1.16 or higher
- Standard Go libraries and `golang.org/x/crypto` for cryptographic functions

## Installation

1. Ensure Go is installed on your system. You can download it from [golang.org](https://golang.org/).
2. Clone or download this repository.
3. Navigate to the project directory and run:

   ```bash
   go mod init password_manager
   go get golang.org/x/crypto/pbkdf2
   go get golang.org/x/term
   ```

4. Build and run the program:

   ```bash
   go run password_manager.go
   ```

## Usage

1. **Initial Setup**:
   - On first run, if `passwords.json` does not exist, you will be prompted to set a master password.
   - Confirm the master password by re-entering it.
2. **Main Menu**:
   - **1. Show passwords**: Displays all stored passwords (site, username, password).
   - **2. Add password**: Prompts for site name, username, and password, then saves them.
   - **3. Exit**: Exits the program.
3. **Loading Existing Data**:
   - If `passwords.json` exists, you will be prompted for the master password to decrypt and load the stored passwords.
   - If the master password is incorrect, a decryption error will occur, and no passwords will be loaded.

## Security Details

- **Encryption**: Uses AES-GCM (Galois/Counter Mode) for authenticated encryption.
- **Key Derivation**: The master password is used with PBKDF2 (100,000 iterations, SHA-256) and a random 16-byte salt to derive a 32-byte encryption key.
- **Nonce**: A random nonce is generated for each encryption operation to ensure uniqueness.
- **Storage**: Encrypted data, salt, and nonce are stored in `passwords.json` in base64-encoded format.

## File Structure

- `password_manager.go`: The main Go source file containing the password manager logic.
- `passwords.json`: The file where encrypted passwords are stored (created automatically).

## Example

```bash
$ go run password_manager.go
Set new master password: ******
Confirm master password: ******
File saved successfully

1. Show passwords
2. Add password
3. Exit
Choose option: 2
Site name: example.com
Username: user123
Password: mysecurepassword
File saved successfully

1. Show passwords
2. Add password
3. Exit
Choose option: 1
Passwords:
Site: example.com | Username: user123 | Password: mysecurepassword
```

## Notes

- The master password is critical. If lost, the encrypted passwords in `passwords.json` cannot be recovered.
- Ensure `passwords.json` is backed up securely, as it contains all encrypted credentials.
- The program does not currently support editing or deleting passwords; you can extend it by modifying the code.

## Limitations

- No password editing or deletion functionality.
- No backup or recovery mechanism for the master password.
- The program runs in a terminal and does not have a graphical interface.

## Future Improvements

- Add functionality to edit or delete existing passwords.
- Implement a password generator for stronger passwords.
- Add support for exporting/importing the password database.
- Enhance error handling for invalid inputs.
