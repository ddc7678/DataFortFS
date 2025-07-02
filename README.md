# DataFortFS

**DataFortFS** is a secure, command-line encrypted file system written in Rust. It provides robust file encryption using AES-256, RSA-2048 (OAEP with SHA-256 padding), Argon2id key derivation, and optional Time-Based One-Time Password (TOTP) multi-factor authentication (MFA). File names are obfuscated using AES-256 encryption and base64 encoding, ensuring privacy. DataFortFS is ideal for users needing secure, portable file storage with strong cryptographic guarantees.

## Features
- **Encryption**: Files and configuration are encrypted with AES-256; the AES key is encrypted with RSA-2048.
- **Key Derivation**: Argon2id (64 MiB, 3 iterations, 4 threads) derives keys for configuration encryption.
- **File Name Obfuscation**: File names are encrypted with AES-256 and base64-encoded for privacy.
- **MFA**: Optional TOTP (SHA-1, 6 digits, 30-second period) for `create` and `mount` commands, with a ±30-second window and 3 attempts.
- **QR Code Support**: Generates QR codes for TOTP setup in Google Authenticator or similar apps.
- **Debug Mode**: Use `--debug` to enable verbose output for TOTP troubleshooting.
- **Commands**: `create`, `mount`, and `unmount` for managing encrypted containers.

## Installation
1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```
2. **Clone and Build DataFortFS**:
   ```bash
   git clone https://github.com/ddc7678/DataFortFS.git
   cd DataFortFS
   cargo build --release
   ```
3. **Install the Binary**:
   ```bash
   sudo cp target/release/dffs /usr/local/bin/
   ```
   - The CLI command is `dffs`.

## Generating an RSA Key Pair
DataFortFS uses RSA-2048 for encrypting the AES-256 key. You need an unencrypted RSA key pair in PEM format.

1. **Generate Private Key**:
   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   ```
   - Creates `private_key.pem` (RSA-2048 private key).

2. **Generate Public Key**:
   ```bash
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   ```
   - Creates `public_key.pem` (RSA-2048 public key).

3. **Set Permissions**:
   ```bash
   chmod 600 private_key.pem
   chmod 644 public_key.pem
   ```
   - Ensures the private key is only readable by the owner.

**Note**: Do not use encrypted private keys, as they are not supported. Store `private_key.pem` securely.

## Usage
Run `dffs` with one of the following commands. Use `--mfa` for TOTP authentication and `--debug` for verbose output.

### Create a Container
Creates an encrypted container directory to store files. 

```bash
dffs create <container_path> <public_key_path> [--mfa] [--debug]
```

- **Example (Without MFA)**:
  ```bash
  dffs create ./my_container public_key.pem
  ```
  - **Output**:
    ```
    Container created at "my_container"
    ```
  - **Result**: Creates `my_container/.config` with the encrypted AES-256 key and public key.

- **Example (With MFA)**: With --mfa open your terminal to full screen for the QR Code.
  ```bash
  dffs create ./my_container public_key.pem --mfa
  ```
  - **Output**:
    ```
    MFA enabled. Scan the QR code below with Google Authenticator:
    [QR code ASCII art]
    Or manually enter this secret: V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J
    Enter the 6-digit TOTP code (3 attempts):
    TOTP code: 
    ```
  - Enter the 6-digit code from Google Authenticator (e.g., `840817`).
  - **Result**: Creates `my_container/.config` with the TOTP secret included.
  - **With `--debug`**:
    ```bash
    dffs create ./my_container public_key.pem --mfa --debug
    ```
    - **Additional Output**:
      ```
      DEBUG: Raw secret (hex): <20-byte hex, e.g., 53a4c...>
      DEBUG: Base32 secret: V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J
      DEBUG: Secret bytes (hex): <hex of decoded base32>
      DEBUG: otpauth URI: otpauth://totp/DataFortFS:my_container?secret=V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J&issuer=DataFortFS
      ...
      DEBUG: Current timestamp (seconds since epoch): 1751480580
      DEBUG: Expected TOTP codes: t-1: 123456, t: 840817, t+1: 789012
      ```

### Mount a Container
Decrypts the container’s files to a mount point for access.

```bash
dffs mount <container_path> <private_key_path> <base_mount_point> [--debug]
```

- **Example (Without MFA)**:
  ```bash
  mkdir -p /some/mount
  chmod 700 /some/mount
  dffs mount ./my_container private_key.pem /some/mount
  ```
  - **Output**:
    ```
    Container mounted at "/some/mount/my_container"
    ```
  - **Result**: Decrypts files to `/some/mount/my_container`.

- **Example (With MFA)**:
  ```bash
  dffs mount ./my_container private_key.pem /some/mount
  ```
  - **Output**:
    ```
    MFA required. Enter the 6-digit TOTP code (3 attempts):
    TOTP code: 
    ```
  - Enter the 6-digit TOTP code. Verify: `Container mounted at "/some/mount/my_container"`.
  - **With `--debug`**:
    ```bash
    dffs mount ./my_container private_key.pem /some/mount --debug
    ```
    - **Additional Output**:
      ```
      DEBUG: Current timestamp (seconds since epoch): 1751480640
      DEBUG: Expected TOTP codes: t-1: 123456, t: 840817, t+1: 789012
      ```

- **File Operations**:
  ```bash
  echo "Hello" > /some/mount/my_container/test.txt
  cat /some/mount/my_container/test.txt  # Outputs: Hello
  ```

### Unmount a Container
Encrypts files back to the container and removes the mount point.

```bash
dffs unmount <container_path> <private_key_path> <base_mount_point> [--debug]
```

- **Example**:
  ```bash
  dffs unmount ./my_container private_key.pem /some/mount
  ```
  - **Output**:
    ```
    Container unmounted from "/some/mount/my_container"
    ```
  - **Result**: Encrypts files to `my_container` with obfuscated names (e.g., `my_container/<base64_string>`) and removes `/some/mount/my_container`.

## Full Example
1. **Generate Keys**:
   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   chmod 600 private_key.pem
   chmod 644 public_key.pem
   ```

2. **Create Container with MFA**:
   ```bash
   dffs create ./secure_data public_key.pem --mfa --debug
   ```
   - Scan the QR code or enter the secret (e.g., `V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J`) in Google Authenticator.
   - Enter the 6-digit code (e.g., `840817`).
   - **Output**:
     ```
     DEBUG: Raw secret (hex): <20-byte hex>
     DEBUG: Base32 secret: V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J
     DEBUG: Secret bytes (hex): <hex of decoded base32>
     DEBUG: otpauth URI: otpauth://totp/DataFortFS:secure_data?secret=V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J&issuer=DataFortFS
     MFA enabled. Scan the QR code below with Google Authenticator:
     [QR code ASCII art]
     Or manually enter this secret: V2HMJDQ6F3SBNCBCH2L7ZKCEXV5WEI5J
     Enter the 6-digit TOTP code (3 attempts):
     TOTP code: 840817
     Container created at "secure_data"
     ```
   - **Verify**:
     ```bash
     ls ./secure_data
     ```
     - Output: `.config`

3. **Mount Container**:
   ```bash
   mkdir -p /mnt/secure
   chmod 700 /mnt/secure
   dffs mount ./secure_data private_key.pem /mnt/secure --debug
   ```
   - Enter the 6-digit TOTP code.
   - **Output**:
     ```
     MFA required. Enter the 6-digit TOTP code (3 attempts):
     DEBUG: Current timestamp (seconds since epoch): 1751480700
     DEBUG: Expected TOTP codes: t-1: 123456, t: 840817, t+1: 789012
     TOTP code: 840817
     Container mounted at "/mnt/secure/secure_data"
     ```

4. **Use Files**:
   ```bash
   echo "Secret data" > /mnt/secure/secure_data/secret.txt
   cat /mnt/secure/secure_data/secret.txt  # Outputs: Secret data
   ```

5. **Unmount Container**:
   ```bash
   dffs unmount ./secure_data private_key.pem /mnt/secure
   ```
   - **Output**:
     ```
     Container unmounted from "/mnt/secure/secure_data"
     ```
   - **Verify**:
     ```bash
     ls ./secure_data
     ```
     - Output: `.config <base64_obfuscated_filename>`

## Troubleshooting
- **TOTP Code Rejected**:
  - Ensure system time is synchronized:
    ```bash
    timedatectl  # Check "System clock synchronized: yes"
    sudo ntpdate pool.ntp.org
    ```
  - Verify the TOTP secret matches Google Authenticator’s setup.
  - Use `--debug` to inspect expected codes:
    ```bash
    dffs create ./my_container public_key.pem --mfa --debug
    ```
  - Check phone time sync for Google Authenticator.
- **Key Errors**:
  - Ensure `private_key.pem` is unencrypted and in PKCS#8 or PKCS#1 PEM format.
  - Verify `public_key.pem` matches the private key.
- **Mount Point Issues**:
  - Ensure `<base_mount_point>` exists, is a directory, and is writable:
    ```bash
    mkdir -p /some/mount
    chmod 700 /some/mount
    ```

## Security Notes
- **Private Key**: Store `private_key.pem` securely and never share it.
- **TOTP Secret**: Record the base32 secret (shown during `create --mfa`) in a secure location.
- **Backups**: Consider implementing backup codes for TOTP recovery (future feature).
- **System Time**: TOTP requires accurate system time for code validation.

## Contributing
Contributions are welcome! Please submit issues or pull requests to the [GitHub repository](https://github.com/<your-repo>/datafortfs). For feature requests (e.g., MFA for `unmount`, Windows support), contact us via `datafortfs.com`.

## License
[MIT License](LICENSE)
