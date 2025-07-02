use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use rand::Rng;
use std::fmt;
use std::process;
use argon2::{Algorithm, Argon2, Params, Version};
use rsa::{RsaPublicKey, RsaPrivateKey, Oaep};
use rsa::pkcs8::{DecodePublicKey, DecodePrivateKey, EncodePublicKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use base64::{engine::general_purpose, Engine as _};
use std::os::unix::fs::PermissionsExt;
use qrcode::QrCode;
use base32;
use hex;
use totp_lite::{totp, Sha1};

#[derive(Debug)]
enum CryptoError {
    Argon2(argon2::Error),
    Base64(base64::DecodeError),
    QRCode(qrcode::types::QrError),
    TOTP(String),
    Other(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Argon2(e) => write!(f, "Argon2 error: {:?}", e),
            CryptoError::Base64(e) => write!(f, "Base64 error: {}", e),
            CryptoError::QRCode(e) => write!(f, "QR code error: {}", e),
            CryptoError::TOTP(e) => write!(f, "TOTP error: {}", e),
            CryptoError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        CryptoError::Argon2(err)
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::Base64(err)
    }
}

impl From<qrcode::types::QrError> for CryptoError {
    fn from(err: qrcode::types::QrError) -> Self {
        CryptoError::QRCode(err)
    }
}

impl From<String> for CryptoError {
    fn from(err: String) -> Self {
        CryptoError::Other(err)
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

impl From<rsa::errors::Error> for CryptoError {
    fn from(err: rsa::errors::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

impl From<rsa::pkcs8::Error> for CryptoError {
    fn from(err: rsa::pkcs8::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

impl From<rsa::pkcs8::spki::Error> for CryptoError {
    fn from(err: rsa::pkcs8::spki::Error) -> Self {
        CryptoError::Other(err.to_string())
    }
}

#[derive(Serialize, Deserialize)]
struct ContainerConfig {
    encrypted_aes_key: Vec<u8>, // AES-256 key encrypted with RSA public key
    public_key: Vec<u8>,       // RSA public key in DER format
    totp_secret: Option<String>, // Base32-encoded TOTP secret (None if MFA not enabled)
}

fn derive_key(key_data: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    let params = Params::new(64 * 1024, 3, 4, None).map_err(CryptoError::Argon2)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(key_data, salt, &mut key).map_err(CryptoError::Argon2)?;
    Ok(key)
}

fn encrypt_config(config: &ContainerConfig, key_data: &[u8], salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(key_data, salt)?;
    let cipher = aes::Aes256::new(GenericArray::from_slice(&key));

    let mut config_data = serde_json::to_vec(config)?;
    let padding = 16 - (config_data.len() % 16);
    config_data.extend(vec![padding as u8; padding]);

    let mut encrypted = Vec::new();
    for chunk in config_data.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(&block);
    }

    let mut result = salt.to_vec();
    result.extend(encrypted);
    Ok(result)
}

fn decrypt_config(encrypted_data: &[u8], key_data: &[u8]) -> Result<ContainerConfig, CryptoError> {
    if encrypted_data.len() < 16 {
        return Err(CryptoError::Other("Invalid encrypted .config data: too short (must include at least 16-byte salt)".to_string()));
    }
    let (salt, ciphertext) = encrypted_data.split_at(16);
    let key = derive_key(key_data, salt)?;
    let cipher = aes::Aes256::new(GenericArray::from_slice(&key));

    let mut decrypted = Vec::new();
    for chunk in ciphertext.chunks(16) {
        if chunk.len() != 16 {
            return Err(CryptoError::Other("Invalid ciphertext chunk length in .config: must be multiple of 16 bytes".to_string()));
        }
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(&block);
    }

    let padding = *decrypted.last().ok_or(CryptoError::Other("Invalid .config data: empty ciphertext after decryption".to_string()))?;
    if padding as usize > 16 || padding == 0 {
        return Err(CryptoError::Other(format!("Invalid padding value in .config: {} (must be 1-16)", padding)));
    }
    decrypted.truncate(decrypted.len() - padding as usize);
    let config = serde_json::from_slice(&decrypted).map_err(|e| CryptoError::Other(format!("Failed to deserialize .config: {}", e)))?;
    Ok(config)
}

fn encrypt_file(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));

    let mut encrypted = Vec::new();
    let padding = 16 - (data.len() % 16);
    let mut padded_data = data.to_vec();
    padded_data.extend(vec![padding as u8; padding]);

    for chunk in padded_data.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(&block);
    }
    Ok(encrypted)
}

fn decrypt_file(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() % 16 != 0 {
        return Err(CryptoError::Other("Invalid encrypted file data: length must be multiple of 16 bytes".to_string()));
    }
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));

    let mut decrypted = Vec::new();
    for chunk in encrypted_data.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(&block);
    }

    let padding = *decrypted.last().ok_or(CryptoError::Other("Invalid file data: empty ciphertext after decryption".to_string()))?;
    if padding as usize > 16 || padding == 0 {
        return Err(CryptoError::Other(format!("Invalid padding value in file: {} (must be 1-16)", padding)));
    }
    decrypted.truncate(decrypted.len() - padding as usize);
    Ok(decrypted)
}

fn encrypt_filename(filename: &str, key: &[u8]) -> Result<String, CryptoError> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut data = filename.as_bytes().to_vec();
    let padding = 16 - (data.len() % 16);
    data.extend(vec![padding as u8; padding]);

    let mut encrypted = Vec::new();
    for chunk in data.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(&block);
    }

    Ok(general_purpose::STANDARD_NO_PAD.encode(&encrypted))
}

fn decrypt_filename(encrypted_filename: &str, key: &[u8]) -> Result<String, CryptoError> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let encrypted_data = general_purpose::STANDARD_NO_PAD.decode(encrypted_filename)?;
    if encrypted_data.len() % 16 != 0 {
        return Err(CryptoError::Other("Invalid encrypted filename length: must be multiple of 16 bytes".to_string()));
    }

    let mut decrypted = Vec::new();
    for chunk in encrypted_data.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(&block);
    }

    let padding = *decrypted.last().ok_or(CryptoError::Other("Invalid filename data: empty after decryption".to_string()))?;
    if padding as usize > 16 || padding == 0 {
        return Err(CryptoError::Other(format!("Invalid padding value in filename: {} (must be 1-16)", padding)));
    }
    decrypted.truncate(decrypted.len() - padding as usize);
    String::from_utf8(decrypted).map_err(|e| CryptoError::Other(format!("Failed to decode filename as UTF-8: {}", e)))
}

fn create_container(container_path: &Path, public_key_path: &Path, enable_mfa: bool, debug: bool) -> Result<(), CryptoError> {
    fs::create_dir_all(container_path)?;

    // Read and parse public key
    let mut public_key_file = File::open(public_key_path)?;
    let mut public_key_data = Vec::new();
    public_key_file.read_to_end(&mut public_key_data)?;
    let public_key_pem = String::from_utf8_lossy(&public_key_data);
    if !public_key_pem.contains("-----BEGIN PUBLIC KEY-----") {
        return Err(CryptoError::Other("Invalid public key format: expected PEM with '-----BEGIN PUBLIC KEY-----' header".to_string()));
    }
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem).map_err(|e| CryptoError::Other(format!("Failed to parse public key: {}", e)))?;

    // Generate random AES-256 key
    let aes_key: [u8; 32] = rand::thread_rng().gen();

    // Encrypt AES-256 key with public key
    let padding = Oaep::new::<Sha256>();
    let encrypted_aes_key = public_key.encrypt(&mut rand::thread_rng(), padding, &aes_key)?;

    // Generate salt for .config encryption
    let salt = rand::thread_rng().gen::<[u8; 16]>().to_vec();

    // Handle MFA if enabled
    let totp_secret = if enable_mfa {
        let container_name = container_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or(CryptoError::Other("Invalid container path: no file name".to_string()))?;
        let raw_secret = rand::thread_rng().gen::<[u8; 20]>();
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw_secret);
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
            .ok_or_else(|| CryptoError::TOTP("Failed to decode base32 secret".to_string()))?;

        let uri = format!(
            "otpauth://totp/DataFortFS:{}?secret={}&issuer=DataFortFS",
            container_name, secret
        );
        
        // Debug prints for TOTP verification
        if debug {
            println!("DEBUG: Raw secret (hex): {}", hex::encode(&raw_secret));
            println!("DEBUG: Base32 secret: {}", secret);
            println!("DEBUG: Secret bytes (hex): {}", hex::encode(&secret_bytes));
            println!("DEBUG: otpauth URI: {}", uri);
        }

        let qr = QrCode::new(uri.as_bytes())?;
        let ascii = qr
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build();
        
        println!("MFA enabled. Scan the QR code below with Google Authenticator:");
        println!("{}", ascii);
        println!("Or manually enter this secret: {}", secret);
        println!("Enter the 6-digit TOTP code (3 attempts):");

        let mut attempts = 3;
        let mut verified = false;
        while attempts > 0 {
            // Get current timestamp
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if debug {
                println!("DEBUG: Current timestamp (seconds since epoch): {}", current_time);
            }
            
            // Generate TOTP codes for current and adjacent time steps
            let time_steps = [
                current_time.saturating_sub(30), // t-1
                current_time,                    // t
                current_time + 30,              // t+1
            ];
            let mut expected_codes = Vec::new();
            for &t in &time_steps {
                let code = totp::<Sha1>(&secret_bytes, t);
                // Truncate to 6 digits (take last 6 digits)
                let code = code.chars().rev().take(6).collect::<String>().chars().rev().collect::<String>();
                expected_codes.push(code);
            }
            if debug {
                println!("DEBUG: Expected TOTP codes: t-1: {}, t: {}, t+1: {}", 
                    expected_codes[0], expected_codes[1], expected_codes[2]);
            }
            
            print!("TOTP code: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let code = input.trim();
            if code.len() != 6 || !code.chars().all(|c| c.is_digit(10)) {
                println!("Invalid code: must be exactly 6 digits and numeric");
                attempts -= 1;
                continue;
            }
            // Manual verification
            if expected_codes.iter().any(|c| c == code) {
                verified = true;
                break;
            }
            attempts -= 1;
            println!("Invalid TOTP code. {} attempts remaining.", attempts);
        }
        if !verified {
            return Err(CryptoError::TOTP("Failed to verify TOTP code after 3 attempts".to_string()));
        }
        Some(secret)
    } else {
        None
    };

    // Create config with encrypted AES key, public key, and TOTP secret
    let config = ContainerConfig {
        encrypted_aes_key,
        public_key: public_key.to_public_key_der().map_err(|e| CryptoError::Other(format!("Failed to encode public key to DER: {}", e)))?.as_bytes().to_vec(),
        totp_secret,
    };

    // Encrypt config with AES-256 (using public key as key input for Argon2id)
    let config_path = container_path.join(".config");
    let public_key_der = public_key.to_public_key_der().map_err(|e| CryptoError::Other(format!("Failed to encode public key to DER: {}", e)))?.as_bytes().to_vec();
    let encrypted_config = encrypt_config(&config, &public_key_der, &salt)?;
    let mut config_file = File::create(&config_path)?;
    config_file.write_all(&encrypted_config)?;

    Ok(())
}

fn mount_container(container_path: &Path, private_key_path: &Path, mount_point: &Path, debug: bool) -> Result<(), CryptoError> {
    // Read and parse private key
    let mut private_key_file = File::open(private_key_path)?;
    let mut private_key_data = Vec::new();
    private_key_file.read_to_end(&mut private_key_data)?;
    let private_key_pem = String::from_utf8_lossy(&private_key_data);
    if !(private_key_pem.contains("-----BEGIN PRIVATE KEY-----") || private_key_pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
        return Err(CryptoError::Other("Invalid private key format: expected PEM with '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----' header".to_string()));
    }
    if private_key_pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(CryptoError::Other("Encrypted private keys are not supported; use an unencrypted RSA key".to_string()));
    }
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem).or_else(|pkcs8_err| {
        RsaPrivateKey::from_pkcs1_pem(&private_key_pem).map_err(|pkcs1_err| {
            CryptoError::Other(format!(
                "Failed to parse private key (PKCS#8 error: {}; PKCS#1 error: {}). Ensure the key is an unencrypted RSA private key.",
                pkcs8_err, pkcs1_err
            ))
        })
    })?;

    // Read and decrypt .config
    let config_path = container_path.join(".config");
    let mut config_file = File::open(&config_path).map_err(|e| CryptoError::Other(format!("Failed to open .config: {}", e)))?;
    let mut encrypted_config = Vec::new();
    config_file.read_to_end(&mut encrypted_config)?;

    // Decrypt .config using public key derived key
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key.to_public_key_der().map_err(|e| CryptoError::Other(format!("Failed to encode public key to DER: {}", e)))?.as_bytes().to_vec();
    let config = decrypt_config(&encrypted_config, &public_key_der)?;

    // Verify TOTP if MFA is enabled
    if let Some(secret) = &config.totp_secret {
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| CryptoError::TOTP("Failed to decode base32 secret".to_string()))?;
        
        println!("MFA required. Enter the 6-digit TOTP code (3 attempts):");
        let mut attempts = 3;
        let mut verified = false;
        while attempts > 0 {
            // Get current timestamp
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if debug {
                println!("DEBUG: Current timestamp (seconds since epoch): {}", current_time);
            }
            
            // Generate TOTP codes for current and adjacent time steps
            let time_steps = [
                current_time.saturating_sub(30), // t-1
                current_time,                    // t
                current_time + 30,              // t+1
            ];
            let mut expected_codes = Vec::new();
            for &t in &time_steps {
                let code = totp::<Sha1>(&secret_bytes, t);
                // Truncate to 6 digits (take last 6 digits)
                let code = code.chars().rev().take(6).collect::<String>().chars().rev().collect::<String>();
                expected_codes.push(code);
            }
            if debug {
                println!("DEBUG: Expected TOTP codes: t-1: {}, t: {}, t+1: {}", 
                    expected_codes[0], expected_codes[1], expected_codes[2]);
            }
            
            print!("TOTP code: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let code = input.trim();
            if code.len() != 6 || !code.chars().all(|c| c.is_digit(10)) {
                println!("Invalid code: must be exactly 6 digits and numeric");
                attempts -= 1;
                continue;
            }
            // Manual verification
            if expected_codes.iter().any(|c| c == code) {
                verified = true;
                break;
            }
            attempts -= 1;
            println!("Invalid TOTP code. {} attempts remaining.", attempts);
        }
        if !verified {
            return Err(CryptoError::TOTP("Failed to verify TOTP code after 3 attempts".to_string()));
        }
    }

    // Decrypt AES-256 key
    let padding = Oaep::new::<Sha256>();
    let aes_key = private_key.decrypt(padding, &config.encrypted_aes_key).map_err(|e| CryptoError::Other(format!("Failed to decrypt AES key: {}", e)))?;

    // Verify public key matches
    if public_key_der != config.public_key {
        return Err(CryptoError::Other("Public key mismatch: private key does not correspond to the public key in .config".to_string()));
    }

    fs::create_dir_all(mount_point)?;

    let entries: Vec<_> = fs::read_dir(container_path)?.collect();
    if entries.is_empty() {
        return Ok(()); // No files to decrypt
    }

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        if file_name_str == ".config" {
            continue;
        }

        let original_file_name = decrypt_filename(&file_name_str, &aes_key)?;
        let output_path = mount_point.join(original_file_name);
        let mut file_data = Vec::new();
        File::open(entry.path())?.read_to_end(&mut file_data)?;
        let decrypted_data = decrypt_file(&file_data, &aes_key)?;

        let mut output_file = File::create(&output_path)?;
        output_file.write_all(&decrypted_data)?;
    }

    Ok(())
}

fn unmount_container(container_path: &Path, private_key_path: &Path, mount_point: &Path, _debug: bool) -> Result<(), CryptoError> {
    // Read and parse private key
    let mut private_key_file = File::open(private_key_path)?;
    let mut private_key_data = Vec::new();
    private_key_file.read_to_end(&mut private_key_data)?;
    let private_key_pem = String::from_utf8_lossy(&private_key_data);
    if !(private_key_pem.contains("-----BEGIN PRIVATE KEY-----") || private_key_pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
        return Err(CryptoError::Other("Invalid private key format: expected PEM with '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----' header".to_string()));
    }
    if private_key_pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(CryptoError::Other("Encrypted private keys are not supported; use an unencrypted RSA key".to_string()));
    }
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem).or_else(|pkcs8_err| {
        RsaPrivateKey::from_pkcs1_pem(&private_key_pem).map_err(|pkcs1_err| {
            CryptoError::Other(format!(
                "Failed to parse private key (PKCS#8 error: {}; PKCS#1 error: {}). Ensure the key is an unencrypted RSA private key.",
                pkcs8_err, pkcs1_err
            ))
        })
    })?;

    // Read and decrypt .config
    let config_path = container_path.join(".config");
    let mut config_file = File::open(&config_path).map_err(|e| CryptoError::Other(format!("Failed to open .config: {}", e)))?;
    let mut encrypted_config = Vec::new();
    config_file.read_to_end(&mut encrypted_config)?;

    // Decrypt .config using public key derived key
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key.to_public_key_der().map_err(|e| CryptoError::Other(format!("Failed to encode public key to DER: {}", e)))?.as_bytes().to_vec();
    let config = decrypt_config(&encrypted_config, &public_key_der)?;

    // Decrypt AES-256 key
    let padding = Oaep::new::<Sha256>();
    let aes_key = private_key.decrypt(padding, &config.encrypted_aes_key).map_err(|e| CryptoError::Other(format!("Failed to decrypt AES key: {}", e)))?;

    // Verify public key matches
    if public_key_der != config.public_key {
        return Err(CryptoError::Other("Public key mismatch: private key does not correspond to the public key in .config".to_string()));
    }

    let entries: Vec<_> = fs::read_dir(mount_point)?.collect();
    if entries.is_empty() {
        fs::remove_dir_all(mount_point)?;
        return Ok(()); // No files to encrypt
    }

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        let encrypted_file_name = encrypt_filename(&file_name_str, &aes_key)?;

        let mut file_data = Vec::new();
        File::open(entry.path())?.read_to_end(&mut file_data)?;
        let encrypted_data = encrypt_file(&file_data, &aes_key)?;

        let output_path = container_path.join(encrypted_file_name);
        let mut output_file = File::create(&output_path)?;
        output_file.write_all(&encrypted_data)?;
    }

    fs::remove_dir_all(mount_point)?;

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: dffs create <container_path> <public_key_path> [--mfa] [--debug]");
        eprintln!("       dffs mount <container_path> <private_key_path> <base_mount_point> [--debug]");
        eprintln!("       dffs unmount <container_path> <private_key_path> <base_mount_point> [--debug]");
        process::exit(1);
    }

    let command = &args[1];
    let container_path = PathBuf::from(&args[2]);
    let container_name = container_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            eprintln!("Invalid container path: no file name");
            process::exit(1);
        });

    let debug = args.contains(&"--debug".to_string());

    match command.as_str() {
        "create" => {
            if args.len() < 4 || args.len() > 6 {
                eprintln!("Usage: dffs create <container_path> <public_key_path> [--mfa] [--debug]");
                process::exit(1);
            }
            let public_key_path = PathBuf::from(&args[3]);
            let enable_mfa = args.contains(&"--mfa".to_string());
            if let Err(e) = create_container(&container_path, &public_key_path, enable_mfa, debug) {
                eprintln!("Error creating container: {}", e);
                process::exit(1);
            }
            println!("Container created at {:?}", container_path);
        }
        "mount" | "unmount" => {
            if args.len() < 5 || args.len() > 6 {
                eprintln!("Usage: dffs {} <container_path> <private_key_path> <base_mount_point> [--debug]", command);
                process::exit(1);
            }
            let private_key_path = PathBuf::from(&args[3]);
            let base_mount_point = PathBuf::from(&args[4]);

            // Validate base mount point
            if !base_mount_point.exists() {
                eprintln!("Base mount point does not exist: {:?}", base_mount_point);
                process::exit(1);
            }
            if !base_mount_point.is_dir() {
                eprintln!("Base mount point is not a directory: {:?}", base_mount_point);
                process::exit(1);
            }
            if !fs::metadata(&base_mount_point)
                .map(|m| m.permissions().mode() & 0o200 != 0)
                .unwrap_or(false)
            {
                eprintln!("Base mount point is not writable: {:?}", base_mount_point);
                process::exit(1);
            }

            let mount_point = base_mount_point.join(&container_name);

            match command.as_str() {
                "mount" => {
                    if let Err(e) = mount_container(&container_path, &private_key_path, &mount_point, debug) {
                        eprintln!("Error mounting container: {}", e);
                        process::exit(1);
                    }
                    println!("Container mounted at {:?}", mount_point);
                }
                "unmount" => {
                    if let Err(e) = unmount_container(&container_path, &private_key_path, &mount_point, debug) {
                        eprintln!("Error unmounting container: {}", e);
                        process::exit(1);
                    }
                    println!("Container unmounted from {:?}", mount_point);
                }
                _ => unreachable!(),
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            process::exit(1);
        }
    }
}