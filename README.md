# 🔐 4CRY ENCRYPT v3.0 - Advanced File Encryption System

**ENHANCED SECURITY & PROFESSIONAL FEATURES**

A professional-grade file encryption system that converts any file or entire folder structures to the secure `.4cry` format with enhanced security features, advanced encryption algorithms, and comprehensive file management capabilities.

## 🚀 Advanced Features

### 🔒 Enhanced Encryption Architecture v3.0
- **AES-256-GCM**: Advanced symmetric encryption with authentication
- **PBKDF2-SHA256**: Enhanced key derivation with 150,000 iterations
- **HMAC-SHA256**: Cryptographic integrity verification
- **Authentication Tags**: Protection against data tampering
- **Unique Salt Per File**: Prevents rainbow table attacks
- **Random IV Generation**: Eliminates pattern analysis
- **Enhanced Password Validation**: Minimum 12 characters with complexity requirements
- **Security Logging**: Comprehensive audit trail

### 🛡️ Enhanced Security Features v3.0
- **Multi-Layer Encryption**: Encrypt files 2-10 times for MAXIMUM SECURITY
- **Secure Erase**: PERMANENTLY DESTROY original files with multiple overwrites
- **Metadata Hiding**: Optional removal of file identification data
- **Size Camouflage**: Random file size generation to prevent analysis
- **Steganographic Padding**: Random data injection for enhanced security
- **Secure Key Storage**: Encrypted password database with master key
- **Batch Processing**: Secure processing of multiple files/folders
- **Integrity Verification**: Real-time corruption detection
- **Security Audit**: Comprehensive system security analysis
- **File Security Assessment**: Risk analysis for individual files
- **RSA Key Generation**: Advanced asymmetric encryption support

### 📁 File Management
- **Single File Encryption**: Individual file encryption with advanced options
- **Full Folder Support**: Complete folder structure encryption
- **Batch Operations**: Multiple file processing capabilities
- **Structure Preservation**: Maintains folder hierarchy during encryption
- **Pattern Filtering**: Automatic exclusion of system/hidden files
- **Size Limits**: Configurable file size limits for security


## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/ItsMeMonge/4Cry-Encrypt.git
cd 4Cry-Encrypt

# Install dependencies
npm install

# Verify installation
node 4cry.js --version

# Initialize key storage
node 4cry.js list-keys
```

## 🎮 Usage

### Single File Encryption

```bash
# Encrypt with enhanced privacy
node 4cry.js encrypt sensitive_file.pdf --hide-metadata --random-camouflage

# Encrypt with specific size camouflage
node 4cry.js encrypt document.txt --camouflage-size 50MB --hide-metadata

# Generate and store secure password
node 4cry.js encrypt data.xlsx --generate-password --store-key "project_2024"
```

### Full Folder Encryption

```bash
# Encrypt entire folder with advanced security
node 4cry.js encrypt-folder ./sensitive_data ./encrypted_data --hide-metadata --random-camouflage

# Encrypt with security filters
node 4cry.js encrypt-folder ./documents ./secure --include-patterns ".pdf,.docx,.txt" --max-file-size 1GB

# Encrypt with stored password
node 4cry.js encrypt-folder ./data ./encrypted --store-key "backup_2024"
```

### Batch Operations

```bash
# Batch encrypt multiple sources
node 4cry.js batch-encrypt file1.txt folder1/ folder2/ --hide-metadata --random-camouflage

# Batch with security filters
node 4cry.js batch-encrypt ./data --extensions ".pdf,.docx" --store-key "batch_2024"
```

### Key Management

```bash
# Store password securely
node 4cry.js store-key "confidential" "MySecurePassword123!" -d "Confidential documents"

# List stored keys
node 4cry.js list-keys

# Retrieve password
node 4cry.js retrieve-key "confidential"

# Delete key
node 4cry.js delete-key "confidential"
```

### Advanced Security Commands

```bash
# Enhanced password analysis with entropy calculation
node 4cry.js analyze-password "MySecurePassword123!"

# Perform comprehensive security audit
node 4cry.js security-audit --check-logs --check-passwords

# Generate RSA key pair for advanced encryption
node 4cry.js generate-keypair --bits 4096 --output ./keys

# Analyze file security and get recommendations
node 4cry.js file-info sensitive_document.pdf

# Multi-layer encryption for MAXIMUM SECURITY (5 layers)
node 4cry.js multi-encrypt secret.txt secret_multi.4cry -l 5 -p "MyPassword123!"

# Decrypt multi-layer encrypted file
node 4cry.js multi-decrypt secret_multi.4cry secret_restored.txt -l 5 -p "MyPassword123!"

# RSA encryption with public key
node 4cry.js encrypt-with-key document.pdf document_rsa.4cry keys/public.pem -p "password"

# RSA decryption with private key
node 4cry.js decrypt-with-key document_rsa.4cry document_restored.pdf keys/private.pem -p "password"

# ULTRA-SECURE ERASE - Complete data elimination with zero traces
node 4cry.js erase sensitive.txt sensitive.4cry -p "password" --overwrite-passes 15

# ULTRA-SECURE ERASE with generated password and maximum security
node 4cry.js erase classified.pdf classified.4cry -g --overwrite-passes 20 --hide-metadata
```

## 📋 Available Commands

### 🔐 Core Encryption Commands
- `encrypt` - Standard single-layer encryption
- `decrypt` - Standard single-layer decryption
- `multi-encrypt` - Multi-layer encryption (2-10 layers)
- `multi-decrypt` - Multi-layer decryption
- `erase` - ULTRA-SECURE ERASE - Complete data elimination with zero traces
- `encrypt-folder` - Encrypt entire folder structures
- `decrypt-folder` - Decrypt entire folder structures
- `batch-encrypt` - Batch process multiple files/folders

### 🔑 Advanced Security Commands
- `encrypt-with-key` - RSA public key encryption
- `decrypt-with-key` - RSA private key decryption
- `generate-keypair` - Generate RSA key pairs
- `security-audit` - Comprehensive security analysis
- `file-info` - File security assessment
- `analyze-password` - Advanced password analysis

### 🛠️ Utility Commands
- `generate-password` - Generate secure passwords
- `store-key` - Store passwords securely
- `retrieve-key` - Retrieve stored passwords
- `list-keys` - List all stored keys
- `delete-key` - Delete stored keys

## 🔍 Practical Examples

### Example 1: Enhanced Privacy Encryption

```bash
# Encrypt sensitive document with enhanced privacy
node 4cry.js encrypt confidential_report.pdf --hide-metadata --random-camouflage

# Result: File appears as random size with no metadata traces
# Security Level: Enhanced
# Privacy Level: Maximum
```

### Example 2: Full Folder Security Operation

```bash
# Encrypt entire project folder with advanced security
node 4cry.js encrypt-folder ./project_data ./secure_backup --hide-metadata --random-camouflage --store-key "project_backup"

# Result: Complete folder encrypted with stored password
# All files: Metadata hidden, sizes randomized
# Password: Securely stored for future use
```

### Example 3: Multi-Layer Encryption for MAXIMUM SECURITY

```bash
# Encrypt with 5 layers for military-grade security
node 4cry.js multi-encrypt classified_document.pdf classified.4cry -l 5 -p "UltraSecurePassword123!"

# Decrypt the multi-layer encrypted file
node 4cry.js multi-decrypt classified.4cry classified_restored.pdf -l 5 -p "UltraSecurePassword123!"

# Generate secure password automatically
node 4cry.js multi-encrypt secret.txt secret.4cry -l 3 -g --hide-metadata
```

**Multi-Layer Encryption Benefits:**
- **Exponential Security**: Each layer multiplies security by 2^256
- **Defense in Depth**: Multiple independent encryption layers
- **Tamper Detection**: Each layer has independent integrity verification
- **Performance Optimized**: Smart compression only on first layer
- **Configurable**: Choose 2-10 layers based on security needs

**Multi-Layer Encryption Benefits:**
- **Exponential Security**: Each layer multiplies security by 2^256
- **Defense in Depth**: Multiple independent encryption layers
- **Tamper Detection**: Each layer has independent integrity verification
- **Performance Optimized**: Smart compression only on first layer
- **Configurable**: Choose 2-10 layers based on security needs

### Example 4: ULTRA-SECURE ERASE - Complete Data Elimination

```bash
# ULTRA-SECURE ERASE with 15 overwrite passes (Military-grade standard)
node 4cry.js erase sensitive_document.pdf sensitive.4cry -p "UltraSecurePassword123!" --overwrite-passes 15

# ULTRA-SECURE ERASE with maximum security (20 passes)
node 4cry.js erase classified_data.txt classified.4cry -g --overwrite-passes 20 --hide-metadata

# ULTRA-SECURE ERASE with custom configuration
node 4cry.js erase personal_info.docx personal.4cry -p "password" --overwrite-passes 10 --random-camouflage
```

**ULTRA-SECURE ERASE Process:**
1. **🔐 Encryption**: File is encrypted to .4cry format with AES-256-GCM
2. **🔥 Multi-Pattern Overwrite**: Original file is overwritten 5-25 times using diverse patterns
3. **🔍 Extended Verification**: Multiple verification checks ensure complete overwrite
4. **🧹 System Trace Elimination**: Metadata, timestamps, and system cache are cleared
5. **🗑️ Secure Deletion**: Multiple deletion attempts with verification
6. **✅ Final Confirmation**: Complete elimination verification

**Advanced Overwrite Patterns:**
- **Binary Patterns**: Zeros (0x00), Ones (0xFF), Alternating (0xAA/0x55)
- **Random Data**: Cryptographically secure random bytes
- **Specific Patterns**: Military-grade overwrite patterns (0x92, 0x49)
- **Entropy Verification**: Ensures sufficient randomness in final state

**ULTRA-SECURE ERASE Benefits:**
- **Zero Trace Recovery**: Original file cannot be recovered by any forensic method
- **Military-Grade Standard**: Exceeds Department of Defense erasure requirements
- **System Integration**: Eliminates metadata, timestamps, and system traces
- **Multi-Layer Verification**: Comprehensive verification of complete elimination
- **Forensic Resistance**: Resistant to advanced data recovery techniques
- **Recovery**: Only possible with correct password and encrypted .4cry file

### Example 5: Batch Security Processing

```bash
# Process multiple sensitive folders
node 4cry.js batch-encrypt ./documents ./financial ./personal --hide-metadata --random-camouflage --store-key "mass_backup"

# Result: All folders processed with advanced security
# Each file: Unique random size, no metadata
# Password: Securely stored
```

## 🏗️ File Structure

```
┌─────────────────────────┐
│ Signature "4CRY_v2.0"   │ (9 bytes) - Version identification
├─────────────────────────┤
│ Security Header         │ (256 bytes) - Security parameters
├─────────────────────────┤
│ Cryptographic Salt      │ (32 bytes) - Unique per file
├─────────────────────────┤
│ AES-256-GCM IV          │ (16 bytes) - Random initialization
├─────────────────────────┤
│ GCM Authentication Tag  │ (16 bytes) - Integrity verification
├─────────────────────────┤
│ HMAC Integrity Hash     │ (32 bytes) - Data integrity
├─────────────────────────┤
│ HMAC Key                │ (32 bytes) - Integrity key
├─────────────────────────┤
│ Steganographic Metadata │ (variable) - Hidden/anonymous data
├─────────────────────────┤
│ Encrypted Data          │ (variable) - AES-256-GCM encrypted
├─────────────────────────┤
│ Anonymity Padding       │ (variable) - Random size camouflage
└─────────────────────────┘
```

## 🔐 Security Algorithms

| Component | Algorithm | Key Size | Security Level | Purpose |
|-----------|-----------|----------|----------------|---------|
| Primary Encryption | AES-256-GCM | 256 bits | Advanced | Core encryption |
| Key Derivation | PBKDF2-SHA256 | 256 bits | Advanced | Password to key conversion |
| Integrity Verification | HMAC-SHA256 | 256 bits | Advanced | Data integrity |
| Authentication | GCM Auth Tag | 128 bits | Advanced | Tamper detection |
| Compression | Deflate/Gzip | N/A | Secure | Size optimization |
| Random Generation | crypto.randomBytes | N/A | Cryptographic | Salt, IV, padding |
| Key Storage | AES-256-GCM | 256 bits | Advanced | Password database |

## ⚠️ Security Considerations

### 🔒 Important Security Requirements

1. **Strong Passwords**: Use passwords with at least 12 characters, including uppercase, lowercase, numbers, and symbols
2. **Password Backup**: Store passwords securely - without them, files are unrecoverable
3. **Sensitive Files**: For extremely sensitive data, consider using the automatic password generator
4. **Integrity Verification**: The system automatically detects corrupted or modified files
5. **Metadata Privacy**: Use `--hide-metadata` flag for enhanced privacy when encrypting sensitive files
6. **Size Camouflage**: Use `--camouflage-size` to hide the real file size (e.g., `--camouflage-size 5MB`)
7. **Random Camouflage**: Use `--random-camouflage` for automatic random size generation
8. **Key Management**: Use the secure key storage system for password management

### 🛡️ Best Practices

- **Always use strong passwords** for sensitive operations
- **Store passwords securely** using the built-in key management system
- **Enable privacy features** for maximum privacy protection
- **Verify file integrity** after encryption/decryption operations
- **Use unique passwords** for each encryption operation
- **Regular security audits** of stored keys and encrypted data
- **Secure backup procedures** for critical encrypted data

## 🚧 Current Limitations

- **File Size Limits**: Maximum 2GB per file (configurable limit)
- **Memory Requirements**: Large files require sufficient RAM for processing
- **Password Dependency**: Decryption requires exact password (no recovery mechanism)
- **Key Storage**: Master key must be protected (no key recovery if lost)
- **Processing Time**: Advanced security operations take longer due to multiple layers
- **Storage Overhead**: Security features add ~20-30% to file size
- **No Backdoors**: System has no recovery mechanisms or backdoors

## 🆕 What's New v3.0 - "Enhanced Security & Advanced Features"

### ✅ New Features:

- **🔒 Enhanced Encryption**: Increased PBKDF2 iterations to 150,000
- **🔐 Multi-Layer Encryption**: Encrypt files multiple times for MAXIMUM SECURITY
- **🔥 Ultra-Secure Erase**: Complete data elimination with zero traces and forensic resistance
- **🎭 Advanced Password Validation**: Minimum 12 characters with complexity checks
- **🛡️ Security Audit System**: Comprehensive system security analysis
- **📊 File Security Assessment**: Risk analysis for individual files
- **🔑 RSA Key Generation**: Advanced asymmetric encryption support
- **🔓 RSA Encryption/Decryption**: Full RSA public/private key support
- **📋 Security Logging**: Comprehensive audit trail
- **⚡ Enhanced Performance**: Improved processing speed and efficiency
- **🎯 Better Error Handling**: More detailed error messages and recovery
- **📈 Entropy Calculation**: Advanced password strength analysis
- **🔍 Pattern Detection**: Detection of common password patterns

### 🔄 Feature Evolution:

| Feature | v2.2 | v3.0 Enhanced |
|---------|------|---------------|
| PBKDF2 Iterations | 100,000 | 150,000 |
| Multi-Layer Encryption | None | 2-10 layers |
| Ultra-Secure Erase | None | Military-grade (5-25 passes) |
| Password Validation | Basic | Advanced (12+ chars) |
| Security Audit | None | Comprehensive |
| File Analysis | None | Risk assessment |
| RSA Support | None | Full support |
| Security Logging | None | Complete audit trail |
| Error Handling | Basic | Enhanced |
| Performance | Good | Optimized |

## ❓ FAQ - Frequently Asked Questions

### 🤔 Why didn't my PDFs work in v2.1?
Version 2.1 had aggressive preprocessing that modified binary data. v2.2 removes this completely.

### 📊 Why did compression decrease?
We prioritized **integrity** over extreme compression. It's better to have 20% safe reduction than 70% with corruption risk.

### 🔐 Are files still secure?
**Yes!** AES-256-GCM security remains unchanged. We only simplified compression.

### 🚀 What's the difference from the original "For Cry"?
- **Original**: Funny name, ultra-compression 
- **v2.2**: Funny name, **actual functionality** 😭

### 📄 Can I use it with any file type?
**Yes!** PDFs, images, videos, executables - all work perfectly in v2.2.

### 🔒 What does the --hide-metadata option do?
The `--hide-metadata` flag removes file metadata from the encrypted file, providing enhanced privacy for sensitive documents. This prevents information about the original file from being stored in the encrypted container.

### 🎭 What does the --camouflage-size option do?
The `--camouflage-size` flag allows you to hide the real size of your encrypted file by adding random padding. This is useful for operational security when you want to disguise that a small file contains important data. For example, a 1KB text file can be made to appear as a 10MB file.

**Examples:**
- `--camouflage-size 5MB` - Makes the file appear as 5 megabytes
- `--camouflage-size 1.2GB` - Makes the file appear as 1.2 gigabytes  
- `--camouflage-size 500KB` - Makes the file appear as 500 kilobytes

**Important:** The camouflage size must be larger than the original encrypted file size.

### 🎲 What does the --random-camouflage option do?
The `--random-camouflage` flag automatically generates a random size for your encrypted file based on intelligent algorithms. This provides maximum security without requiring you to specify exact sizes.

**How it works:**
- **Small files (< 1KB)**: Multiplied by 10-100x (e.g., 100 bytes → 1-10 KB)
- **Medium files (< 1MB)**: Multiplied by 5-50x (e.g., 50 KB → 250 KB - 2.5 MB)
- **Large files (< 100MB)**: Multiplied by 2-10x (e.g., 10 MB → 20-100 MB)
- **Very large files (≥ 100MB)**: Multiplied by 1.1-3x (e.g., 200 MB → 220-600 MB)

**Benefits:**
- **Automatic**: No need to calculate sizes manually
- **Intelligent**: Adapts to file size for realistic camouflage
- **Secure**: Random generation prevents pattern analysis
- **Convenient**: Perfect for batch operations

## 🔮 Future Enhancements

- [ ] **Graphical User Interface (GUI)**: User-friendly graphical interface
- [x] **Multiple file encryption**: Batch processing capabilities
- [x] **Secure key storage**: Encrypted password database system
- [x] **Batch encryption mode**: Multi-file processing
- [x] **Full folder support**: Complete folder structure encryption
- [x] **Multi-layer encryption**: Encrypt files multiple times for maximum security
- [x] **Ultra-secure erase**: Complete data elimination with forensic resistance
- [x] **RSA encryption/decryption**: Full asymmetric encryption support
- [ ] **Cloud integration**: Cloud storage compatibility
- [x] **Security audit system**: Comprehensive security analysis
- [x] **File security assessment**: Risk analysis for files
- [x] **RSA key generation**: Asymmetric encryption support

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

**4CRY ENCRYPT v3.0** - "Enhanced Security & Professional Features!" 🔐🚀

*Developed by Sr. Monge* 🎩
