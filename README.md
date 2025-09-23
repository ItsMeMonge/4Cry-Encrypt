# 🔐 4CRY ENCRYPT v2.2 - Advanced File Encryption System

A professional-grade file encryption system that converts any file to the secure `.4cry` format with moderate compression, multiple security layers, and maximum compatibility with binary files including PDFs.

## 🚀 Advanced Features

### 🔒 Multi-Layer Encryption Architecture
- **AES-256-GCM**: Military-grade symmetric encryption with authentication
- **PBKDF2**: Secure key derivation with 100,000 iterations
- **HMAC-SHA256**: Data integrity verification
- **Authentication Tag**: Protection against data tampering

### 🛡️ Security Features v2.2
- **🗜️ Safe Compression**: Deflate or Gzip (level 6) for maximum compatibility
- **✅ Binary-Safe**: No preprocessing that corrupts files
- **🔒 100% Integrity**: Preserves all original data
- **Metadata Steganography**: Hides original file information
- **Integrity Verification**: Detects any data alterations
- **Unique Salt**: Each file uses a different salt
- **Optional Metadata Hiding**: Enhanced privacy control
- **Size Camouflage**: Hide real file size with random padding
- **Random Camouflage**: Automatic random size generation for enhanced security

### 🎯 Core Functionality v2.2
- Convert any file type to secure `.4cry` format
- **📄 PDF-Safe**: Perfect compatibility with binary files
- **🗜️ Moderate Compression**: ~20-30% size reduction without risks
- **📁 Auto Organization**: Automatic `input/`, `output/`, `encrypted/`, `decrypted/` folders
- **🛡️ Maximum Reliability**: Simplified and robust system
- Complete decryption with original file restoration
- Password strength analysis
- Automatic secure password generation
- Professional CLI interface
- Complete metadata preservation

## 📦 Installation

```bash
# Clone the project
git clone https://github.com/ItsMeMonge/4Cry-Encrypt.git
cd 4Cry-Encrypt

# Install dependencies
npm install

# Make the script executable (Linux/Mac)
chmod +x 4cry.js
```

## 🎮 Usage

### Encrypt a File

```bash
# Encryption with manual password (saves to ./encrypted/)
node 4cry.js encrypt my_image.jpg

# Encryption with specified password
node 4cry.js encrypt document.pdf -p "my_super_secure_password"

# Generate automatic password (more secure)
node 4cry.js encrypt video.mp4 --generate-password

# Specify custom output file
node 4cry.js encrypt file.txt ./custom/path/file.4cry

# Encrypt with hidden metadata for enhanced privacy
node 4cry.js encrypt sensitive_file.pdf --hide-metadata

# Encrypt with size camouflage to hide real file size
node 4cry.js encrypt secret_document.txt --camouflage-size 10MB

# Encrypt with random size camouflage
node 4cry.js encrypt secret_file.txt --random-camouflage

# Combine random camouflage with hidden metadata
node 4cry.js encrypt confidential_data.pdf --hide-metadata --random-camouflage
```

### Decrypt a File

```bash
# Decryption with password prompt (saves to ./decrypted/)
node 4cry.js decrypt ./encrypted/file.4cry

# Decryption with specified password
node 4cry.js decrypt ./encrypted/file.4cry -p "my_super_secure_password"

# Specify custom output file
node 4cry.js decrypt ./encrypted/file.4cry ./restored/original_file.jpg
```

### Password Utilities

```bash
# Generate secure password
node 4cry.js generate-password

# Generate password with specific length
node 4cry.js generate-password --length 64

# Analyze password strength
node 4cry.js analyze-password "my_password123"
```

## 🔍 Practical Example

```bash
# 1. Encrypt an image
node 4cry.js encrypt secret_photo.jpg

# The system will prompt for a password and create secret_photo.jpg.4cry

# 2. Decrypt the image
node 4cry.js decrypt ./encrypted/secret_photo.jpg.4cry

# The system will prompt for the password and restore the original image
```

## 🏗️ .4cry File Structure

```
┌─────────────────────────┐
│ Signature "4CRY_v2.0"   │ (9 bytes)
├─────────────────────────┤
│ 4CRY v2.2 Header        │ (256 bytes)
├─────────────────────────┤
│ Cryptographic Salt      │ (32 bytes)
├─────────────────────────┤
│ AES-256-GCM IV          │ (16 bytes)
├─────────────────────────┤
│ GCM Auth Tag            │ (16 bytes)
├─────────────────────────┤
│ Integrity HMAC          │ (32 bytes)
├─────────────────────────┤
│ HMAC Key                │ (32 bytes)
├─────────────────────────┤
│ Secure Metadata         │ (variable)
├─────────────────────────┤
│ Encrypted Data          │ (variable)
└─────────────────────────┘
```

## 🔐 Security Algorithms Used

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Symmetric Encryption | AES-256-GCM | 256 bits | Primary encryption |
| Key Derivation | PBKDF2-SHA256 | 256 bits | Derive key from password |
| Integrity Verification | HMAC-SHA256 | 256 bits | Detect alterations |
| Compression | Deflate/Gzip | N/A | Reduce size (level 6) |
| Random Numbers | crypto.randomBytes | N/A | Salt, IV, padding |

## ⚠️ Security Considerations v2.2

1. **Strong Passwords**: Use passwords with at least 12 characters, including uppercase, lowercase, numbers, and symbols
2. **Password Backup**: Store passwords securely - without them, files are unrecoverable
3. **Sensitive Files**: For extremely sensitive data, consider using the automatic password generator
4. **Integrity Verification**: The system automatically detects corrupted or modified files
5. **📄 PDF-Safe**: Version 2.2 ensures total compatibility with binary files
6. **Metadata Privacy**: Use `--hide-metadata` flag for enhanced privacy when encrypting sensitive files
7. **Size Camouflage**: Use `--camouflage-size` to hide the real file size (e.g., `--camouflage-size 5MB`)
8. **Random Camouflage**: Use `--random-camouflage` for automatic random size generation

## 🚧 Current Limitations

- Very large files (>2GB) may require more RAM
- Decryption requires the exact password used for encryption
- No password recovery - keep them secure
- Moderate compression (~20-30%) prioritizing security over size

## 🆕 What's New v2.2 - "Secure & Reliable"

### ✅ Important Fixes:
- **🔧 PDF Fix**: Fixed issue that corrupted PDF and binary files
- **🗜️ Simplified Compression**: Removed aggressive ultra-compression
- **🛡️ Maximum Compatibility**: System now works with 100% of file types
- **⚡ Performance**: Faster and more stable
- **🎯 Security Focus**: Prioritizes integrity over extreme compression
- **🔒 Enhanced Privacy**: Optional metadata hiding for sensitive operations
- **🎭 Size Camouflage**: Hide real file size with random padding
- **🎲 Random Camouflage**: Automatic intelligent size generation

### 🔄 Differences from v2.1:
| Aspect | v2.1 (Ultra) | v2.2 (Secure) |
|--------|-------------|---------------|
| Compression | 50-70% | 20-30% |
| PDFs | ❌ Corrupted | ✅ Works |
| Complexity | High | Simple |
| Reliability | Medium | High |
| Speed | Slow | Fast |
| Privacy Control | Basic | Enhanced |

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

## 🔮 Future Versions

- [ ] Graphical User Interface (GUI)
- [ ] Multiple file encryption
- [ ] Secure key storage
- [ ] Batch encryption mode
- [ ] Full folder support
- [ ] Cloud integration
- [ ] Key management system

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

**4CRY ENCRYPT v2.2** - "Professional encryption that actually works!" 🔐🚀

*Developed by ItsMeMonge* 💻
