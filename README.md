# CodTech-ADVANCED-ENCRYPTION-TOOL

Advanced Encryption Tool – Detailed Documentation
1. Introduction

The Advanced Encryption Tool is a Python-based security application designed to provide robust encryption and decryption capabilities using AES-256-GCM, a modern and highly secure authenticated encryption standard. This project demonstrates applied cybersecurity concepts such as key derivation, encryption algorithms, password hardening, secure metadata handling, and user-friendly CLI interface design.
Its purpose is to give users a simple yet powerful way to protect sensitive files during storage or transmission.

This tool was developed as part of a cybersecurity internship task and aims to illustrate real-world cryptographic engineering principles while maintaining strict security best practices.

2. Project Goals

The goals of the Advanced Encryption Tool include:

Provide a secure way to encrypt and decrypt any file type.

Implement strong encryption using AES-256 in GCM mode.

Use PBKDF2 (Password-Based Key Derivation Function) to strengthen user passwords.

Include an option to use randomly generated AES-256 keys stored in separate key files.

Provide a user-friendly interface for non-technical users.

Demonstrate safe handling of salts, nonces, and authentication tags.

Produce a clear, maintainable, and well-structured codebase.

Ensure tamper detection through authenticated encryption.

Offer extensibility for future GUI or cloud-integration enhancements.

3. Background: Fundamentals of Encryption

To understand the tool, it is important to know a few cryptographic fundamentals:

3.1 AES (Advanced Encryption Standard)

AES is a symmetric encryption algorithm widely used in modern security systems. It comes in key sizes of 128, 192, and 256 bits.
This tool uses AES-256, offering the highest security level.

3.2 AES-GCM Mode

GCM (Galois/Counter Mode) provides:

Confidentiality (encryption)

Integrity & authenticity (authentication tag)

High performance

Nonce-based security

This makes AES-GCM ideal for secure, high-assurance applications.

3.3 Password-Based Key Derivation (PBKDF2)

Passwords alone are insecure. PBKDF2 strengthens them using:

Salt (random data)

Many iterations

A cryptographic hash function (SHA-256)

This prevents:

Rainbow-table attacks

Parallel brute-force attacks

Offline cracking

3.4 Random Key Support

For advanced users or automated systems, the tool supports:

Random 256-bit AES key generation

Base64 encoding for portability

4. System Architecture

The system is divided into four main layers:

4.1 Cryptography Layer

Handles:

Key derivation

AES-256-GCM encryption/decryption

Nonce generation

Authentication tag verification

4.2 Metadata Layer

Stores:

Magic header

Version number

Salt length + value

Nonce length + value

Associated data length + value

Ciphertext

This guarantees decryptability without external metadata.

4.3 User Interface Layer

A clean CLI with commands:

encrypt
decrypt
genkey

4.4 Error-Handling Layer

Manages:

Wrong passwords

Missing files

Invalid encrypted format

Modified or corrupted data

Incorrect key files

5. File Format Specification

Encrypted files follow a predictable structure:

Component	Size	Description
MAGIC	4 bytes	Identifies file
VERSION	1 byte	Format version
salt_len	1 byte	Length of salt
salt	variable	PBKDF2 salt
nonce_len	1 byte	AES-GCM nonce length
nonce	variable	Unique per file
ad_len	2 bytes	Length of associated data
associated_data	variable	Typically filename
ciphertext	variable	Encrypted content + tag

This makes encrypted files self-contained and portable.

6. Key Processes
6.1 Encryption Process

User provides password or key file.

If password-based, PBKDF2 derives a secure key.

A random nonce is generated.

AES-GCM encrypts the plaintext.

Associated data ensures filename integrity.

Structured header + ciphertext are saved to output file.

6.2 Decryption Process

Input file header is parsed.

Salt, nonce, associated data, and ciphertext are extracted.

Key is derived or loaded from key file.

AES-GCM decrypts content.

Authentication tag is validated.

Plaintext is output.

7. Security Rationale
Why AES-256-GCM?

Industry standard

Used by TLS 1.3, SSH, cloud providers

Provides authentication (detects modification)

Why PBKDF2?

Makes weak passwords harder to attack

Used in many security products

High iteration count delays brute-force attacks

Why random salt and nonce?

Salt prevents key reuse from password

Nonce prevents GCM mode security failures

Both improve unpredictability

Why store metadata in the file?

Self-contained file reduces user error

No need for external keys/nonce files

Easier portability

8. Threat Model
Protected Against

Offline brute-force (harder due to PBKDF2)

File tampering/modification

Replay attacks (due to nonce)

Accidental metadata loss

Rainbow-table attacks

Not Protected Against

Weak user passwords

Malware capturing decrypted files

Key exposure

Memory extraction attacks

Physical access to plaintext

9. Installation and Usage
Install Dependencies
pip install cryptography

Encrypt a File
python aes_encryptor.py encrypt myfile.pdf myfile.pdf.enc --password

Decrypt a File
python aes_encryptor.py decrypt myfile.pdf.enc myfile_decrypted.pdf --password

Generate a Key File
python aes_encryptor.py genkey secretkey.b64

Encrypt Using Key File
python aes_encryptor.py encrypt data.bin data.bin.enc --key-file secretkey.b64

10. Testing Methodology
10.1 Unit Tests Conducted

Password mismatch detection

Wrong key rejection

Correct decryption restores identical file

Tampered ciphertext triggers authentication failure

Header parsing validation

10.2 Performance Tests

Encryption speed on text, PDF, images, binaries

PBKDF2 timing under different iteration counts

10.3 Functional Tests

Nonce randomness validation

Salt uniqueness validation

Key-file correctness test

11. Error Handling

The tool displays descriptive messages for errors such as:

Incorrect password

Corrupted file

Invalid key-file

Missing metadata

Nonce mismatch

Version mismatch

This prevents user confusion and improves reliability.

12. Limitations

Non-streaming encryption (large files use more memory)

CLI only (no GUI yet)

Users must manage key-file security

PBKDF2 iteration count fixed

No key revocation or rotation system

13. Future Enhancements
Planned Improvements

GUI using Tkinter or PyQt

Streaming encryption mode

Cloud-based key vault integration

Support for multiple algorithms (ChaCha20-Poly1305)

File shredding (secure deletion)

Multi-file batch encryption

Encrypted archives (.aetzip format)

14. Conclusion

The Advanced Encryption Tool successfully implements secure, modern encryption using AES-256-GCM. Through authenticated encryption, password strengthening with PBKDF2, structured metadata, and user-friendly design, the project achieves both practical utility and educational value.

This tool demonstrates an understanding of:

Applied cryptography

Secure software design

Key management

Encryption workflows

Cybersecurity best practices

It fulfills all internship task requirements and provides a strong foundation for future improvements
