# RSA_AES_Encryption_and_Decryption

CYB 301 - by Analytical Minds

A Python project to demonstrate the implementation and usage of two industry-standard cryptographic systems:
- **RSA** (asymmetric encryption)
- **AES** (symmetric encryption)

This repository provides clean, commented, and fully functional code for both RSA and AES encryption/decryption, suitable for security students and enthusiasts.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Install Requirements](#install-requirements)
- [RSA: Public-Key Cryptography](#rsa-public-key-cryptography)
  - [How RSA Works](#how-rsa-works)
  - [Code Walkthrough: `rsa_implementation.py`](#code-walkthrough-rsa_implementationpy)
- [AES: Symmetric-Key Cryptography](#aes-symmetric-key-cryptography)
  - [How AES Works](#how-aes-works)
  - [Code Walkthrough: `aes_implementation.py`](#code-walkthrough-aes_implementationpy)
- [Usage](#usage)
- [Credits](#credits)

---

## Project Overview

This project showcases:
- How to generate RSA keys, encrypt and decrypt messages with RSA.
- How to generate AES keys, encrypt and decrypt messages with AES.
- Code is written in pure Python, no external command-line tools needed.

---

## Install Requirements

Install dependencies (Requires Python 3.x):

```bash
pip install pycryptodome
```

---

## RSA: Public-Key Cryptography

### How RSA Works

**RSA** is an asymmetric (public-key) encryption algorithm:
- Uses two mathematically linked keys: **public** (shareable) and **private** (secret).
- Public key: `(n, e)` is used for **encryption**
- Private key: `(n, d)` is used for **decryption**
- Security is based on the difficulty of factoring large prime numbers.

---

### Code Walkthrough: `rsa_implementation.py`
[View source](https://github.com/Analytical-Minds/RSA_AES_Encryption_and_Decryption/blob/main/rsa_implementation.py)

- **Prime Generation (`generate_large_prime`)**: Uses the Miller-Rabin test (`is_prime`) for probabilistic primality checking and generates primes for RSA.
- **Key Generation (`generate_keys`)**: 
  - Picks two large random primes (`p`, `q`).
  - Computes modulus `n = p * q` and Euler's totient `phi = (p-1)*(q-1)`.
  - Chooses public exponent `e` (default: 65537, standard safe value).
  - Calculates private exponent `d` as the modular inverse of `e mod phi`.
- **Encryption (`encrypt`)**:
  - Converts your message to an integer.
  - Applies modular exponentiation: `C = M^e mod n` to get the ciphertext.
- **Decryption (`decrypt`)**:
  - Uses private key to compute `M = C^d mod n` (reverses encryption).
  - Converts the integer back into the original UTF-8 string.

- **Demo (`run_rsa_demo`)**: Runs the full encryption-decryption cycle, asks user for input, and displays all steps and results.

---

## AES: Symmetric-Key Cryptography

### How AES Works

**AES** is a symmetric cipher, which means the same key is used for both encryption and decryption.
- Data is encrypted in fixed-size blocks (typically 16 bytes for AES-128).
- The mode used is **CBC (Cipher Block Chaining)**, which requires an additional randomly generated **IV** (Initialization Vector) for each encryption session.

---

### Code Walkthrough: `aes_implementation.py`
[View source](https://github.com/Analytical-Minds/RSA_AES_Encryption_and_Decryption/blob/main/aes_implementation.py)

- **Key Generation (`generate_aes_key`)**: Uses cryptographically secure random bytes to create a 128-bit key.
- **Encryption (`encrypt_aes`)**:
  - AES cipher is set up in CBC mode with a random IV.
  - Pads the plaintext to a full 16-byte block.
  - Encrypts the message, prepends the IV to the ciphertext, and returns the result as a base64-encoded string.
- **Decryption (`decrypt_aes`)**:
  - Decodes base64 message, separates the IV and ciphertext.
  - Decrypts and unpads the message, returning the original string.
- **Demo (`run_aes_demo`)**: User is prompted for a message, which is encrypted and decrypted, displaying all intermediate info (key, ciphertext, decrypted text).

---

## Usage

**Run the RSA demo:**

```bash
python rsa_implementation.py
```

**Run the AES demo:**

```bash
python aes_implementation.py
```

You will be prompted to enter a message, and the scripts will perform encryption and decryption, outputting all values step-by-step.

---

## Credits

- Developed by Analytical Minds for CYB 301.
- Utilizes [PyCryptodome](https://www.pycryptodome.org/) for secure cryptographic primitives.
