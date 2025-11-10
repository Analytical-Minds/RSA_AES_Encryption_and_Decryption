# 🔒 Cryptography Implementation Project: RSA & AES

This project implements two fundamental cryptographic algorithms—**RSA (Asymmetric)** and **AES (Symmetric)**—in Python. It serves as a practical demonstration of public-key and private-key encryption methods, including key generation, encryption, and decryption processes.

## 🚀 Project Overview

The project consists of two separate Python scripts:

1.  **`rsa_implementation.py`**: Demonstrates the RSA public-key cryptosystem, which is primarily used for secure key exchange and digital signatures. It relies on the mathematical difficulty of factoring large composite numbers.
2.  **`aes_implementation.py`**: Demonstrates the AES symmetric-key algorithm in **Cipher Block Chaining (CBC) mode**. AES is the current standard for fast, bulk data encryption.

## 🛠️ Setup and Installation

### Prerequisites

* Python 3.x

### Installation

The AES implementation requires the `pycryptodome` library. Install it using pip:

```bash
pip install pycryptodome
