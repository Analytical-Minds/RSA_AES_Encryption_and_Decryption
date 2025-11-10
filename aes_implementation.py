from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# --- Constants ---
# AES-128 uses a 16-byte (128-bit) key
KEY_SIZE = 16

# --- Encryption and Decryption Functions ---

def generate_aes_key():
    """Generates a random, cryptographically secure 16-byte AES key."""
    return get_random_bytes(KEY_SIZE)

def encrypt_aes(key, plaintext):
    """Encrypts the plaintext using AES in CBC mode."""
    #. Create a new cipher object using the key and the CBC mode
    # The cipher automatically generate a new, random IV
    cipher = AES.new(key, AES.MODE_CBC)

    #. Pad the message
    # AES operates on the fixed-size blocks (16 bytes). The message must be padded
    # to be an exact multiple of the block size.
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)

    #. Encrypt the data
    ciphertext = cipher.encrypt(padded_data)

    # The IV is crucial for decryption, so we prepend it to the ciphertext
    # and encode the entire result using Base64 for safe transmission/display.
    encoded_ciphertext = base64.b64encode(cipher.iv + ciphertext)

    # Return the Base64-encoded ciphertext (IV + encrypted data)
    return encoded_ciphertext

def decrypt_aes(key, encoded_ciphertext):
    """Decrypts the ciphertext using AES key in CBC mode."""
    #. Decode from Base64
    raw = base64.b64decode(encoded_ciphertext)

    #. Separate the IV (first 16 bytes) and the actual ciphertext
    iv = raw[:AES.block_size] # Get the IV from the start
    ciphertext = raw[AES.block_size:] # The rest is the ciphertext

    #. Create a new cipher object using the key, CBC mode, and the retrieved IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    #. Decrypt the data
    decrypted_padded_data = cipher.decrypt(ciphertext)

    #. Unpad the message
    # Remove the padding to get the original plaintext bytes
    plaintext_bytes = unpad(decrypted_padded_data, AES.block_size)

    #. Decode back to a string
    return plaintext_bytes.decode('utf-8')


# --- Main Execution ---
def run_aes_demo():
    print("\n" + "=" * 50)
    print("      AES Symmetric Encryption Demo (CBC Mode)      ")
    print("=" * 50)

    # 1. Get user input
    original_message = input("\n## Encryption Input\n   Enter the message to encrypt (AES): ")

    # 2. Generate Key
    key = generate_aes_key()

    # Display Key
    key_b64 = base64.b64encode(key).decode('utf-8')
    print("\n## Generated Key")
    print("-" * 30)
    print(f"   * AES Key (128-bit, Base64): **{key_b64}**")
    print("-" * 30)

    # 3. Encrypt
    encrypted_message_b64 = encrypt_aes(key, original_message).decode('utf-8')

    # 4. Decrypt
    decrypted_message = decrypt_aes(key, encrypted_message_b64)

    # Display Results
    print("\n## Encryption & Decryption Results")
    print("-" * 40)
    print(f"   * Original Message: **{original_message}**")
    print(f"   * Cipher Text (IV + Data, Base64): **{encrypted_message_b64}**")
    print(f"   * Decrypted Message: **{decrypted_message}**")
    print("-" * 40)

    # Verification
    if original_message == decrypted_message:
        print("\nVerification: Decryption Successful. Message integrity confirmed.")
    else:
        print("\nVerification: Decryption Failed.")
    print("=" * 50)


if __name__ == "__main__":
    run_aes_demo()