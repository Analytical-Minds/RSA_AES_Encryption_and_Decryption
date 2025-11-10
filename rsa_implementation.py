import random

# --- Primality Test (Miller-Rabin) ---

def is_prime(n, k=20):
    """
    Miller-Rabin primality test.
    K is the number of rounds (higher k means lower error probability).
    :param n:
    :param k:
    :return:
    """
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test 'k' random bases
    for _ in range(k):
        a = random.randint(2, n -2)
        x = pow(a, d, n)  # Modular exponentiation: a^d mod n

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False # n is composite

    return True # n is likely prime


def generate_large_prime(bits=1024):
    """Generates a prime number of 'bits' length."""
    while True:
        # Generate a random number with specified number of bits
        p = random.getrandbits(bits)
        # Ensure the number is odd and falls within the bit range
        p |= (1 << bits - 1) | 1 # Set highest and lowest bit (odd)
        if is_prime(p):
            return p

# --- Key Generation Functions ---

def gcd(x, y):
    """Computes the Greatest Common Divisor (GCD) using the Euclidean algorithm."""
    while y:
        x, y = y, x % y
    return x

def multiplicative_inverse(e, phi):
    """
    Computer the modular multiplicative inverse of e mod phi using Euclidean algorithm.
    This finds 'd' such that (d * e) mod phi = 1.
    :param e:
    :param phi:
    :return:
    """
    d, new_d = 0, 1
    r, new_r = phi, e
    while new_r != 0:
        quotient = r // new_r
        d, new_d = new_d, d - quotient * new_d
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise Exception("e is not invertible")
    if d < 0:
        d += phi
    return d


def generate_keys(bits=256):
    """Generates the RSA public (n, e) and private (n, d) keys."""
    # - Generate two large primes, p and q
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)

    # - Compute n (modulus) and phi (Euler's Totient function)
    n = p * q # Public modulus
    phi = (p - 1) * (q - 1) #Totient function

    # - Choose public exponent 'e'
    # 'e' must be 1 < e < phi and gcd(e, phi) = 1 (coprime)
    e = 65537 # A common, efficient choice (2^16 + 1)
    while gcd(e, phi) != 1:
        # This loop ensures e is coprime, though 65537 usually is
        e = random.randint(2**16 + 1, phi - 1)

    # - Compute private exponent 'd'
    # 'd' is the modular multiplicative inverse of e mod phi
    d = multiplicative_inverse(e, phi)

    return (n, e), (n, d)

# --- Encryption and Decryption Functions ---

def encrypt(public_key, plaintext):
    """
    Encrypts a message using the public key (n, e).
    Ciphertext C = M^e mod n
    The message must first be converted to an integer.
    :param public_key:
    :param plaintext:
    :return:
    """
    n, e = public_key
    # Convert string to integer representation
    message_int = int.from_bytes(plaintext.encode('utf-8'), 'big')

    if message_int >= n:
        raise ValueError("Message is too long for the chosen prime size.")

    # Apply modular exponentiation
    ciphertext = pow(message_int, e, n)
    return ciphertext


def decrypt(private_key, ciphertext):
    """
    Decrypts a ciphertext using the private key (n, d).
    Plaintext M = C^d mod n
    :param private_key:
    :param ciphertext:
    :return:
    """
    n, d = private_key
    # Apply modular exponentiation
    message_int = pow(ciphertext, d, n)

    # Convert integer back to string
    # Determine the required byte length (n.bit_length() + 7) // 8
    byte_length = (n.bit_length() + 7) // 8
    plaintext = message_int.to_bytes(byte_length, 'big').lstrip(b'\x00').decode('utf-8')
    return plaintext

# --- Main Execution ---

def run_rsa_demo():
    print("-" * 50)
    print("      RSA Encryption and Decryption Demo      ")
    print("-" * 50)

    # Generate keys (using 256 bits for this demo)
    public_key, private_key = generate_keys(bits=256)

    pub_n, pub_e = public_key
    priv_n, priv_d = private_key

    # Display Generated Keys with better formatting
    print("\n## Generated Keys")
    print(f"   Key Size: {pub_n.bit_length()} bits")
    print("-" * 25)
    print(f"   * Public Key (n, e):")
    print(f"     n (Modulus): **{pub_n}**")
    print(f"     e (Exponent): **{pub_e}**")
    print("\n   * Private Key (n, d):")
    print(f"     n (Modulus): **{priv_n}**")
    print(f"     d (Secret Exponent): **{priv_d}**")
    print("-" * 25)

    # Get user input
    plaintext = input("\n## Encryption Input\n   Enter the message to encrypt: ")

    # 1. Encrypt
    try:
        ciphertext = encrypt(public_key, plaintext)
    except ValueError as e:
        print(f"\nError: {e}")
        return

    # 2. Decrypt
    decrypted_message = decrypt(private_key, ciphertext)

    # Display Results with clear headings
    print("\n## Encryption & Decryption Results")
    print("-" * 40)
    print(f"   * Original Message: **{plaintext}**")
    print(f"   * Cipher Text (Integer): **{ciphertext}**")
    print(f"   * Decrypted Message: **{decrypted_message}**")
    print("-" * 40)

    # Verification
    if plaintext == decrypted_message:
        print("\nVerification: Decryption Successful. Message integrity confirmed.")
    else:
        print("\nVerification: Decryption Failed.")
    print("-" * 50)


if __name__ == "__main__":
    run_rsa_demo()

