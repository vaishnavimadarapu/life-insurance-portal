import random
import os
import secrets

# Modular exponentiation
def power(a, b, m):
    res = 1
    a %= m
    while b > 0:
        if b % 2 == 1:
            res = (res * a) % m
        a = (a * a) % m
        b //= 2
    return res

# Modular inverse using Fermat's Little Theorem (requires m to be prime)
def modInverse(n, m):
    return power(n, m - 2, m)

# Simple primality test (Miller-Rabin)
def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = power(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=16):
    while True:
        p = secrets.randbits(bits)
        if p % 2 != 0 and is_prime(p):
            return p

def generate_keys():
    # Using 16-bit for demo visibility, 256 or more for security
    p = generate_prime(16)
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2) # Private key
    h = power(g, x, p) # Public key
    
    public_key = (p, g, h)
    private_key = (p, g, x)
    return public_key, private_key

def encrypt_message(message, public_key):
    p, g, h = public_key
    cipher_pairs = []
    for char in message:
        m = ord(char)
        k = random.randint(2, p - 2)
        c1 = power(g, k, p)
        c2 = (m * power(h, k, p)) % p
        cipher_pairs.append((c1, c2))
    return cipher_pairs

def decrypt_message(cipher_pairs, private_key):
    p, g, x = private_key
    plaintext = ""
    for c1, c2 in cipher_pairs:
        s = power(c1, x, p)
        m = (c2 * modInverse(s, p)) % p
        plaintext += chr(m)
    return plaintext

def encrypt_file(input_path, output_path, public_key):
    with open(input_path, 'rb') as f:
        data = f.read()
    
    p, g, h = public_key
    encrypted_data = []
    for byte in data:
        k = random.randint(2, p - 2)
        c1 = power(g, k, p)
        c2 = (byte * power(h, k, p)) % p
        encrypted_data.append(f"{c1},{c2}")
    
    with open(output_path, 'w') as f:
        f.write("\n".join(encrypted_data))

def decrypt_file(input_path, output_path, private_key):
    with open(input_path, 'r') as f:
        lines = f.readlines()
    
    p, g, x = private_key
    decrypted_bytes = bytearray()
    for line in lines:
        if not line.strip(): continue
        c1, c2 = map(int, line.strip().split(','))
        s = power(c1, x, p)
        m = (c2 * modInverse(s, p)) % p
        decrypted_bytes.append(m)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_bytes)

if __name__ == "__main__":
    # Test
    pub, priv = generate_keys()
    msg = "Hello ElGamal!"
    enc = encrypt_message(msg, pub)
    dec = decrypt_message(enc, priv)
    print(f"Original: {msg}")
    print(f"Decrypted: {dec}")
