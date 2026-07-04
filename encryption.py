from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# AES Encryption & Decryption
def generate_aes_key():
    return get_random_bytes(16)  # AES requires a 16-byte key

def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(cipher_text, key):
    raw = base64.b64decode(cipher_text)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# DES Encryption & Decryption
def generate_des_key():
    return get_random_bytes(8)  # DES requires an 8-byte key

def des_encrypt(plain_text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def des_decrypt(cipher_text, key):
    raw = base64.b64decode(cipher_text)
    iv = raw[:DES.block_size]
    ct = raw[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode()

# RSA Key Generation, Encryption & Decryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(plain_text, public_key):
    cipher_text = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(cipher_text).decode()

def rsa_decrypt(cipher_text, private_key):
    decrypted_text = private_key.decrypt(
        base64.b64decode(cipher_text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode()

# Main function
def main():
    print("===== Secure Encryption Program =====")
    print("Choose encryption method:")
    print("1. AES (Advanced Encryption Standard)")
    print("2. DES (Data Encryption Standard)")
    print("3. RSA (Rivest-Shamir-Adleman)")
    
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        key = generate_aes_key()
        text = input("\nEnter text to encrypt with AES: ")
        encrypted = aes_encrypt(text, key)
        decrypted = aes_decrypt(encrypted, key)
        print("\nAES Encrypted:", encrypted)
        print("AES Decrypted:", decrypted)

    elif choice == "2":
        key = generate_des_key()
        text = input("\nEnter text to encrypt with DES: ")
        encrypted = des_encrypt(text, key)
        decrypted = des_decrypt(encrypted, key)
        print("\nDES Encrypted:", encrypted)
        print("DES Decrypted:", decrypted)

    elif choice == "3":
        private_key, public_key = generate_rsa_keys()
        text = input("\nEnter text to encrypt with RSA: ")
        encrypted = rsa_encrypt(text, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        print("\nRSA Encrypted:", encrypted)
        print("RSA Decrypted:", decrypted)

    else:
        print("Invalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()

