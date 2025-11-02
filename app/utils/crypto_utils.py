from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

def encrypt_message(plaintext: str, key: bytes) -> dict:
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)
    return {"ciphertext": ciphertext.hex(), "nonce": nonce.hex()}

def decrypt_message(ciphertext_hex: str, nonce_hex: str, key: bytes) -> str:
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
