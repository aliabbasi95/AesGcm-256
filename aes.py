import hashlib
import os
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def create_key(passphrase: str, salt: bytes = None) -> [str, bytes]:
    if salt is None:
        salt = os.urandom(8)
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000), salt


def encrypt(passphrase: str, plaintext: str, entry_aad: bytes) -> str:
    key, salt = create_key(passphrase)
    aes = AESGCM(key)
    iv = os.urandom(12)
    entry_aad = entry_aad
    aad = b"entry_aad"
    plaintext = plaintext.encode("utf8")
    cipher_text = aes.encrypt(iv, plaintext, aad)
    return "%s-%s-%s" % (hexlify(salt).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(cipher_text).decode("utf8"))


def decrypt(passphrase: str, cipher_text: str, entry_aad: bytes) -> str:

    salt, iv, cipher_text = map(unhexlify, cipher_text.split("-"))
    key, _ = create_key(passphrase, salt)
    aes = AESGCM(key)
    entry_aad = entry_aad
    aad = b"entry_aad"
    plaintext = aes.decrypt(iv, cipher_text, aad)
    return plaintext.decode("utf8")
