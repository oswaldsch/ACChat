from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import hashlib

def deserialize_public_key(public_key_raw: bytes):
    return Ed25519PublicKey.from_public_bytes(public_key_raw)

def serialize_public_key(public_key: Ed25519PublicKey):
    return public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def generate_sid(public_key_raw: bytes):
    return hashlib.sha256(public_key_raw).digest()[:12]

def sign_data(data: bytes, private_key: Ed25519PrivateKey):
    return private_key.sign(data)

def check_signature(data: bytes, signature: bytes, public_key: Ed25519PublicKey):
    if len(signature) != 64:
        return False
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False

def generate_keys():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key
