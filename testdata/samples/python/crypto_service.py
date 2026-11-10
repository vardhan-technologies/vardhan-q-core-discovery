import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def generate_legacy_keys():
    # Quantum-vulnerable RSA
    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Quantum-vulnerable ECDSA
    ec_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ec_key

def insecure_checksum(payload: bytes):
    # Weak classical MD5
    return hashlib.md5(payload).hexdigest()
