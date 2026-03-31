from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

ROOT_DIR = Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT_DIR / "keys"

def generate_keys(name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEYS_DIR / f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(KEYS_DIR / f"{name}_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

generate_keys("alice")

