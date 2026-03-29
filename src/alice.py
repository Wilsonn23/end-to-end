import socket
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Konfigurasi
BOB_IP = '10.129.119.120' # GANTI DENGAN IP BOB
PORT = 5000

# 1. Load Keys
with open("../keys/alice_private.pem", "rb") as f:
    private_key_alice = serialization.load_pem_private_key(f.read(), password=None)
with open("../keys/bob_public.pem", "rb") as f:
    public_key_bob = serialization.load_pem_public_key(f.read())

# 2. Menyiapkan Plaintext [cite: 41, 81, 82]
plaintext = b"Halo Bob, ini adalah pesan rahasia yang sangat aman."

# 3. Enkripsi Simetris (AES-256) [cite: 42, 43, 86]
sym_key = os.urandom(32) 
iv = os.urandom(16)
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()
cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# 4. Enkripsi Kunci Simetris dengan Public Key Bob [cite: 44, 87]
encrypted_sym_key = public_key_bob.encrypt(
    sym_key,
    asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# 5. Digital Signature (Sign Plaintext) [cite: 45, 46, 88, 89]
signature = private_key_alice.sign(
    plaintext,
    asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# 6. Kirim Payload JSON [cite: 47, 48, 83, 109]
payload = {
    'ciphertext': base64.b64encode(ciphertext).decode(),
    'encrypted_key': base64.b64encode(encrypted_sym_key).decode(),
    'iv': base64.b64encode(iv).decode(),
    'signature': base64.b64encode(signature).decode()
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((BOB_IP, PORT))
    s.sendall(json.dumps(payload).encode())
    print("Pesan telah dikirim ke Bob.")