import socket
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Konfigurasi
PORT = 5000
ROOT_DIR = Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT_DIR / "keys"

# 1. Load Keys (absolute path so cwd does not matter)
with open(KEYS_DIR / "bob_private.pem", "rb") as f:
    private_key_bob = serialization.load_pem_private_key(f.read(), password=None)
with open(KEYS_DIR / "alice_public.pem", "rb") as f:
    public_key_alice = serialization.load_pem_public_key(f.read())

def start_bob():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', PORT)) # Mendengarkan di semua interface [cite: 75]
        s.listen()
        print(f"Bob menunggu pesan di port {PORT}...", flush=True)
        conn, addr = s.accept()
        with conn:
            print(f"Terhubung dengan IP Alice: {addr}", flush=True)
            try:
                data = conn.recv(8192)
                print(f"[DEBUG] Bytes diterima: {len(data)}", flush=True)
                payload = json.loads(data.decode())
                print("[DEBUG] Payload keys: " + ", ".join(payload.keys()), flush=True)
                pretty_payload = json.dumps(payload, indent=2)
                print(f"[DEBUG] Payload JSON:\n{pretty_payload}", flush=True)

                # Dekode Base64
                enc_sym_key = base64.b64decode(payload['encrypted_key'])
                ciphertext = base64.b64decode(payload['ciphertext'])
                iv = base64.b64decode(payload['iv'])
                signature = base64.b64decode(payload['signature'])

                # 2. Dekripsi Kunci Simetris [cite: 60, 139]
                sym_key = private_key_bob.decrypt(
                    enc_sym_key,
                    asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print("[DEBUG] Kunci simetris didekripsi", flush=True)

                # 3. Dekripsi Pesan [cite: 61, 140]
                cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = sym_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                
                print(f"\nPesan Diterima: {plaintext.decode()}", flush=True)

                # 4. Verifikasi Digital Signature [cite: 63, 142]
                try:
                    public_key_alice.verify(
                        signature, plaintext,
                        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    print("Hasil: [VERIFIED] Pesan asli dari Alice dan belum diubah.", flush=True)
                except Exception:
                    print("Hasil: [FAILED] Tanda tangan tidak valid!", flush=True)
            except Exception as exc:
                print(f"[ERROR] Gagal memproses pesan: {exc}", flush=True)

if __name__ == "__main__":
    start_bob()