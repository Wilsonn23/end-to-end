import base64
import json
import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

ROOT_DIR = Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT_DIR / "keys"
DEFAULT_MESSAGE = "Halo Bob, ini adalah pesan rahasia yang sangat aman."


def load_keys():
    with open(KEYS_DIR / "alice_private.pem", "rb") as f:
        private_key_alice = serialization.load_pem_private_key(f.read(), password=None)
    with open(KEYS_DIR / "bob_public.pem", "rb") as f:
        public_key_bob = serialization.load_pem_public_key(f.read())
    return private_key_alice, public_key_bob


def encrypt_and_send(ip: str, port: int, message: str, private_key_alice, public_key_bob):
    plaintext = message.encode()

    # AES-256-CBC untuk payload
    sym_key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # RSA-OAEP untuk kunci simetris
    encrypted_sym_key = public_key_bob.encrypt(
        sym_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # Signature PSS atas plaintext
    signature = private_key_alice.sign(
        plaintext,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    payload = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_sym_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "signature": base64.b64encode(signature).decode(),
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.sendall(json.dumps(payload).encode())


class AliceApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Alice - Pengirim Pesan")
        self.private_key_alice, self.public_key_bob = load_keys()

        self.ip_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.IntVar(value=5000)

        container = ttk.Frame(root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        # Target section
        target_frame = ttk.LabelFrame(container, text="Tujuan")
        target_frame.pack(fill=tk.X, expand=False, pady=(0, 8))

        ttk.Label(target_frame, text="IP Bob:").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=4)
        ttk.Entry(target_frame, textvariable=self.ip_var, width=18).grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(target_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(12, 4), pady=4)
        ttk.Entry(target_frame, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky=tk.W, pady=4)

        # Message section
        msg_frame = ttk.LabelFrame(container, text="Pesan")
        msg_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self.message_box = scrolledtext.ScrolledText(msg_frame, height=6, wrap=tk.WORD)
        self.message_box.insert("1.0", DEFAULT_MESSAGE)
        self.message_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Action buttons
        action_frame = ttk.Frame(container)
        action_frame.pack(fill=tk.X, expand=False)

        self.send_btn = ttk.Button(action_frame, text="Kirim", command=self.on_send)
        self.send_btn.pack(side=tk.LEFT)

        # Log area
        log_frame = ttk.LabelFrame(container, text="Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.log_box = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def append_log(self, text: str):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def on_send(self):
        ip = self.ip_var.get().strip()
        message = self.message_box.get("1.0", tk.END).strip()
        port = self.port_var.get()

        if not ip:
            messagebox.showerror("Error", "IP Bob tidak boleh kosong")
            return
        try:
            port_int = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port harus berupa angka")
            return
        if port_int <= 0 or port_int > 65535:
            messagebox.showerror("Error", "Port harus di antara 1-65535")
            return

        if not message:
            message = DEFAULT_MESSAGE

        self.append_log(f"[INFO] Mengirim ke {ip}:{port_int}...")
        self.send_btn.configure(state=tk.DISABLED)

        def worker():
            try:
                encrypt_and_send(ip, port_int, message, self.private_key_alice, self.public_key_bob)
                self.append_log("[OK] Pesan terkirim")
            except Exception as exc:
                self.append_log(f"[ERROR] Gagal mengirim: {exc}")
            finally:
                self.send_btn.configure(state=tk.NORMAL)

        threading.Thread(target=worker, daemon=True).start()


def main():
    root = tk.Tk()
    AliceApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
