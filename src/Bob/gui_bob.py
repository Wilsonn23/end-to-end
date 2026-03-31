import base64
import json
import socket
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

ROOT_DIR = Path(__file__).resolve().parents[2]
KEYS_DIR = ROOT_DIR / "keys"


def load_keys():
    with open(KEYS_DIR / "bob_private.pem", "rb") as f:
        private_key_bob = serialization.load_pem_private_key(f.read(), password=None)
    with open(KEYS_DIR / "alice_public.pem", "rb") as f:
        public_key_alice = serialization.load_pem_public_key(f.read())
    return private_key_bob, public_key_alice


class BobServer(threading.Thread):
    def __init__(self, port: int, private_key_bob, public_key_alice, log_cb, message_cb):
        super().__init__(daemon=True)
        self.port = port
        self.private_key_bob = private_key_bob
        self.public_key_alice = public_key_alice
        self.log_cb = log_cb
        self.message_cb = message_cb
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def log(self, text: str):
        if self.log_cb:
            self.log_cb(text)

    def handle_client(self, conn: socket.socket, addr):
        try:
            data = conn.recv(8192)
            if not data:
                self.log("[WARN] Tidak ada data diterima")
                return
            payload = json.loads(data.decode())
            pretty_payload = json.dumps(payload, indent=2)
            self.log(f"Payload masuk dari {addr}:\n{pretty_payload}")

            enc_sym_key = base64.b64decode(payload["encrypted_key"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            iv = base64.b64decode(payload["iv"])
            signature = base64.b64decode(payload["signature"])

            sym_key = self.private_key_bob.decrypt(
                enc_sym_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            message_text = plaintext.decode()
            self.log(f"[INFO] Pesan didekripsi: {message_text}")
            if self.message_cb:
                self.message_cb(message_text)

            try:
                self.public_key_alice.verify(
                    signature,
                    plaintext,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                self.log("[VERIFIED] Tanda tangan valid dari Alice")
            except Exception:
                self.log("[FAILED] Tanda tangan tidak valid")
        except Exception as exc:
            self.log(f"[ERROR] Gagal memproses pesan: {exc}")

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", self.port))
                s.listen()
                s.settimeout(0.5)
                self.log(f"Bob menunggu pesan di port {self.port}...")

                while not self._stop_event.is_set():
                    try:
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(
                        target=self.handle_client, args=(conn, addr), daemon=True
                    ).start()
        except OSError as exc:
            self.log(f"[ERROR] Tidak bisa membuka port {self.port}: {exc}")
        finally:
            self.log("Server dihentikan")


class BobApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Bob - Penerima Pesan")
        self.private_key_bob, self.public_key_alice = load_keys()

        self.server: Optional[BobServer] = None

        container = ttk.Frame(root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.LabelFrame(container, text="Kontrol")
        control_frame.pack(fill=tk.X, expand=False, pady=(0, 8))

        ttk.Label(control_frame, text="Port:").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=4)
        self.port_var = tk.IntVar(value=5000)
        ttk.Entry(control_frame, textvariable=self.port_var, width=8).grid(row=0, column=1, sticky=tk.W, pady=4)

        self.start_btn = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_btn.grid(row=0, column=2, padx=(12, 4), pady=4)

        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=(4, 4), pady=4)

        status_frame = ttk.LabelFrame(container, text="Status Pesan Terakhir")
        status_frame.pack(fill=tk.X, expand=False, pady=(0, 8))

        self.last_message_var = tk.StringVar(value="- belum ada pesan -")
        ttk.Label(status_frame, textvariable=self.last_message_var, wraplength=500, justify=tk.LEFT).pack(
            fill=tk.X, expand=True, padx=8, pady=6
        )

        log_frame = ttk.LabelFrame(container, text="Log")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_box = scrolledtext.ScrolledText(log_frame, height=14, state=tk.DISABLED, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def append_log(self, text: str):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def set_last_message(self, message: str):
        self.last_message_var.set(message)

    def start_server(self):
        if self.server and self.server.is_alive():
            messagebox.showinfo("Info", "Server sudah berjalan")
            return

        port_value = self.port_var.get()
        try:
            port_int = int(port_value)
        except ValueError:
            messagebox.showerror("Error", "Port harus berupa angka")
            return
        if port_int <= 0 or port_int > 65535:
            messagebox.showerror("Error", "Port harus di antara 1-65535")
            return

        self.server = BobServer(
            port_int,
            self.private_key_bob,
            self.public_key_alice,
            self.append_log,
            self.set_last_message,
        )
        self.server.start()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.append_log(f"[INFO] Server mulai di port {port_int}")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server.join(timeout=1.5)
            self.server = None
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.append_log("[INFO] Server diminta berhenti")

    def on_close(self):
        self.stop_server()
        self.root.destroy()


def main():
    root = tk.Tk()
    BobApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
