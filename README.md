# End-to-End Alice ⇆ Bob

Demo sederhana enkripsi hibrid (RSA + AES) dan tanda tangan digital antara Alice dan Bob.

## Struktur
- src/Bob/bob.py — penerima pesan, mendekripsi dan verifikasi signature
- src/Alice/alice.py — pengirim pesan, kini pesan diambil dari input pengguna
- src/main.py — runner praktis untuk menyalakan Bob lalu Alice
- keys/ — simpan kunci RSA (alice_private.pem, alice_public.pem, bob_private.pem, bob_public.pem)

## Prasyarat
- Python 3.10+
- Paket `cryptography` terpasang (`pip install cryptography`)
- Folder `keys/` berisi pasangan kunci RSA yang cocok (lihat script key_gen_* di masing-masing folder jika tersedia)

## Cara Menjalankan

### Opsi cepat: langsung script terpisah
1) Terminal 1 (Bob):
	```bash
	python src/Bob/bob.py
	```
2) Terminal 2 (Alice):
	```bash
	python src/Alice/alice.py
	```
	Ketik pesan saat diminta, lalu Enter.

### Opsi terorkestrasi: via main.py
- Jalankan Bob saja: `python src/main.py --bob` / `python src/Bob/bob.py`
- Jalankan Alice saja: `python src/main.py --alice` / `python src/Alice/alice.py`
- Jalankan berurutan (Bob lalu Alice): `python src/main.py --all`

Catatan: Saat memakai `--alice` atau `--all`, prompt input pesan mungkin tidak tampil jelas karena output ditangkap; tetap bisa ketik pesan lalu Enter.

## Perilaku
- Alice mengenkripsi pesan dengan AES-256 (kunci acak), kunci simetris dienkripsi RSA-OAEP memakai public key Bob.
- Plaintext ditandatangani PSS + SHA-256 memakai private key Alice.
- Bob mendekripsi, menghapus padding, menampilkan plaintext, lalu memverifikasi signature.