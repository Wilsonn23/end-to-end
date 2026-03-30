import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BOB_SCRIPT = SCRIPT_DIR / "Bob" / "bob.py"
ALICE_SCRIPT = SCRIPT_DIR / "Alice" / "alice.py"


def run_bob_process(timeout: float = 10.0) -> subprocess.Popen:
    print("[main] Menjalankan Bob...")
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, str(BOB_SCRIPT)],
        cwd=SCRIPT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    start_at = time.time()
    ready = False

    while time.time() - start_at < timeout:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        print(f"[Bob] {line.rstrip()}")
        if "Bob menunggu pesan di port" in line:
            ready = True
            break

    if not ready:
        print("[main] Peringatan: Bob kemungkinan belum siap, melanjutkan eksekusi.")

    return proc


def run_alice() -> int:
    print("[main] Menjalankan Alice...")
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    result = subprocess.run(
        [sys.executable, str(ALICE_SCRIPT)],
        cwd=SCRIPT_DIR,
        capture_output=True,
        text=True,
        env=env,
    )

    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)

    return result.returncode


def shutdown_process(proc: subprocess.Popen) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    stdout, stderr = proc.communicate(timeout=2)
    if stdout:
        print(stdout.rstrip())
    if stderr:
        print(stderr.rstrip(), file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Otomasi Alice + Bob")
    parser.add_argument("--bob", action="store_true", help="Jalankan Bob saja")
    parser.add_argument("--alice", action="store_true", help="Jalankan Alice saja")
    parser.add_argument("--all", action="store_true", help="Jalankan Bob lalu Alice")
    args = parser.parse_args()

    if not any((args.bob, args.alice, args.all)):
        args.all = True

    bob_proc = None
    exit_code = 0

    try:
        if args.bob or args.all:
            bob_proc = run_bob_process()
            if args.bob:
                if bob_proc:
                    bob_proc.wait()
                return 0

        if args.alice or args.all:
            code = run_alice()
            if code != 0:
                print(f"[main] Alice mengembalikan kode keluar {code}", file=sys.stderr)
                exit_code = code

            # Beri waktu Bob menyelesaikan dekripsi & verifikasi
            if bob_proc is not None:
                try:
                    bob_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

    finally:
        if args.all and bob_proc is not None:
            shutdown_process(bob_proc)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())