#!/usr/bin/env python3
"""AES-256-Dateiverschlüsselung mit GCM, PBKDF2-Schlüsselableitung,
Fortschrittsanzeige und Fehlerbehandlung."""

import getpass
import os
import sys
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Sichere Standardparameter
KEY_LENGTH = 32            # 256 Bit fuer AES-256
SALT_LENGTH = 16           # 128 Bit Salt
NONCE_LENGTH = 12          # 96 Bit Nonce (Empfehlung fuer GCM)
KDF_ITERATIONS = 600_000   # Iterationen fuer PBKDF2-HMAC-SHA256
MAGIC = b"AESGCM1"         # Formatkennung am Dateianfang
CHUNK_SIZE = 1024 * 1024   # 1 MiB Bloecke fuer die Fortschrittsanzeige


class CryptoError(Exception):
    """Fehler bei der Ver- oder Entschluesselung."""


def get_passphrase(confirm: bool) -> str:
    """Passwort sicher vom Benutzer abfragen."""
    while True:
        pw = getpass.getpass("Passwort: ")
        if not pw:
            print("Ein leeres Passwort ist nicht erlaubt.", file=sys.stderr)
            continue
        if confirm:
            pw2 = getpass.getpass("Passwort wiederholen: ")
            if pw != pw2:
                print("Die Passwoerter stimmen nicht ueberein.", file=sys.stderr)
                continue
        return pw


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Leitet einen 256-Bit-Schluessel aus dem Passwort ab (PBKDF2-HMAC-SHA256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _progress(action: str, done: int, total: int, last_pct: int) -> int:
    """Zeigt einen einfachen Text-Fortschrittsbalken an.
    Gibt den zuletzt angezeigten Prozentwert zurueck, um
    Wiederholungen zu vermeiden."""
    if total <= 0:
        return last_pct
    pct = min(done * 100 // total, 100)
    if pct == last_pct:
        return last_pct
    bar_len = 30
    filled = bar_len * pct // 100
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\r{action}: [{bar}] {pct:>3d}% ")
    sys.stdout.flush()
    return pct


def _finish_progress(action: str, last_pct: int) -> None:
    """Schliesst die Fortschrittsanzeige mit Zeilenumbruch ab."""
    if last_pct >= 0:
        sys.stdout.write("\n")
        sys.stdout.flush()


ProgressCallback = Optional[Callable[[int, int], None]]


def _read_with_progress(f, action: str, total: int, on_progress: ProgressCallback = None) -> bytes:
    """Liest die Datei in Bloecken und zeigt dabei den Fortschritt an.
    'on_progress(done_bytes, total_bytes)' ist ein optionaler Callback
    (z. B. fuer eine GUI-Fortschrittsanzeige)."""
    data = bytearray()
    done = 0
    last_pct = -1
    while True:
        chunk = f.read(CHUNK_SIZE)
        if not chunk:
            break
        data.extend(chunk)
        done += len(chunk)
        last_pct = _progress(action, done, total, last_pct)
        if on_progress is not None:
            on_progress(done, total)
    _finish_progress(action, last_pct)
    return bytes(data)


def encrypt_file(src: Path, dst: Path, password: str, on_progress: ProgressCallback = None) -> None:
    """Verschluesselt 'src' mit AES-256-GCM und schreibt das Ergebnis nach 'dst'.
    'on_progress(done_bytes, total_bytes)' ist ein optionaler Callback."""
    if not src.is_file():
        raise CryptoError(f"Die Quelldatei existiert nicht: {src}")
    if dst.exists():
        raise CryptoError(f"Die Zieldatei existiert bereits: {dst}")

    total = src.stat().st_size
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    with src.open("rb") as f:
        plaintext = _read_with_progress(f, "Verschluesselung", total, on_progress)

    # GCM authentifiziert die gesamten Daten in einem Stück.
    ciphertext = aesgcm.encrypt(nonce, plaintext, MAGIC)

    with dst.open("wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(src: Path, dst: Path, password: str, on_progress: ProgressCallback = None) -> None:
    """Entschluesselt eine mit encrypt_file() erzeugte Datei nach 'dst'.
    'on_progress(done_bytes, total_bytes)' ist ein optionaler Callback."""
    if not src.is_file():
        raise CryptoError(f"Die Quelldatei existiert nicht: {src}")
    if dst.exists():
        raise CryptoError(f"Die Zieldatei existiert bereits: {dst}")

    header_overhead = len(MAGIC) + SALT_LENGTH + NONCE_LENGTH
    total = max(src.stat().st_size - header_overhead, 0)
    with src.open("rb") as f:
        header = f.read(len(MAGIC))
        if header != MAGIC:
            raise CryptoError(
                "Keine gueltige Verschluesselungsdatei (falsches Format)."
            )
        salt = f.read(SALT_LENGTH)
        nonce = f.read(NONCE_LENGTH)
        if len(salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH:
            raise CryptoError("Die Datei ist beschaedigt (Header zu kurz).")
        ciphertext = _read_with_progress(f, "Entschluesselung", total, on_progress)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, MAGIC)
    except Exception:
        raise CryptoError(
            "Falsches Passwort oder die Datei wurde manipuliert."
        )

    with dst.open("wb") as f:
        f.write(plaintext)


def parse_args(argv):
    if len(argv) != 3:
        return None
    mode, path = argv[1], argv[2]
    if mode in ("-e", "--encrypt"):
        return ("encrypt", Path(path))
    if mode in ("-d", "--decrypt"):
        return ("decrypt", Path(path))
    return None


def usage():
    print(
        "Verwendung:\n"
        "  python3 aes_file_crypto.py -e  <datei>   Verschluesseln\n"
        "  python3 aes_file_crypto.py -d  <datei>   Entschluesseln\n",
        file=sys.stderr,
    )


def main(argv) -> int:
    args = parse_args(argv)
    if args is None:
        usage()
        return 2

    mode, src = args
    try:
        src = src.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        print(f"Fehler beim Aufloesen des Pfads: {exc}", file=sys.stderr)
        return 1

    if mode == "encrypt":
        dst = src.with_suffix(src.suffix + ".enc")
        try:
            password = get_passphrase(confirm=True)
        except (EOFError, KeyboardInterrupt):
            print("\nAbgebrochen.", file=sys.stderr)
            return 130
        try:
            encrypt_file(src, dst, password)
        except CryptoError as exc:
            print(f"Fehler: {exc}", file=sys.stderr)
            return 1
        print(f"Fertig: {dst}")
        return 0

    # decrypt
    dst = src.with_suffix("") if src.suffix == ".enc" else src.with_suffix(".dec")
    try:
        password = get_passphrase(confirm=False)
    except (EOFError, KeyboardInterrupt):
        print("\nAbgebrochen.", file=sys.stderr)
        return 130
    try:
        decrypt_file(src, dst, password)
    except CryptoError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    print(f"Fertig: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
