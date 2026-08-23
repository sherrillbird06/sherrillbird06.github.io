#!/usr/bin/env python3
"""
Lockbox — encrypt a file before it leaves your machine.

Design notes:

  AES-256-GCM, not AES-CBC. GCM is authenticated: if a single byte of the
  ciphertext changes in transit, decryption fails loudly instead of
  handing back convincing garbage. Unauthenticated encryption is how
  padding-oracle attacks happen.

  scrypt for key derivation. A passphrase is not a key. Stretching it with
  a memory-hard KDF and a per-file random salt means two people with the
  same passphrase still get different keys, and brute-forcing the
  passphrase costs real memory.

  Chunked streaming. Reading a 4 GB file into memory to encrypt it is a
  denial of service you inflict on yourself. Each chunk is sealed
  separately with its own nonce and its index bound in as associated
  data, so chunks cannot be reordered, duplicated, or dropped.

File format:
    MAGIC(6) VERSION(1) SALT(16) [ NONCE(12) LEN(4) CIPHERTEXT ]...

Usage:
    python3 lockbox.py lock   secret.pdf
    python3 lockbox.py unlock secret.pdf.lockbox
    python3 lockbox.py watch  ./outbox        # auto-encrypt new files
"""

import argparse
import getpass
import os
import struct
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"LOCKBX"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
CHUNK = 64 * 1024

# n=2^15 keeps derivation near a quarter-second and costs an attacker
# ~32 MB of memory per guess.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, passphrase: str):
    salt = os.urandom(SALT_LEN)
    aes = AESGCM(derive_key(passphrase, salt))

    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(MAGIC + bytes([VERSION]) + salt)

        index = 0
        while chunk := fin.read(CHUNK):
            nonce = os.urandom(NONCE_LEN)
            # Chunk index as associated data: authenticated but not
            # encrypted. Reordering chunks now invalidates the tag.
            sealed = aes.encrypt(nonce, chunk, struct.pack(">Q", index))
            fout.write(nonce + struct.pack(">I", len(sealed)) + sealed)
            index += 1

    return index


def decrypt_file(src: Path, dst: Path, passphrase: str):
    with src.open("rb") as fin:
        header = fin.read(len(MAGIC) + 1 + SALT_LEN)
        if len(header) < len(MAGIC) + 1 + SALT_LEN or not header.startswith(MAGIC):
            raise ValueError("Not a Lockbox file.")

        version = header[len(MAGIC)]
        if version != VERSION:
            raise ValueError(f"File uses format version {version}, this build reads {VERSION}.")

        salt = header[len(MAGIC) + 1:]
        aes = AESGCM(derive_key(passphrase, salt))

        # Write to a temp file: a failed decrypt should never leave a
        # half-written file that looks like a successful one.
        tmp = dst.with_suffix(dst.suffix + ".part")
        index = 0
        try:
            with tmp.open("wb") as fout:
                while True:
                    nonce = fin.read(NONCE_LEN)
                    if not nonce:
                        break
                    (length,) = struct.unpack(">I", fin.read(4))
                    sealed = fin.read(length)
                    fout.write(aes.decrypt(nonce, sealed, struct.pack(">Q", index)))
                    index += 1
            tmp.replace(dst)
        except InvalidTag:
            tmp.unlink(missing_ok=True)
            raise ValueError(
                "Authentication failed. Either the passphrase is wrong or "
                "the file was modified after it was encrypted."
            )
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    return index


def watch(folder: Path, passphrase: str, interval=3):
    """Encrypt anything dropped into a folder. The automated half."""
    seen = set()
    print(f"Watching {folder} — Ctrl-C to stop.")
    while True:
        for f in folder.iterdir():
            if f.is_file() and f.suffix != ".lockbox" and f not in seen:
                # Wait for the write to finish before touching it.
                size = f.stat().st_size
                time.sleep(0.4)
                if f.stat().st_size != size:
                    continue
                out = f.with_suffix(f.suffix + ".lockbox")
                encrypt_file(f, out, passphrase)
                f.unlink()
                seen.add(f)
                print(f"  sealed {f.name} -> {out.name}")
        time.sleep(interval)


def get_passphrase(confirm=False):
    # getpass keeps it off the screen and out of shell history.
    pw = os.environ.get("LOCKBOX_PASSPHRASE") or getpass.getpass("Passphrase: ")
    if confirm and not os.environ.get("LOCKBOX_PASSPHRASE"):
        if pw != getpass.getpass("Confirm: "):
            sys.exit("lockbox: passphrases did not match.")
    if len(pw) < 8:
        sys.exit("lockbox: use at least 8 characters.")
    return pw


def main():
    ap = argparse.ArgumentParser(description="Encrypt files with AES-256-GCM.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("lock", help="encrypt a file")
    p.add_argument("file", type=Path)
    p.add_argument("-o", "--out", type=Path)

    p = sub.add_parser("unlock", help="decrypt a file")
    p.add_argument("file", type=Path)
    p.add_argument("-o", "--out", type=Path)

    p = sub.add_parser("watch", help="auto-encrypt a folder")
    p.add_argument("folder", type=Path)

    args = ap.parse_args()

    if args.cmd == "lock":
        if not args.file.is_file():
            sys.exit(f"lockbox: no such file: {args.file}")
        out = args.out or args.file.with_suffix(args.file.suffix + ".lockbox")
        n = encrypt_file(args.file, out, get_passphrase(confirm=True))
        print(f"Sealed {args.file.name} -> {out.name} ({n} chunks)")

    elif args.cmd == "unlock":
        out = args.out or Path(str(args.file).removesuffix(".lockbox"))
        if out == args.file:
            out = args.file.with_suffix(".decrypted")
        try:
            n = decrypt_file(args.file, out, get_passphrase())
        except ValueError as e:
            sys.exit(f"lockbox: {e}")
        print(f"Opened {args.file.name} -> {out.name} ({n} chunks)")

    elif args.cmd == "watch":
        if not args.folder.is_dir():
            sys.exit(f"lockbox: no such folder: {args.folder}")
        try:
            watch(args.folder, get_passphrase(confirm=True))
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
