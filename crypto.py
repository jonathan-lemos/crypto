import argparse
import os
import secrets
import sys
from enum import Enum
from getpass import getpass
from typing import Any, Dict, Iterable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CipherType(Enum):
    AES = {
        "name": "AES",
        "key_sizes": [128, 192, 256],
        "algorithm": algorithms.AES,
        "block_cipher": True,
        "block_size": 16,
    }
    CAMELLIA = {
        "name": "CAMELLIA",
        "key_sizes": [128, 192, 256],
        "algorithm": algorithms.Camellia,
        "block_cipher": True,
        "block_size": 16
    }
    CAST5 = {
        "name": "CAST5",
        "key_sizes": list(range(40, 128 + 1, 8)),
        "algorithm": algorithms.CAST5,
        "block_cipher": True,
        "block_size": 8
    }
    SEED = {
        "name": "SEED",
        "key_sizes": [128],
        "algorithm": algorithms.SEED,
        "block_cipher": True,
        "block_size": 8
    }


class BlockCipherModeType(Enum):
    CBC = {
        "name": "CBC",
        "algorithm": modes.CBC,
        "auth_tag": None
    }
    CTR = {
        "name": "CTR",
        "algorithm": modes.CTR,
        "auth_tag": None
    }
    OFB = {
        "name": "OFB",
        "algorithm": modes.OFB,
        "auth_tag": None
    }
    CFB = {
        "name": "CFB",
        "algorithm": modes.CFB,
        "auth_tag": None
    }
    GCM = {
        "name": "CBC",
        "algorithm": modes.GCM,
        "auth_tag": 16
    }


class KdfType(Enum):
    PBKDF2 = {
        "name": "PBKDF2",
        "algorithm": PBKDF2HMAC
    }
    HKDF = {
        "name": "HKDF",
        "algorithm": HKDF
    }


class HashType(Enum):
    SHA256 = {
        "name": "SHA256",
        "algorithm": hashes.SHA256
    }
    SHA512 = {
        "name": "SHA512",
        "algorithm": hashes.SHA512
    }
    SHA3_512 = {
        "name": "SHA3_512",
        "algorithm": hashes.SHA3_512
    }


cipher_dict = {x.name: x.value for x in CipherType}
mode_dict = {x.name: x.value for x in BlockCipherModeType}


def supported_ciphers() -> Dict[str, Tuple[Dict, int, Optional[Dict]]]:
    ret = {}
    for cipher in cipher_dict:
        for key_size in cipher_dict[cipher]["key_sizes"]:
            if cipher_dict[cipher]["block_cipher"]:
                for mode in mode_dict:
                    ret[f"{cipher}-{key_size}-{mode}"] = (cipher_dict[cipher], key_size, mode_dict[mode])
            else:
                ret[f"{cipher}-{key_size}"] = (cipher_dict[cipher], key_size, None)
    return ret


ciphers = supported_ciphers()
kdfs = {x.name: x.value for x in KdfType}
hashtypes = {x.name: x.value for x in HashType}

parser = argparse.ArgumentParser(
    description="Encrypts or decrypts input. The $PASSPHRASE environment variable can be set to specify the password if you don't want to type it in.")
parser.add_argument("action",
                    metavar="ACTION",
                    help="'enc' to encrypt, 'dec' to decrypt, 'ciphers' to list ciphers, 'hashes' to list hash functions, 'kdfs' to list kdfs.")

parser.add_argument("-c", "--cipher",
                    dest="cipher",
                    metavar="CIPHER",
                    help="the encryption cipher to use (default 'AES-256-GCM')",
                    default="AES-256-GCM")
parser.add_argument("-kdf", "--key-derivation",
                    dest="kdf",
                    metavar="KDF",
                    help="the key derivation function to use (default 'PBKDF2')",
                    default="PBKDF2")
parser.add_argument("-kh", "--key-hash",
                    dest="key_hash",
                    metavar="HASH",
                    help="the hash function to use with the kdf (default 'SHA256')",
                    default="SHA256"),
parser.add_argument("-ki", "--key-iterations",
                    type=int,
                    dest="key_iterations",
                    metavar="ITERATIONS",
                    help="the number of iterations the kdf should perform (default '100000')",
                    default=100000)
parser.add_argument("-in", "--input",
                    dest="input",
                    metavar="FILE",
                    help="a file to encrypt. by default input is taken from stdin",
                    default=None)
parser.add_argument("-iv", "--initialization-vector",
                    dest="initialization_vector",
                    metavar="IV",
                    help="the IV to use (with certain cipher modes). by default this is a randomly generated value of the correct length for the supplied cipher.",
                    default=None)
parser.add_argument("-out", "--output",
                    dest="output",
                    metavar="FILE",
                    help="the file to output to. by default output is written to stdout",
                    default=None)
parser.add_argument("-s", "--salt",
                    dest="salt",
                    metavar="SALT",
                    help="the salt to use with the kdf. by default this is a randomly generated 128-bit value.",
                    default=None)
parser.add_argument("-v", "--verbose",
                    action="store_true",
                    dest="verbose",
                    help="display information to stderr",
                    default=False)

options = parser.parse_args()

actions = ["enc", "dec", "ciphers", "hashes", "kdfs"]
if options.action not in actions:
    print(f"Action must be one of {actions}. Was '{options.action}'.", file=sys.stderr)
    exit(1)

if options.action == "ciphers":
    print("\n".join(ciphers))
    exit(0)

if options.action == "hashes":
    print("\n".join(hashtypes))
    exit(0)

if options.action == "kdfs":
    print("\n".join(kdfs))
    exit(0)

try:
    cipher, key_len, mode = ciphers[options.cipher.upper()]
except KeyError:
    print(f"Invalid cipher '{options.cipher}'. Must be one of: {', '.join(ciphers)}", file=sys.stderr)
    exit(1)

try:
    kdf = kdfs[options.kdf.upper()]
except KeyError:
    print(f"Invalid KDF '{options.kdf}'. Must be one of: {' '.join(kdfs)}", file=sys.stderr)
    exit(1)

try:
    hashfunc = hashtypes[options.key_hash.upper()]
except KeyError:
    print(f"Invalid hash function '{options.key_hash}'. Must be one of {' '.join(hashtypes)}.", file=sys.stderr)
    exit(1)

__backend = default_backend()


def rand_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def make_key(salt: bytes) -> bytes:
    if (passphrase := os.environ.get("PASSPHRASE")) is None:
        passphrase = getpass("Enter passphrase: ")

    df = kdf["algorithm"](
        algorithm=hashfunc["algorithm"],
        length=key_len // 8,
        salt=salt,
        iterations=options.key_iterations,
        backend=__backend
    )

    if options.verbose:
        print(f"Making a {key_len}-bit key with {options.kdf} using {options.key_iterations} rounds of {options.key_hash}.")

    return df.derive(bytes(passphrase, "utf-8"))


def encrypt():
    if (salt := options.salt) is None:
        salt = rand_bytes(16)
    if (iv := options.initialization_vector) is None:
        iv = rand_bytes(cipher["block_size"])
    key = make_key(salt)
    n_bytes = 0

    if options.input is None:
        stdin = sys.stdin.buffer
    else:
        stdin = open(options.input, "rb")

    if options.output is None:
        stdout = sys.stdout.buffer
    else:
        stdout = open(options.output, "wb")

    encryptor = Cipher(
        cipher["algorithm"](key),
        mode["algorithm"](iv) if mode else None,
        backend=__backend
    ).encryptor()

    stdout.write(len(salt).to_bytes(2, byteorder="little"))
    stdout.write(salt)
    if mode:
        stdout.write(iv)

        if options.verbose:
            n_bytes += 2 + len(salt) + len(iv)
            print("Wrote salt length, salt, and iv to file.")
            print(f"\r{n_bytes} bytes processed.", end="")

    while len(buf := stdin.read(65536)) != 0:
        stdout.write(encryptor.update(buf))

        if options.verbose:
            n_bytes += len(buf)
            print(f"\r{n_bytes} bytes processed.", end="")

    if not options.verbose:
        stdout.write(encryptor.finalize())
    else:
        buf = encryptor.finalize()
        stdout.write(buf)
        n_bytes += len(buf)
        print(f"\r{n_bytes} bytes processed.", end="")

    if mode["auth_tag"]:
        if not options.verbose:
            stdout.write(encryptor.tag)
        else:
            buf = encryptor.tag
            stdout.write(encryptor.tag)
            n_bytes += len(buf)
            print(f"\r{n_bytes} bytes processed.", end="")
            print(f"\nWrote authentication tag of length {len(encryptor.tag)}.")
    else:
        if options.verbose:
            print()

    if stdin != sys.stdin.buffer:
        stdin.close()
    if stdout != sys.stdout.buffer:
        stdout.close()


def decrypt():
    if options.input is None:
        stdin = sys.stdin.buffer
    else:
        stdin = open(options.input, "rb")

    if options.output is None:
        stdout = sys.stdout.buffer
    else:
        stdout = open(options.output, "wb")

    salt_len = int.from_bytes(stdin.read(2), byteorder="little")
    salt = stdin.read(salt_len)
    if len(salt) != salt_len:
        print(
            f"Expected a salt of length {salt_len} but the file is not long enough. Most likely the file is corrupted or not encrypted using this cipher.", file=sys.stderr)
        exit(1)

    n_bytes = 0
    if options.verbose:
        n_bytes += 2 + len(salt)
        print(f"Read a salt of length {salt_len}.")

    key = make_key(salt)

    if mode:
        iv = stdin.read(cipher["block_size"])
        if options.verbose:
            n_bytes += len(iv)
            print(f"Read an iv of length {len(iv)}.")
    else:
        iv = None

    decryptor = Cipher(
        cipher["algorithm"](key),
        mode["algorithm"](iv) if mode else None,
        backend=__backend
    ).decryptor()

    buf = None
    while len(buf2 := stdin.read(65536)) != 0:
        if buf:
            stdout.write(decryptor.update(buf))
            if options.verbose:
                n_bytes += len(buf)
                print(f"\rProcessed {n_bytes} bytes.", end="")
        buf = buf2
    if mode["auth_tag"]:
        stdout.write(decryptor.update(buf[:-mode["auth_tag"]]))
        if options.verbose:
            n_bytes += len(buf) - mode["auth_tag"]
            print(f"\rProcessed {n_bytes} bytes.", end="")
        try:
            buf = decryptor.finalize_with_tag(buf[-mode["auth_tag"]:])
            stdout.write(buf)
            if options.verbose:
                n_bytes += mode["auth_tag"]
                print(f"\rProcessed {n_bytes} bytes.", end="")
                print(f"\nProcessed an authentication token of length {mode['auth_tag']}.")
        except InvalidTag:
            print("\nThe authentication token could not be verified. Most likely the data is corrupt.", file=sys.stderr)
            exit(1)
    else:
        stdout.write(decryptor.update(buf))
        stdout.write(decryptor.finalize())


if options.action == "enc":
    encrypt()
else:
    decrypt()
