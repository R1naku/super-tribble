import argparse
import base64
import hashlib
import json
import os
import struct
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b'CRPT'
FORMAT_VERSION = 1

DEFAULT_PBKDF2_ITERATIONS = 1_000_000
DEFAULT_ARGON2ID_TIME_COST = 3
DEFAULT_ARGON2ID_MEMORY_COST = 65536
DEFAULT_ARGON2ID_PARALLELISM = 4

BANNER = r"""
██████╗ ██╗███╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗
██╔══██╗██║████╗  ██║██╔══██╗██║ ██╔╝██║   ██║
██████╔╝██║██╔██╗ ██║███████║█████╔╝ ██║   ██║
██╔══██╗██║██║╚██╗██║██╔══██║██╔═██╗ ██║   ██║
██║  ██║██║██║ ╚████║██║  ██║██║  ██╗╚██████╔╝
╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                              
     ██╗███████╗ ██████╗ ███╗   ██╗███████╗   
     ██║██╔════╝██╔═══██╗████╗  ██║██╔════╝   
     ██║███████╗██║   ██║██╔██╗ ██║███████╗   
██   ██║╚════██║██║   ██║██║╚██╗██║╚════██║   
╚█████╔╝███████║╚██████╔╝██║ ╚████║███████║   
 ╚════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   
                                               """


def derive_key_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def derive_key_argon2id(password: str, salt: bytes, time_cost: int,
                        memory_cost: int, parallelism: int) -> bytes:
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        print("ошибка: argon2-cffi не установлен — pip install argon2-cffi")
        sys.exit(1)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        type=Type.ID,
        hash_len=32,
    )
    return base64.urlsafe_b64encode(key)


def derive_key(password: str, header: dict) -> bytes:
    kdf = header.get("kdf", "pbkdf2")
    salt = base64.urlsafe_b64decode(header["salt"])
    if kdf == "pbkdf2":
        return derive_key_pbkdf2(password, salt, header.get("iter", DEFAULT_PBKDF2_ITERATIONS))
    elif kdf == "argon2id":
        return derive_key_argon2id(
            password, salt,
            header.get("t_cost", DEFAULT_ARGON2ID_TIME_COST),
            header.get("m_cost", DEFAULT_ARGON2ID_MEMORY_COST),
            header.get("parallel", DEFAULT_ARGON2ID_PARALLELISM),
        )
    else:
        raise ValueError(f"неизвестный KDF: {kdf}")


def build_header(kdf: str, salt: bytes, iterations: int = None,
                 time_cost: int = None, memory_cost: int = None,
                 parallelism: int = None, sha256_hex: str = None) -> bytes:
    h = {"v": FORMAT_VERSION, "kdf": kdf,
         "salt": base64.urlsafe_b64encode(salt).decode(),
         "sha256": sha256_hex}
    if kdf == "pbkdf2":
        h["iter"] = iterations or DEFAULT_PBKDF2_ITERATIONS
    elif kdf == "argon2id":
        h["t_cost"] = time_cost or DEFAULT_ARGON2ID_TIME_COST
        h["m_cost"] = memory_cost or DEFAULT_ARGON2ID_MEMORY_COST
        h["parallel"] = parallelism or DEFAULT_ARGON2ID_PARALLELISM
    return json.dumps(h, separators=(',', ':')).encode()


def read_header(data: bytes):
    if data[:4] != MAGIC:
        raise ValueError("неверный формат файла (нет заголовка CRPT)")
    header_len = struct.unpack('>I', data[4:8])[0]
    header = json.loads(data[8:8 + header_len])
    encrypted = data[8 + header_len:]
    return header, encrypted


def encrypt_file(path: str, password: str, kdf: str = "pbkdf2",
                 iterations: int = DEFAULT_PBKDF2_ITERATIONS, quiet: bool = False):
    path = path.strip()
    if not os.path.exists(path):
        print(f"файла нет: {path}")
        return

    if len(password) < 12:
        print("предупреждение: пароль короче 12 символов — ненадёжно")

    with open(path, 'rb') as f:
        data = f.read()

    sha256_hex = hashlib.sha256(data).hexdigest()
    salt = os.urandom(16)

    if kdf == "pbkdf2":
        key = derive_key_pbkdf2(password, salt, iterations)
        header = build_header(kdf="pbkdf2", salt=salt,
                              iterations=iterations, sha256_hex=sha256_hex)
    elif kdf == "argon2id":
        key = derive_key_argon2id(password, salt,
                                  DEFAULT_ARGON2ID_TIME_COST,
                                  DEFAULT_ARGON2ID_MEMORY_COST,
                                  DEFAULT_ARGON2ID_PARALLELISM)
        header = build_header(kdf="argon2id", salt=salt, sha256_hex=sha256_hex)
    else:
        print(f"неизвестный KDF: {kdf}")
        return

    fernet = Fernet(key)

    if not quiet:
        print("шифрование...")
    encrypted = fernet.encrypt(data)

    out_path = path + ".c"
    with open(out_path, 'wb') as f:
        f.write(MAGIC + struct.pack('>I', len(header)) + header + encrypted)

    print(f"зашифровано: {out_path}")


def decrypt_file(path: str, password: str, quiet: bool = False):
    path = path.strip()
    if not os.path.exists(path):
        print(f"файл не найден: {path}")
        return

    with open(path, 'rb') as f:
        raw = f.read()

    try:
        header, encrypted = read_header(raw)
    except (ValueError, json.JSONDecodeError, struct.error) as e:
        print(f"ошибка формата файла: {e}")
        return

    if not quiet:
        print(f"KDF: {header.get('kdf', 'pbkdf2')}")
        if header.get("kdf") == "pbkdf2":
            print(f"итерации: {header.get('iter', '?')}")

    key = derive_key(password, header)
    fernet = Fernet(key)

    try:
        if not quiet:
            print("расшифровка...")
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        print("ошибка: неверный пароль или файл повреждён")
        return

    expected_hash = header.get("sha256")
    if expected_hash:
        actual_hash = hashlib.sha256(decrypted).hexdigest()
        if actual_hash != expected_hash:
            print("ошибка: нарушена целостность данных (SHA-256 не совпадает)")
            return
        if not quiet:
            print("целостность: OK")

    if path.endswith(".c"):
        out_path = path[:-2] + ".d"
    else:
        out_path = path + ".d"

    try:
        js = json.loads(decrypted.decode('utf-8'))
        print("\njson содержимое:")
        print(json.dumps(js, indent=4, ensure_ascii=False))
        if input("\nсохранить файл? (y/n): ").lower() == 'y':
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            print(f"сохранено: {out_path}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        with open(out_path, 'wb') as f:
            f.write(decrypted)
        print(f"сохранено: {out_path}")


def interactive():
    print(BANNER)
    mode = input("1 - зашифровать  2 - расшифровать\nвыбор: ")
    path = input("путь к файлу: ")
    pwd = input("пароль: ")

    if mode == "1":
        encrypt_file(path, pwd)
    elif mode == "2":
        decrypt_file(path, pwd)
    else:
        print("неверный режим")


def main():
    if len(sys.argv) == 1:
        interactive()
        return

    parser = argparse.ArgumentParser(description="шифрование файлов")
    parser.add_argument("mode", nargs='?', choices=["enc", "dec"],
                        help="enc — зашифровать, dec — расшифровать")
    parser.add_argument("path", nargs='?', help="путь к файлу")
    parser.add_argument("-p", "--password", help="пароль (если не указан — будет запрошен)")
    parser.add_argument("-k", "--kdf", choices=["pbkdf2", "argon2id"], default="pbkdf2",
                        help="функция деривации ключа (по умолчанию pbkdf2)")
    parser.add_argument("-i", "--iterations", type=int, default=DEFAULT_PBKDF2_ITERATIONS,
                        help=f"итерации PBKDF2 (по умолчанию {DEFAULT_PBKDF2_ITERATIONS})")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="убрать баннер и лишний вывод")
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    password = args.password or input("пароль: ")

    if args.mode == "enc":
        encrypt_file(args.path, password, kdf=args.kdf,
                     iterations=args.iterations, quiet=args.quiet)
    elif args.mode == "dec":
        decrypt_file(args.path, password, quiet=args.quiet)
    else:
        interactive()


if __name__ == "__main__":
    main()