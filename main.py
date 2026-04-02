import base64
import os
import json
import sys
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(path, password):
    path = path.strip().replace("'", "").replace('"', '')
    if not os.path.exists(path):
        print(f"файла нет: {path}")
        return

    with open(path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    key = get_key(password, salt)
    fernet = Fernet(key)

    encrypted = b''
    chunk_size = 1024 * 1024  # 1 мб
    with tqdm(total=len(data), desc="шифрование", unit="b", unit_scale=True) as pbar:
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted += fernet.encrypt(chunk)
            pbar.update(len(chunk))

    out_path = path + ".c"
    with open(out_path, 'wb') as f:
        f.write(salt + encrypted)

    print(f"\nзашифровано: {out_path}")

def decrypt_file(path, password):
    path = path.strip().replace("'", "").replace('"', '')
    if not os.path.exists(path):
        print(f"файл не найден: {path}")
        return

    with open(path, 'rb') as f:
        full = f.read()
        salt = full[:16]
        encrypted = full[16:]

    key = get_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = b''
        chunk_size = 1024 * 1024
        with tqdm(total=len(encrypted), desc="расшифровка", unit="b", unit_scale=True) as pbar:
            for i in range(0, len(encrypted), chunk_size):
                chunk = encrypted[i:i+chunk_size]
                decrypted += fernet.decrypt(chunk)
                pbar.update(len(chunk))

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
        except:
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            print(f"сохранено: {out_path}")

    except:
        print("ошибка: неверный пароль или файл повреждён")

print(r"""
    ██████╗ ██╗███╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗
    ██╔══██╗██║████╗  ██║██╔══██╗██║ ██╔╝██║   ██║
    ██████╔╝██║██╔██╗ ██║███████║█████╔╝ ██║   ██║
    ██╔══██╗██║██║╚██╗██║██╔══██║██╔═██╗ ██║   ██║
    ██║  ██║██║██║ ╚████║██║  ██║██║  ██╗╚██████╔╝
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ """)

mode = input("1 - зашифровать  2 - расшифровать\nвыбор: ")
path = input("путь к файлу: ")
pwd = input("пароль: ")

if mode == "1":
    encrypt_file(path, pwd)
elif mode == "2":
    decrypt_file(path, pwd)
else:
    print("неверный режим")