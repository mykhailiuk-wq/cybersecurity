"""
USB CryptoVault — шифрування файлів із ключем на USB-носії.
Windows, Python 3.10+

Встановлення:
    py -m pip install cryptography

Запуск:
    py usb_cryptovault.py

Формат шифрування:
    AES-256-CBC + PKCS7 + HMAC-SHA256 (Encrypt-then-MAC).
Ключовий файл на флешці: usbcrypt.key (64 випадкові байти).
Зашифрований файл: оригінальна_назва.ext.usbc
"""

import os
import hmac
import hashlib
import secrets
import struct
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

try:
    import ctypes
    from ctypes import wintypes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError as exc:
    raise SystemExit(
        "Не знайдено залежності. Встановіть її командою:\n"
        "py -m pip install cryptography"
    ) from exc


APP_NAME = "USB CryptoVault"
KEY_FILENAME = "usbcrypt.key"
MAGIC = b"USBCV01!"
IV_SIZE = 16
KEY_SIZE = 64
MAC_SIZE = 32
CHUNK_SIZE = 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".html", ".css", ".js", ".py",
    ".md", ".log", ".docx", ".doc", ".rtf"
}


def removable_drives():
    if os.name != "nt":
        raise OSError("Ця версія програми призначена для Windows.")

    DRIVE_REMOVABLE = 2
    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    get_drive_type.argtypes = [wintypes.LPCWSTR]
    get_drive_type.restype = wintypes.UINT

    mask = ctypes.windll.kernel32.GetLogicalDrives()
    result = []
    for letter_code in range(ord("A"), ord("Z") + 1):
        if mask & (1 << (letter_code - ord("A"))):
            root = f"{chr(letter_code)}:\\"
            if get_drive_type(root) == DRIVE_REMOVABLE:
                result.append(Path(root))
    return result


def require_usb_path(path: Path, drives):
    """Переконується, що шлях лежить на одному зі знімних дисків."""
    resolved = path.resolve()
    for drive in drives:
        try:
            resolved.relative_to(drive.resolve())
            return resolved
        except ValueError:
            continue
    raise ValueError("Дозволено вибирати файли лише зі знімного USB-носія.")


def write_key_to_usb(usb_root: Path) -> Path:
    """Створює ключ без запису його у звичайний каталог користувача."""
    key_path = usb_root / KEY_FILENAME
    if key_path.exists():
        raise FileExistsError(
            f"На носії вже існує {KEY_FILENAME}. "
            "Щоб не втратити доступ до старих файлів, ключ не перезаписано."
        )
    key = secrets.token_bytes(KEY_SIZE)
    # 'xb' не дозволяє випадково перезаписати наявний ключ.
    with key_path.open("xb") as f:
        f.write(key)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key_path


def load_key_from_usb(usb_root: Path) -> bytes:
    key_path = usb_root / KEY_FILENAME
    if not key_path.is_file():
        raise FileNotFoundError(f"На вибраній флешці немає {KEY_FILENAME}.")
    key = key_path.read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("Файл ключа має неправильний формат або пошкоджений.")
    return key


def aes_encrypt_file(source: Path, destination: Path, key: bytes):
    enc_key, mac_key = key[:32], key[32:]
    iv = secrets.token_bytes(IV_SIZE)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()

    # Формат: MAGIC(8) + IV(16) + ciphertext_length(8) + ciphertext + HMAC(32)
    with source.open("rb") as src:
        size = source.stat().st_size
        padded_size = ((size // 16) + 1) * 16
        header = MAGIC + iv + struct.pack(">Q", padded_size)
        mac = hmac.new(mac_key, header, hashlib.sha256)

        # Тимчасовий файл створюється в каталозі призначення, щоб rename був атомарним.
        fd, temp_name = tempfile.mkstemp(prefix=".usbcv_", dir=str(destination.parent))
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(header)
                mac.update(header)
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    padded = padder.update(chunk)
                    if padded:
                        encrypted = encryptor.update(padded)
                        out.write(encrypted)
                        mac.update(encrypted)

                final_padded = padder.finalize()
                encrypted = encryptor.update(final_padded) + encryptor.finalize()
                if encrypted:
                    out.write(encrypted)
                    mac.update(encrypted)
                out.write(mac.digest())
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp_name, destination)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise


def aes_decrypt_file(source: Path, destination: Path, key: bytes):
    enc_key, mac_key = key[:32], key[32:]
    total_size = source.stat().st_size
    header_size = len(MAGIC) + IV_SIZE + 8
    if total_size < header_size + 16 + MAC_SIZE:
        raise ValueError("Зашифрований файл закороткий або пошкоджений.")

    with source.open("rb") as src:
        header = src.read(header_size)
        if len(header) != header_size or header[:len(MAGIC)] != MAGIC:
            raise ValueError("Непідтримуваний формат або це не файл USB CryptoVault.")
        offset = len(MAGIC)
        iv = header[offset:offset + IV_SIZE]
        ciphertext_size = struct.unpack(">Q", header[offset + IV_SIZE:])[0]

        if ciphertext_size < 16 or ciphertext_size % 16 != 0:
            raise ValueError("Неправильна довжина зашифрованих даних.")
        if total_size != header_size + ciphertext_size + MAC_SIZE:
            raise ValueError("Файл неповний або має некоректний формат.")

        mac = hmac.new(mac_key, header, hashlib.sha256)
        remaining = ciphertext_size
        # Перевіряємо HMAC перед розшифруванням, щоб не обробляти підроблені дані.
        while remaining:
            chunk = src.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise ValueError("Файл пошкоджений: неочікуваний кінець.")
            mac.update(chunk)
            remaining -= len(chunk)
        stored_mac = src.read(MAC_SIZE)
        if not hmac.compare_digest(mac.digest(), stored_mac):
            raise ValueError("Перевірка цілісності не пройдена: неправильний ключ або файл змінено.")

        src.seek(header_size)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()

        fd, temp_name = tempfile.mkstemp(prefix=".usbcv_", dir=str(destination.parent))
        try:
            with os.fdopen(fd, "wb") as out:
                remaining = ciphertext_size
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("Файл пошкоджений під час розшифрування.")
                    remaining -= len(chunk)
                    decrypted = decryptor.update(chunk)
                    plain = unpadder.update(decrypted)
                    if plain:
                        out.write(plain)
                tail = decryptor.finalize()
                plain_tail = unpadder.update(tail) + unpadder.finalize()
                if plain_tail:
                    out.write(plain_tail)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp_name, destination)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise


class CryptoVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("760x470")
        self.root.minsize(700, 430)
        self.usb_drives = []
        self.selected_drive = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")
        self.file_path = tk.StringVar()
        self.status = tk.StringVar(value="Підключіть USB-флешку та натисніть «Оновити».")
        self.build_ui()
        self.refresh_drives()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=18)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            main,
            text="AES-256-CBC • HMAC-SHA256 • ключ зберігається на USB-носії",
            wraplength=700
        ).pack(anchor="w", pady=(2, 16))

        drive_frame = ttk.LabelFrame(main, text="1. Знімний USB-носій", padding=10)
        drive_frame.pack(fill="x", pady=5)
        self.drive_combo = ttk.Combobox(
            drive_frame, textvariable=self.selected_drive, state="readonly", width=40
        )
        self.drive_combo.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(drive_frame, text="Оновити", command=self.refresh_drives).pack(side="left")
        ttk.Button(drive_frame, text="Створити ключ", command=self.create_key).pack(
            side="left", padx=(8, 0)
        )

        mode_frame = ttk.LabelFrame(main, text="2. Операція", padding=10)
        mode_frame.pack(fill="x", pady=5)
        ttk.Radiobutton(
            mode_frame, text="Зашифрувати файл", variable=self.mode,
            value="encrypt", command=self.update_mode
        ).pack(side="left", padx=(0, 20))
        ttk.Radiobutton(
            mode_frame, text="Розшифрувати файл", variable=self.mode,
            value="decrypt", command=self.update_mode
        ).pack(side="left")

        file_frame = ttk.LabelFrame(main, text="3. Файл на USB-носії", padding=10)
        file_frame.pack(fill="x", pady=5)
        ttk.Entry(file_frame, textvariable=self.file_path, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        self.browse_button = ttk.Button(file_frame, text="Вибрати файл", command=self.choose_file)
        self.browse_button.pack(side="left")

        self.run_button = ttk.Button(
            main, text="Виконати", command=self.run_operation
        )
        self.run_button.pack(anchor="e", pady=12)

        ttk.Separator(main).pack(fill="x", pady=4)
        ttk.Label(main, textvariable=self.status, wraplength=700).pack(anchor="w", pady=5)
        ttk.Label(
            main,
            text=("Увага: програма не видаляє оригінали автоматично. "
                  "Зробіть резервну копію ключа на окремому захищеному носії."),
            wraplength=700
        ).pack(anchor="w", pady=(10, 0))

    def refresh_drives(self):
        try:
            self.usb_drives = removable_drives()
            self.drive_combo["values"] = [str(drive) for drive in self.usb_drives]
            if self.usb_drives:
                current = self.selected_drive.get()
                self.selected_drive.set(
                    current if current in [str(d) for d in self.usb_drives]
                    else str(self.usb_drives[0])
                )
                self.status.set("Знімні диски знайдено. Виберіть флешку та створіть ключ.")
            else:
                self.selected_drive.set("")
                self.status.set(
                    "Знімних дисків не знайдено. Перевірте підключення флешки. "
                    "Деякі USB-пристрої Windows може визначати як локальні диски."
                )
        except Exception as exc:
            self.status.set(str(exc))

    def drive_root(self):
        value = self.selected_drive.get()
        if not value:
            raise ValueError("Спочатку виберіть знімний USB-носій.")
        drive = Path(value)
        if drive not in self.usb_drives:
            raise ValueError("Вибраний диск більше не визначається як знімний.")
        return drive

    def create_key(self):
        try:
            drive = self.drive_root()
            key_path = write_key_to_usb(drive)
            self.status.set(f"Ключ створено на USB: {key_path}")
            messagebox.showinfo(
                "Ключ створено",
                f"Ключ записано на:\n{key_path}\n\n"
                "Не видаляйте та не перезаписуйте його, інакше зашифровані файли "
                "можуть стати недоступними."
            )
        except Exception as exc:
            messagebox.showerror("Помилка створення ключа", str(exc))

    def update_mode(self):
        self.file_path.set("")

    def choose_file(self):
        try:
            drive = self.drive_root()
            if self.mode.get() == "encrypt":
                filetypes = [
                    ("Підтримувані файли", "*.txt *.csv *.json *.xml *.html *.css *.js *.py *.md *.log *.docx *.doc *.rtf"),
                    ("Усі файли", "*.*")
                ]
            else:
                filetypes = [("Зашифровані файли", "*.usbc"), ("Усі файли", "*.*")]
            chosen = filedialog.askopenfilename(
                title="Виберіть файл на USB-носії",
                initialdir=str(drive),
                filetypes=filetypes
            )
            if not chosen:
                return
            path = require_usb_path(Path(chosen), self.usb_drives)
            if not path.is_file():
                raise ValueError("Вибраний шлях не є файлом.")
            if self.mode.get() == "encrypt":
                if path.suffix.lower() == ".usbc":
                    raise ValueError("Файл .usbc уже зашифрований.")
                if path.suffix.lower() not in ALLOWED_EXTENSIONS:
                    if not messagebox.askyesno(
                        "Невідомий формат",
                        "Розширення файлу не входить до рекомендованого списку. "
                        "Спробувати зашифрувати його як звичайний двійковий файл?"
                    ):
                        return
            elif path.suffix.lower() != ".usbc":
                raise ValueError("Для розшифрування виберіть файл із розширенням .usbc.")
            self.file_path.set(str(path))
            self.status.set(f"Вибрано файл: {path.name}")
        except Exception as exc:
            messagebox.showerror("Помилка вибору файлу", str(exc))

    def run_operation(self):
        try:
            drive = self.drive_root()
            source = require_usb_path(Path(self.file_path.get()), self.usb_drives)
            if not source.is_file():
                raise ValueError("Виберіть файл для обробки.")
            key = load_key_from_usb(drive)

            if self.mode.get() == "encrypt":
                destination = source.with_name(source.name + ".usbc")
                if destination.exists():
                    raise FileExistsError(f"Файл призначення вже існує:\n{destination}")
                aes_encrypt_file(source, destination, key)
                self.status.set(f"Шифрування завершено: {destination.name}")
                messagebox.showinfo("Готово", f"Файл зашифровано:\n{destination}")
            else:
                name = source.name[:-5]  # прибираємо суфікс .usbc
                if not name:
                    name = "decrypted_file"
                destination = source.with_name(name)
                if destination.exists():
                    destination = source.with_name(name + ".decrypted")
                aes_decrypt_file(source, destination, key)
                self.status.set(f"Розшифрування завершено: {destination.name}")
                messagebox.showinfo("Готово", f"Файл розшифровано:\n{destination}")
        except Exception as exc:
            self.status.set(f"Помилка: {exc}")
            messagebox.showerror("Операцію не виконано", str(exc))


def main():
    if os.name != "nt":
        raise SystemExit("USB CryptoVault у цій реалізації працює лише у Windows.")
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except tk.TclError:
        pass
    CryptoVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
