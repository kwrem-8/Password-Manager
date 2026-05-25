import tkinter as tk
from tkinter import messagebox, simpledialog
import os
import json
import base64
import secrets
import string
import threading
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes


DARK = {
    "bg":           "#1a1a1a",
    "panel":        "#222222",
    "card":         "#2a2a2a",
    "row_alt":      "#252525",
    "border":       "#383838",
    "text":         "#e0e0e0",
    "muted":        "#666666",
    "accent":       "#4a90d9",
    "accent_h":     "#357abd",
    "danger":       "#d9534a",
    "danger_h":     "#c0392b",
    "success":      "#4aad6f",
    "success_h":    "#3d9960",
    "input_bg":     "#2f2f2f",
    "header":       "#1e1e1e",
}

VAULT_FILE = os.path.join(os.path.expanduser("~"), ".pwvault")
PBKDF2_ITERATIONS = 600_000
LOCK_AFTER = 300


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_vault(data: dict, key: bytes) -> bytes:
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_vault(raw: bytes, key: bytes) -> dict:
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def load_raw_vault() -> tuple:
    if not os.path.exists(VAULT_FILE):
        return None, None
    with open(VAULT_FILE, "rb") as f:
        content = f.read()
    salt = content[:32]
    payload = content[32:]
    return salt, payload


def save_raw_vault(salt: bytes, encrypted: bytes):
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted)


def generate_password(length=20, upper=True, digits=True, symbols=True) -> str:
    chars = string.ascii_lowercase
    required = []
    if upper:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars += sym
        required.append(secrets.choice(sym))
    pool = list(chars)
    pw = required + [secrets.choice(pool) for _ in range(length - len(required))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


class LoginWindow(tk.Toplevel):
    def __init__(self, parent, on_success, is_new=False):
        super().__init__(parent)
        self.title("Giriş" if not is_new else "Yeni Kasa")
        self.resizable(False, False)
        self.configure(bg=DARK["bg"])
        self.grab_set()
        self.on_success = on_success
        self.is_new = is_new
        self._build(is_new)
        self.protocol("WM_DELETE_WINDOW", parent.destroy)

    def _build(self, is_new):
        frame = tk.Frame(self, bg=DARK["bg"], padx=32, pady=28)
        frame.pack()

        tk.Label(
            frame,
            text="🔐  Password Manager" if not is_new else "🔐  Yeni Kasa Oluştur",
            bg=DARK["bg"], fg=DARK["text"],
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 20))

        tk.Label(frame, text="Ana Şifre", bg=DARK["bg"], fg=DARK["muted"], font=("Segoe UI", 9)).pack(anchor="w")
        self.pw_var = tk.StringVar()
        pw_entry = tk.Entry(
            frame, textvariable=self.pw_var, show="•",
            bg=DARK["input_bg"], fg=DARK["text"],
            insertbackground=DARK["text"],
            relief=tk.FLAT, font=("Segoe UI", 11), width=28
        )
        pw_entry.pack(ipady=7, pady=(2, 12))
        pw_entry.focus_set()
        pw_entry.bind("<Return>", lambda e: self._submit())

        if is_new:
            tk.Label(frame, text="Tekrar Gir", bg=DARK["bg"], fg=DARK["muted"], font=("Segoe UI", 9)).pack(anchor="w")
            self.pw2_var = tk.StringVar()
            pw2_entry = tk.Entry(
                frame, textvariable=self.pw2_var, show="•",
                bg=DARK["input_bg"], fg=DARK["text"],
                insertbackground=DARK["text"],
                relief=tk.FLAT, font=("Segoe UI", 11), width=28
            )
            pw2_entry.pack(ipady=7, pady=(2, 12))
            pw2_entry.bind("<Return>", lambda e: self._submit())

        self.err_label = tk.Label(frame, text="", bg=DARK["bg"], fg=DARK["danger"], font=("Segoe UI", 9))
        self.err_label.pack(pady=(0, 8))

        tk.Button(
            frame,
            text="Kasayı Aç" if not is_new else "Oluştur",
            command=self._submit,
            bg=DARK["accent"], fg="#ffffff",
            activebackground=DARK["accent_h"], activeforeground="#ffffff",
            relief=tk.FLAT, font=("Segoe UI", 10, "bold"),
            padx=16, pady=8, cursor="hand2", width=20
        ).pack()

    def _submit(self):
        pw = self.pw_var.get()
        if not pw:
            self.err_label.config(text="Şifre boş olamaz.")
            return

        if self.is_new:
            pw2 = self.pw2_var.get()
            if pw != pw2:
                self.err_label.config(text="Şifreler eşleşmiyor.")
                return
            if len(pw) < 8:
                self.err_label.config(text="En az 8 karakter gerekli.")
                return
            salt = os.urandom(32)
            key = derive_key(pw, salt)
            encrypted = encrypt_vault({"entries": []}, key)
            save_raw_vault(salt, encrypted)
            self.destroy()
            self.on_success(key)
        else:
            salt, payload = load_raw_vault()
            key = derive_key(pw, salt)
            try:
                decrypt_vault(payload, key)
                self.destroy()
                self.on_success(key)
            except Exception:
                self.err_label.config(text="Hatalı şifre.")


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, on_save, existing=None):
        super().__init__(parent)
        self.title("Kayıt Ekle" if not existing else "Kayıt Düzenle")
        self.resizable(False, False)
        self.configure(bg=DARK["bg"])
        self.grab_set()
        self.on_save = on_save
        self.existing = existing
        self._build()

    def _build(self):
        frame = tk.Frame(self, bg=DARK["bg"], padx=24, pady=20)
        frame.pack()

        self.vars = {}
        fields = [("Site / Uygulama", "site"), ("Kullanıcı Adı", "username"), ("Şifre", "password"), ("Not", "note")]

        for label, key in fields:
            tk.Label(frame, text=label, bg=DARK["bg"], fg=DARK["muted"], font=("Segoe UI", 9)).pack(anchor="w", pady=(8, 2))
            var = tk.StringVar(value=self.existing.get(key, "") if self.existing else "")
            self.vars[key] = var

            if key == "password":
                row = tk.Frame(frame, bg=DARK["bg"])
                row.pack(fill=tk.X)
                self.pw_entry = tk.Entry(
                    row, textvariable=var, show="•",
                    bg=DARK["input_bg"], fg=DARK["text"],
                    insertbackground=DARK["text"],
                    relief=tk.FLAT, font=("Segoe UI", 10), width=24
                )
                self.pw_entry.pack(side=tk.LEFT, ipady=6, padx=(0, 6))
                tk.Button(
                    row, text="Göster",
                    command=self._toggle_pw,
                    bg=DARK["card"], fg=DARK["text"],
                    relief=tk.FLAT, font=("Segoe UI", 8),
                    padx=6, pady=4, cursor="hand2",
                    activebackground=DARK["border"], activeforeground=DARK["text"]
                ).pack(side=tk.LEFT, padx=(0, 4))
                tk.Button(
                    row, text="Üret",
                    command=self._generate,
                    bg=DARK["card"], fg=DARK["text"],
                    relief=tk.FLAT, font=("Segoe UI", 8),
                    padx=6, pady=4, cursor="hand2",
                    activebackground=DARK["border"], activeforeground=DARK["text"]
                ).pack(side=tk.LEFT)
            else:
                tk.Entry(
                    frame, textvariable=var,
                    bg=DARK["input_bg"], fg=DARK["text"],
                    insertbackground=DARK["text"],
                    relief=tk.FLAT, font=("Segoe UI", 10), width=32
                ).pack(ipady=6, pady=(0, 2))

        row = tk.Frame(frame, bg=DARK["bg"])
        row.pack(pady=(16, 0), fill=tk.X)

        tk.Button(
            row, text="Kaydet",
            command=self._save,
            bg=DARK["success"], fg="#ffffff",
            activebackground=DARK["success_h"], activeforeground="#ffffff",
            relief=tk.FLAT, font=("Segoe UI", 9, "bold"),
            padx=14, pady=7, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            row, text="İptal",
            command=self.destroy,
            bg=DARK["card"], fg=DARK["text"],
            activebackground=DARK["border"], activeforeground=DARK["text"],
            relief=tk.FLAT, font=("Segoe UI", 9),
            padx=14, pady=7, cursor="hand2"
        ).pack(side=tk.LEFT)

    def _toggle_pw(self):
        current = self.pw_entry.cget("show")
        self.pw_entry.config(show="" if current == "•" else "•")

    def _generate(self):
        pw = generate_password()
        self.vars["password"].set(pw)
        self.pw_entry.config(show="")

    def _save(self):
        site = self.vars["site"].get().strip()
        if not site:
            messagebox.showwarning("Uyarı", "Site / Uygulama alanı boş olamaz.", parent=self)
            return
        entry = {k: v.get() for k, v in self.vars.items()}
        self.on_save(entry)
        self.destroy()


class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("780x540")
        self.minsize(640, 420)
        self.configure(bg=DARK["bg"])
        self.withdraw()

        self._key = None
        self._vault = {"entries": []}
        self._filtered = []
        self._lock_timer = None
        self._last_activity = time.time()

        self._build_ui()
        self._boot()

    def _build_ui(self):
        top = tk.Frame(self, bg=DARK["bg"])
        top.pack(fill=tk.X, padx=14, pady=(12, 6))

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._render())

        tk.Entry(
            top, textvariable=self._search_var,
            bg=DARK["input_bg"], fg=DARK["text"],
            insertbackground=DARK["text"],
            relief=tk.FLAT, font=("Segoe UI", 9), width=28
        ).pack(side=tk.LEFT, ipady=6, ipadx=8)

        tk.Label(top, text="Ara", bg=DARK["bg"], fg=DARK["muted"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(6, 20))

        tk.Button(
            top, text="+ Yeni Kayıt",
            command=self._add_entry,
            bg=DARK["accent"], fg="#ffffff",
            activebackground=DARK["accent_h"], activeforeground="#ffffff",
            relief=tk.FLAT, font=("Segoe UI", 9),
            padx=12, pady=5, cursor="hand2"
        ).pack(side=tk.LEFT)

        tk.Button(
            top, text="Kilitle",
            command=self._lock,
            bg=DARK["card"], fg=DARK["muted"],
            activebackground=DARK["border"], activeforeground=DARK["text"],
            relief=tk.FLAT, font=("Segoe UI", 9),
            padx=10, pady=5, cursor="hand2"
        ).pack(side=tk.RIGHT)

        self._count_label = tk.Label(top, bg=DARK["bg"], fg=DARK["muted"], font=("Segoe UI", 9))
        self._count_label.pack(side=tk.RIGHT, padx=12)

        header = tk.Frame(self, bg=DARK["header"])
        header.pack(fill=tk.X, padx=14, pady=(4, 0))

        for text, w in [("Site / Uygulama", 22), ("Kullanıcı Adı", 20), ("İşlemler", 16)]:
            tk.Label(
                header, text=text, width=w, anchor="w",
                bg=DARK["header"], fg=DARK["muted"],
                font=("Segoe UI", 8, "bold"), padx=6, pady=4
            ).pack(side=tk.LEFT)

        list_frame = tk.Frame(self, bg=DARK["card"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 4))

        scrollbar = tk.Scrollbar(list_frame, bg=DARK["card"], troughcolor=DARK["card"], bd=0, width=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._canvas = tk.Canvas(list_frame, bg=DARK["card"], highlightthickness=0, yscrollcommand=scrollbar.set)
        self._canvas.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._canvas.yview)

        self._rows_frame = tk.Frame(self._canvas, bg=DARK["card"])
        self._canvas_window = self._canvas.create_window((0, 0), window=self._rows_frame, anchor="nw")

        self._rows_frame.bind("<Configure>", lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfig(self._canvas_window, width=e.width))

        self.bind_all("<Motion>", self._reset_timer)
        self.bind_all("<Key>",    self._reset_timer)

    def _boot(self):
        salt, payload = load_raw_vault()
        if salt is None:
            LoginWindow(self, self._on_login, is_new=True)
        else:
            LoginWindow(self, self._on_login, is_new=False)

    def _on_login(self, key):
        self._key = key
        salt, payload = load_raw_vault()
        self._vault = decrypt_vault(payload, key)
        self.deiconify()
        self._render()
        self._start_lock_timer()

    def _save(self):
        if not self._key:
            return
        salt, _ = load_raw_vault()
        encrypted = encrypt_vault(self._vault, self._key)
        save_raw_vault(salt, encrypted)

    def _render(self):
        for w in self._rows_frame.winfo_children():
            w.destroy()

        q = self._search_var.get().lower().strip()
        entries = self._vault.get("entries", [])
        self._filtered = [e for e in entries if q in e.get("site", "").lower() or q in e.get("username", "").lower()] if q else entries

        for i, entry in enumerate(self._filtered):
            bg = DARK["card"] if i % 2 == 0 else DARK["row_alt"]
            row = tk.Frame(self._rows_frame, bg=bg)
            row.pack(fill=tk.X)

            tk.Label(
                row, text=entry.get("site", "")[:28], width=22, anchor="w",
                bg=bg, fg=DARK["text"], font=("Segoe UI", 9), padx=8, pady=7
            ).pack(side=tk.LEFT)

            tk.Label(
                row, text=entry.get("username", "")[:24], width=20, anchor="w",
                bg=bg, fg=DARK["muted"], font=("Segoe UI", 9), padx=4, pady=7
            ).pack(side=tk.LEFT)

            btn_frame = tk.Frame(row, bg=bg)
            btn_frame.pack(side=tk.LEFT)

            tk.Button(
                btn_frame, text="Kopyala",
                command=lambda e=entry: self._copy_pw(e),
                bg=bg, fg=DARK["accent"],
                activebackground=DARK["border"], activeforeground=DARK["accent"],
                relief=tk.FLAT, font=("Segoe UI", 8),
                padx=6, pady=3, cursor="hand2"
            ).pack(side=tk.LEFT, padx=(0, 4))

            tk.Button(
                btn_frame, text="Düzenle",
                command=lambda e=entry: self._edit_entry(e),
                bg=bg, fg=DARK["muted"],
                activebackground=DARK["border"], activeforeground=DARK["text"],
                relief=tk.FLAT, font=("Segoe UI", 8),
                padx=6, pady=3, cursor="hand2"
            ).pack(side=tk.LEFT, padx=(0, 4))

            tk.Button(
                btn_frame, text="Sil",
                command=lambda e=entry: self._delete_entry(e),
                bg=bg, fg=DARK["danger"],
                activebackground=DARK["border"], activeforeground=DARK["danger"],
                relief=tk.FLAT, font=("Segoe UI", 8),
                padx=6, pady=3, cursor="hand2"
            ).pack(side=tk.LEFT)

        self._count_label.config(text=f"{len(self._filtered)} / {len(entries)} kayıt")

    def _copy_pw(self, entry):
        pw = entry.get("password", "")
        self.clipboard_clear()
        self.clipboard_append(pw)
        self.after(15000, self.clipboard_clear)
        self._reset_timer()

    def _add_entry(self):
        self._reset_timer()
        EntryDialog(self, self._on_save_entry)

    def _edit_entry(self, entry):
        self._reset_timer()
        idx = self._vault["entries"].index(entry)
        def on_save(updated):
            self._vault["entries"][idx] = updated
            self._save()
            self._render()
        EntryDialog(self, on_save, existing=entry)

    def _delete_entry(self, entry):
        self._reset_timer()
        if messagebox.askyesno("Sil", f'"{entry.get("site", "")}" kaydı silinsin mi?'):
            self._vault["entries"].remove(entry)
            self._save()
            self._render()

    def _on_save_entry(self, entry):
        self._vault["entries"].append(entry)
        self._save()
        self._render()

    def _lock(self):
        self._key = None
        self._vault = {"entries": []}
        self.withdraw()
        for w in self._rows_frame.winfo_children():
            w.destroy()
        LoginWindow(self, self._on_login, is_new=False)

    def _start_lock_timer(self):
        def check():
            while self._key:
                time.sleep(10)
                if self._key and (time.time() - self._last_activity) > LOCK_AFTER:
                    self.after(0, self._lock)
                    break
        t = threading.Thread(target=check, daemon=True)
        t.start()

    def _reset_timer(self, *_):
        self._last_activity = time.time()


if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()
