import os
import tkinter as tk
from tkinter import filedialog
import tkinter.font as tkFont
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DB_FILE = 'file_encryption_db.sqlite'

def create_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encryption_keys (
            id INTEGER PRIMARY KEY,
            user_key BLOB NOT NULL,
            key_file_path TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY,
            key_id INTEGER,
            file_path TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            FOREIGN KEY (key_id) REFERENCES encryption_keys (id)
        )
    ''')

    conn.commit()
    conn.close()

def insert_key(user_key, key_file_path):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO encryption_keys (user_key, key_file_path) VALUES (?, ?)', (sqlite3.Binary(user_key), key_file_path))
    key_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return key_id

def insert_encrypted_file(key_id, file_path, encrypted_data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO encrypted_files (key_id, file_path, encrypted_data) VALUES (?, ?, ?)', (key_id, file_path, sqlite3.Binary(encrypted_data)))
    conn.commit()
    conn.close()

def get_user_key_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_key, key_file_path FROM encryption_keys')
    result = cursor.fetchone()
    conn.close()
    return result if result is not None else (None, None)

def get_key_id():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM encryption_keys')
    result = cursor.fetchone()
    conn.close()
    return result[0] if result is not None else None

def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return iv + tag + ciphertext

def decrypt(key, encrypted_data):
    header = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(header, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data

class SecureFileApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Encryption and Decryption")

        self.welcome_label = tk.Label(master, text="Welcome to the Secure File Encryption and Decryption Tool!", font=("Arial", 16, "bold"), fg="blue")
        self.welcome_label.pack(pady=20)

        self.generate_key_button = tk.Button(master, text="Generate Encryption Key", command=self.generate_key, bg="#3498db", fg="white", height=2, width=30)
        self.generate_key_button.pack(pady=10)

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt, bg="#4CAF50", fg="white", height=2, width=30)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt, bg="#FF5733", fg="white", height=2, width=30)
        self.decrypt_button.pack(pady=10)

        self.status_label = tk.Label(master, text="", font=("Arial", 12))
        self.status_label.pack()

        self.info_font = tkFont.Font(family="Helvetica", size=12, weight="bold", slant="italic")

        self.info_label = tk.Label(
            master,
            text="Instructions:\n1. Click 'Generate Encryption Key' to create a new encryption key.\n2. Use 'Encrypt File' to secure your files.\n3. 'Decrypt File' will restore encrypted files.",
            font=self.info_font,
            justify=tk.LEFT
        )
        self.info_label.pack(pady=20)

    def generate_key(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title="Save Key As")
        if not file_path:
            self.status_label.config(text="Key generation canceled.", fg="red")
            return

        user_key = os.urandom(32)
        with open(file_path, 'wb') as key_file:
            key_file.write(user_key)

        key_id = insert_key(user_key, file_path)

        self.status_label.config(text=f"Key generated and saved (ID: {key_id})", fg="blue")

    def encrypt(self):
        user_key, key_file_path = get_user_key_from_db()

        if user_key is None:
            self.status_label.config(text="Key not found. Please generate a key.", fg="red")
            return

        file_to_encrypt = filedialog.askopenfilename(title="Select file to encrypt")
        if file_to_encrypt:
            with open(file_to_encrypt, 'rb') as file:
                plaintext = file.read()

            encrypted_data = encrypt(user_key, plaintext)
            key_id = get_key_id()
            insert_encrypted_file(key_id, file_to_encrypt, encrypted_data)

            encrypted_filename = f"encrypted_{os.path.basename(file_to_encrypt)}"
            with open(encrypted_filename, 'wb') as file:
                file.write(encrypted_data)

            self.status_label.config(text=f"File '{file_to_encrypt}' encrypted and saved to the database and '{encrypted_filename}'.", fg="green")

    def decrypt(self):
        user_key, key_file_path = get_user_key_from_db()

        if user_key is None:
            self.status_label.config(text="Key not found. Please generate a key.", fg="red")
            return

        file_to_decrypt = filedialog.askopenfilename(title="Select file to decrypt")
        if file_to_decrypt:
            with open(file_to_decrypt, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = decrypt(user_key, encrypted_data)
            decrypted_filename = f"decrypted_{os.path.basename(file_to_decrypt)}"
            with open(decrypted_filename, 'wb') as file:
                file.write(decrypted_data)
            self.status_label.config(text=f"File '{file_to_decrypt}' decrypted. Decrypted data saved as '{decrypted_filename}'.", fg="green")

if __name__ == "__main__":
    create_table()
    root = tk.Tk()
    app = SecureFileApp(root)
    root.geometry("800x600")
    root.configure(bg="#ecf0f1")
    root.mainloop()
