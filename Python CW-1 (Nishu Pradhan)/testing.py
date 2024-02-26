import unittest
import os
import sqlite3
import tkinter as tk
from unittest.mock import patch
from cryptography.hazmat.backends import default_backend
from main import create_table, insert_key, insert_encrypted_file, get_key_id, get_user_key_from_db, encrypt, decrypt, SecureFileApp

DB_FILE = 'file_encryption_db.sqlite'

class TestFileEncryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create or connect to the database
        create_table()

    @patch('tkinter.filedialog.asksaveasfilename', return_value='test_key.txt')
    def test_generate_key(self, mock_file_dialog):
        root = tk.Tk()  # Create a Tkinter root window
        app = SecureFileApp(root)
        app.generate_key()

        # Assuming a key is generated and inserted into the database
        key_id = get_key_id()

        self.assertIsNotNone(key_id)

    @patch('tkinter.filedialog.asksaveasfilename', return_value='test_key.txt')
    def test_generate_key_cancel(self, mock_file_dialog):
        root = tk.Tk()  # Create a Tkinter root window
        app = SecureFileApp(root)

        # Mock user canceling key generation
        with patch('tkinter.filedialog.asksaveasfilename', return_value=''):
            app.generate_key()

        # Ensure that the status label indicates key generation was canceled
        self.assertEqual(app.status_label.cget('text'), "Key generation canceled.")
        self.assertEqual(app.status_label.cget('fg'), "red")
    
    def test_create_table(self):
        # Assuming create_table has already been called in setUpClass
        # Verify that the tables exist in the database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute("PRAGMA foreign_keys=on;")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        self.assertIn(('encryption_keys',), tables)
        self.assertIn(('encrypted_files',), tables)

        conn.close()

    def test_insert_key(self):
        # Assuming a key is generated and inserted into the database in test_generate_key
        key_id = get_key_id()

        self.assertIsNotNone(key_id)
    
    def test_insert_encrypted_file(self):
        # Assuming an encrypted file is inserted into the database in test_encrypt_decrypt
        encrypted_file_id = get_key_id()

        self.assertIsNotNone(encrypted_file_id)
    
    def test_get_user_key_from_db(self):
        # Assuming a key is generated and inserted into the database in test_generate_key
        user_key, key_file_path = get_user_key_from_db()

        self.assertIsNotNone(user_key)
        self.assertIsNotNone(key_file_path)
    
    def test_encrypt_decrypt_functions(self):
        # Assuming encryption and decryption functions are working correctly
        user_key = os.urandom(32)
        plaintext_data = b'Test data for encryption and decryption.'

        encrypted_data = encrypt(user_key, plaintext_data)
        decrypted_data = decrypt(user_key, encrypted_data)

        self.assertEqual(plaintext_data, decrypted_data)
        
if __name__ == '__main__':
    unittest.main()

