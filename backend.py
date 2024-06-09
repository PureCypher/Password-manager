"""
Name: backend.py
Author: PureCypher
Version: 1.0
"""


import sqlite3
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class PasswordManagerBackend:
    """
    Backend class for managing password storage, encryption, and decryption.

    Attributes:
        db_name (str): The name of the SQLite database file.
        key (bytes): The encryption key derived from the master password.
        conn (sqlite3.Connection): The SQLite database connection.
    """
    def __init__(self, db_name="passwords.db"):
        """
        Initialize the PasswordManagerBackend.

        Args:
            db_name (str): The name of the SQLite database file.
        """
        self.db_name = db_name
        self.key = None  # Key will be derived from master password
        self.conn = sqlite3.connect(self.db_name)
        self.create_table()

    def derive_key(self, master_password):
        """
        Derive a 16-byte encryption key from the master password using PBKDF2.

        Args:
            master_password (str): The master password entered by the user.
        """
        salt = b'some_salt'  # Should be stored and retrieved securely
        self.key = PBKDF2(master_password, salt, dkLen=16)

    def encrypt(self, plain_text):
        """
        Encrypt the plain text using AES encryption.

        Args:
            plain_text (str): The plain text to encrypt.

        Returns:
            str: The encrypted text encoded in base64.
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, _ = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
        return b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_text):
        """
        Decrypt the encrypted text using AES decryption.

        Args:
            encrypted_text (str): The encrypted text encoded in base64.

        Returns:
            str: The decrypted plain text.
        """
        encrypted_data = b64decode(encrypted_text)
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt(ciphertext).decode('utf-8')
        return plain_text

    def create_table(self):
        """
        Create the passwords table in the database if it does not exist.
        """
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            """)

    def add_password(self, website, username, password):
        """
        Add a new password to the database.

        Args:
            website (str): The website associated with the password.
            username (str): The username associated with the password.
            password (str): The plain text password to store.
        """
        encrypted_password = self.encrypt(password)
        with self.conn:
            self.conn.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                              (website, username, encrypted_password))

    def get_passwords(self):
        """
        Retrieve all passwords from the database.

        Returns:
            list: A list of dictionaries containing password entries.
        """
        with self.conn:
            cursor = self.conn.execute("SELECT id, website, username, password FROM passwords")
            passwords = []
            for row in cursor:
                passwords.append({
                    "id": row[0],
                    "website": row[1],
                    "username": row[2],
                    "password": self.decrypt(row[3])
                })
            return passwords

    def update_password(self, password_id, website, username, password):
        """
        Update an existing password in the database.

        Args:
            password_id (int): The ID of the password entry to update.
            website (str): The website associated with the password.
            username (str): The username associated with the password.
            password (str): The plain text password to store.
        """
        encrypted_password = self.encrypt(password)
        with self.conn:
            self.conn.execute("""
                UPDATE passwords
                SET website = ?, username = ?, password = ?
                WHERE id = ?
            """, (website, username, encrypted_password, password_id))

    def delete_password(self, password_id):
        """
        Delete a password from the database.

        Args:
            password_id (int): The ID of the password entry to delete.
        """
        with self.conn:
            self.conn.execute("DELETE FROM passwords WHERE id = ?", (password_id,))

    def close(self):
        """
        Close the database connection.
        """
        self.conn.close()

# Example usage:
if __name__ == "__main__":
    pm = PasswordManagerBackend()
    pm.close()
