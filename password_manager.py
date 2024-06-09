"""
Name: password_manager.py
Author: PureCypher
Version: 1.0
"""


import sys
from backend import PasswordManagerBackend
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QMessageBox

class PasswordManager(QMainWindow):
    """
    Main window class for the password manager GUI.
    """
    def __init__(self):
        """
        Initialize the PasswordManager.
        """
        super().__init__()

        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        self.backend = PasswordManagerBackend()  # Initialize the backend

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.setWindowIcon(QIcon("password-minimalistic.png"))

        self.layout = QVBoxLayout(self.central_widget)

        self.login_label = QLabel("Enter Master Password:")
        self.layout.addWidget(self.login_label)

        self.login_input = QLineEdit()
        self.login_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.login_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.show_main_window)
        self.layout.addWidget(self.login_button)

        self.main_layout = QVBoxLayout()
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(4)
        self.password_table.setHorizontalHeaderLabels(["ID", "Website", "Username", "Password"])
        self.password_table.setColumnHidden(0, True)  # Hide the ID column
        self.main_layout.addWidget(self.password_table)

        self.add_button = QPushButton("Add Password")
        self.add_button.clicked.connect(self.add_password)
        self.main_layout.addWidget(self.add_button)

        self.edit_button = QPushButton("Edit Password")
        self.main_layout.addWidget(self.edit_button)
        self.delete_button = QPushButton("Delete Password")

        self.delete_button.clicked.connect(self.delete_password)
        self.main_layout.addWidget(self.delete_button)

        self.central_widget.setLayout(self.layout)

        self.add_password_window = QWidget()
        self.website_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.save_button = QPushButton("Save")

    def show_main_window(self):
        """
        Handle the login process and display the main password management interface.
        """
        master_password = self.login_input.text()
        if master_password:
            self.backend.derive_key(master_password)
            self.login_label.hide()
            self.login_input.hide()
            self.login_button.hide()
            self.layout.addLayout(self.main_layout)
            self.load_passwords()

    def add_password(self):
        """
        Display the window to add a new password.
        """
        self.add_password_window.setWindowTitle("Add Password")
        self.add_password_window.setGeometry(150, 150, 400, 200)

        layout = QVBoxLayout()

        self.website_input.setPlaceholderText("Website")
        layout.addWidget(self.website_input)

        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input.setPlaceholderText("Password")
        layout.addWidget(self.password_input)

        self.save_button.clicked.connect(self.save_password)
        layout.addWidget(self.save_button)

        self.add_password_window.setLayout(layout)
        self.add_password_window.show()

    def save_password(self):
        """
        Save the new password to the backend and update the table.
        """
        website = self.website_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if website and username and password:
            self.backend.add_password(website, username, password)
            self.load_passwords()
            self.add_password_window.close()

    def load_passwords(self):
        """
        Load passwords from the backend and display them in the table.
        """
        self.password_table.setRowCount(0)
        passwords = self.backend.get_passwords()
        for password in passwords:
            row_position = self.password_table.rowCount()
            self.password_table.insertRow(row_position)
            self.password_table.setItem(row_position, 0, QTableWidgetItem(str(password["id"])))
            self.password_table.setItem(row_position, 1, QTableWidgetItem(password["website"]))
            self.password_table.setItem(row_position, 2, QTableWidgetItem(password["username"]))
            self.password_table.setItem(row_position, 3, QTableWidgetItem(password["password"]))

    def delete_password(self):
        """
        Delete the selected password from the backend and update the table.
        """
        selected_row = self.password_table.currentRow()
        password_id_item = self.password_table.item(selected_row, 0)
        if not selected_row >=0:
            QMessageBox.warning(self, "No Selection", "Please select a password to delete.")
        if password_id_item:
            password_id = int(password_id_item.text())
            confirm = QMessageBox.question(
                self, "Confirm Delete",
                "Are you sure you want to delete this password?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm == QMessageBox.StandardButton.Yes:
                self.backend.delete_password(password_id)
                self.load_passwords()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
