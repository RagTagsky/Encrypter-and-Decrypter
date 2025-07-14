import sys
import os
import hmac
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
                             QSpacerItem, QSizePolicy, QTabWidget, QFormLayout, QHBoxLayout)
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Генерация ключа
def generate_key_iv():
    key = os.urandom(32)  # 256-битный ключ для AES-256
    iv = os.urandom(16)   # 128-битный IV для CBC
    return key, iv

# Генерация HMAC
def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).digest()

# Шифрование
def encrypt_file(input_file, output_file, key, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        hmac_digest = generate_hmac(ciphertext, key)

        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext + hmac_digest)

        return True
    except Exception as e:
        return str(e)

# Дешифрование
def decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            iv = f.read(16)
            content = f.read()
            hmac_digest = content[-32:]
            ciphertext = content[:-32]

        if generate_hmac(ciphertext, key) != hmac_digest:
            return "HMAC signature mismatch! The file may be corrupted or the key is invalid."

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        return True
    except Exception as e:
        return str(e)


# Вкладка шифрования

class EncryptionTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()
        layout.addLayout(form)

        self.input_file_encrypt = QLineEdit()
        self.browse_encrypt_button = QPushButton("Browse")
        self.browse_encrypt_button.clicked.connect(self.browse_encrypt_file)
        file_input_layout = QHBoxLayout()
        file_input_layout.addWidget(self.input_file_encrypt)
        file_input_layout.addWidget(self.browse_encrypt_button)
        form.addRow("File to encrypt:", file_input_layout)

        self.output_file_encrypt = QLineEdit()
        form.addRow("Save as:", self.output_file_encrypt)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt_action)
        layout.addWidget(self.encrypt_button)

        layout.addStretch()
        self.setLayout(layout)

    def browse_encrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if file_name:
            self.input_file_encrypt.setText(file_name)

    def encrypt_action(self):
        input_file = self.input_file_encrypt.text()
        output_file = self.output_file_encrypt.text()

        if not input_file or not output_file:
            QMessageBox.warning(self, "Error", "Please specify both input and output files.")
            return

        if os.path.exists(output_file):
            QMessageBox.warning(self, "Error", "Output file already exists. Delete it or choose another name.")
            return

        key, iv = generate_key_iv()
        result = encrypt_file(input_file, output_file, key, iv)

        if result is True:
            key_file_path, _ = QFileDialog.getSaveFileName(self, "Save Key", "Key.bin", "Binary Files (*.bin)")
            if key_file_path:
                with open(key_file_path, "wb") as key_file:
                    key_file.write(key)
                QMessageBox.information(self, "Success", "File encrypted successfully. Key saved.")
            else:
                QMessageBox.warning(self, "Warning", "Key was not saved because no path was specified.")
        else:
            QMessageBox.critical(self, "Error", f"Encryption error: {result}")


# Вкладка дешифрования

class DecryptionTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()
        layout.addLayout(form)

        self.input_file_decrypt = QLineEdit()
        self.browse_decrypt_button = QPushButton("Browse")
        self.browse_decrypt_button.clicked.connect(self.browse_decrypt_file)
        decrypt_layout = QHBoxLayout()
        decrypt_layout.addWidget(self.input_file_decrypt)
        decrypt_layout.addWidget(self.browse_decrypt_button)
        form.addRow("Encrypted file:", decrypt_layout)

        self.output_file_decrypt = QLineEdit()
        form.addRow("Save as:", self.output_file_decrypt)

        self.key_file = QLineEdit()
        self.browse_key_button = QPushButton("Browse")
        self.browse_key_button.clicked.connect(self.browse_key_file)
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_file)
        key_layout.addWidget(self.browse_key_button)
        form.addRow("Key file:", key_layout)

        self.decrypt_button = QPushButton("🔓 Decrypt File")
        self.decrypt_button.clicked.connect(self.decrypt_action)
        layout.addWidget(self.decrypt_button)

        layout.addStretch()
        self.setLayout(layout)

    def browse_decrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if file_name:
            self.input_file_decrypt.setText(file_name)

    def browse_key_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select key file")
        if file_name:
            self.key_file.setText(file_name)

    def decrypt_action(self):
        input_file = self.input_file_decrypt.text()
        output_file = self.output_file_decrypt.text()
        key_file_path = self.key_file.text()

        if not input_file or not output_file or not key_file_path:
            QMessageBox.warning(self, "Error", "Please specify input, output, and key files.")
            return

        try:
            with open(key_file_path, "rb") as key_file:
                key = key_file.read()

            result = decrypt_file(input_file, output_file, key)

            if result is True:
                QMessageBox.information(self, "Success", "File decrypted successfully.")
            else:
                QMessageBox.critical(self, "Error", f"Decryption error: {result}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read key: {e}")

# Основной интерфейс 
class FileEncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Encryptor & Decryptor")
        self.resize(500, 320)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        self.tab_widget = QTabWidget()

        self.encryption_tab = EncryptionTab(self)
        self.decryption_tab = DecryptionTab(self)

        self.tab_widget.addTab(self.encryption_tab, "Encryption")
        self.tab_widget.addTab(self.decryption_tab, "Decryption")

        self.main_layout.addWidget(self.tab_widget, stretch=1)

        self.bottom_widget = QWidget()
        self.main_layout.addWidget(self.bottom_widget, stretch=1)

        self.central_widget.setStyleSheet("background-color: #ffffff;")

# Запуск
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec_())
