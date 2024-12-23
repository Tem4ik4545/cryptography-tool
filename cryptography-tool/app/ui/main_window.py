import sys
import requests
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLabel, QLineEdit, QMessageBox, QTextEdit, QComboBox
)
from PyQt6.QtCore import Qt
from app.ui.worker import WorkerThread
import os

API_BASE_URL = "http://127.0.0.1:8000"


class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cryptography Tool")
        self.setGeometry(300, 300, 500, 1000)

        # Инициализация макета
        self.layout = QVBoxLayout()

        # --- Key Management ---
        self.add_section_label("Key Management")
        self.key_name_input = QLineEdit()
        self.key_name_input.setPlaceholderText("Enter key name")
        self.layout.addWidget(self.key_name_input)

        self.key_password_input = QLineEdit()
        self.key_password_input.setPlaceholderText("Enter password for key container")
        self.key_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.key_password_input)

        self.generate_keys_button = QPushButton("Generate Keys")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        self.layout.addWidget(self.generate_keys_button)

        self.delete_keys_button = QPushButton("Delete Key")
        self.delete_keys_button.clicked.connect(self.delete_keys)
        self.layout.addWidget(self.delete_keys_button)

        # --- File Encryption/Decryption ---
        self.add_section_label("File Encryption/Decryption")
        self.file_label = QLabel("No file selected")
        self.layout.addWidget(self.file_label)

        self.choose_file_button = QPushButton("Choose File")
        self.choose_file_button.clicked.connect(self.choose_file)
        self.layout.addWidget(self.choose_file_button)

        self.file_algorithm_selector = QComboBox()
        self.file_algorithm_selector.addItems(["AES", "RSA"])
        self.file_algorithm_selector.currentTextChanged.connect(self.toggle_file_fields)
        self.layout.addWidget(self.file_algorithm_selector)

        self.file_aes_password_input = QLineEdit()
        self.file_aes_password_input.setPlaceholderText("Enter password for AES")
        self.layout.addWidget(self.file_aes_password_input)
        self.file_aes_password_input.hide()

        self.file_rsa_key_name_input = QLineEdit()
        self.file_rsa_key_name_input.setPlaceholderText("Enter key name (RSA)")
        self.layout.addWidget(self.file_rsa_key_name_input)
        self.file_rsa_key_name_input.hide()

        self.file_rsa_password_input = QLineEdit()
        self.file_rsa_password_input.setPlaceholderText("Enter password for RSA")
        self.file_rsa_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.file_rsa_password_input)
        self.file_rsa_password_input.hide()

        self.encrypt_file_button = QPushButton("Encrypt File")
        self.encrypt_file_button.clicked.connect(self.encrypt_file)
        self.layout.addWidget(self.encrypt_file_button)

        self.decrypt_file_button = QPushButton("Decrypt File")
        self.decrypt_file_button.clicked.connect(self.decrypt_file)
        self.layout.addWidget(self.decrypt_file_button)

        # --- Text Encryption/Decryption ---
        self.add_section_label("Text Encryption/Decryption")
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt or decrypt")
        self.layout.addWidget(self.text_input)

        self.text_algorithm_selector = QComboBox()
        self.text_algorithm_selector.addItems(["AES", "RSA"])
        self.text_algorithm_selector.currentTextChanged.connect(self.toggle_text_fields)
        self.layout.addWidget(self.text_algorithm_selector)

        self.text_aes_password_input = QLineEdit()
        self.text_aes_password_input.setPlaceholderText("Enter password for AES")
        self.layout.addWidget(self.text_aes_password_input)
        self.text_aes_password_input.hide()

        self.text_rsa_key_name_input = QLineEdit()
        self.text_rsa_key_name_input.setPlaceholderText("Enter key name (RSA)")
        self.layout.addWidget(self.text_rsa_key_name_input)
        self.text_rsa_key_name_input.hide()

        self.text_rsa_password_input = QLineEdit()
        self.text_rsa_password_input.setPlaceholderText("Enter password for RSA")
        self.text_rsa_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.text_rsa_password_input)
        self.text_rsa_password_input.hide()

        self.encrypt_text_button = QPushButton("Encrypt Text")
        self.encrypt_text_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_text_button)

        self.decrypt_text_button = QPushButton("Decrypt Text")
        self.decrypt_text_button.clicked.connect(self.decrypt_text)
        self.layout.addWidget(self.decrypt_text_button)

        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        self.layout.addWidget(self.text_output)

        # --- Digital Signature for File ---
        self.add_section_label("Digital Signature for Files")

        # Выбор файла для подписи
        self.file_to_sign_label = QLabel("No file selected for signing or verification")
        self.layout.addWidget(self.file_to_sign_label)

        self.choose_file_to_sign_button = QPushButton("Choose File")
        self.choose_file_to_sign_button.clicked.connect(self.choose_file_to_sign)
        self.layout.addWidget(self.choose_file_to_sign_button)

        # Поле для вывода хэшсуммы файла
        self.file_hash_label = QLabel("File Hash: Not calculated yet")
        self.layout.addWidget(self.file_hash_label)

        # Ввод ключа для подписи
        self.sign_key_name_input = QLineEdit()
        self.sign_key_name_input.setPlaceholderText("Enter key name (for signing)")
        self.layout.addWidget(self.sign_key_name_input)

        # Ввод пароля для подписи
        self.sign_password_input = QLineEdit()
        self.sign_password_input.setPlaceholderText("Enter password for key container")
        self.sign_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.sign_password_input)

        # Кнопка создания подписи
        self.sign_file_button = QPushButton("Sign File")
        self.sign_file_button.clicked.connect(self.sign_file)
        self.layout.addWidget(self.sign_file_button)


        # Кнопка проверки подписи
        self.verify_signature_button = QPushButton("Verify File Signature")
        self.verify_signature_button.clicked.connect(self.verify_signature)
        self.layout.addWidget(self.verify_signature_button)

        # Поле для вывода статуса проверки подписи
        self.verification_result_label = QLabel("")
        self.layout.addWidget(self.verification_result_label)

        # Устанавливаем макет
        self.setLayout(self.layout)

    def add_section_label(self, text):
        label = QLabel(f"--- {text} ---")
        label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(label)

    def choose_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if file_path:
            self.selected_file = file_path
            self.file_label.setText(f"Selected: {file_path}")

    def toggle_file_fields(self, algorithm):
        if algorithm == "AES":
            self.file_aes_password_input.show()
            self.file_rsa_key_name_input.hide()
            self.file_rsa_password_input.hide()
        elif algorithm == "RSA":
            self.file_aes_password_input.hide()
            self.file_rsa_key_name_input.show()
            self.file_rsa_password_input.show()

    def toggle_text_fields(self, algorithm):
        if algorithm == "AES":
            self.text_aes_password_input.show()
            self.text_rsa_key_name_input.hide()
            self.text_rsa_password_input.hide()
        elif algorithm == "RSA":
            self.text_aes_password_input.hide()
            self.text_rsa_key_name_input.show()
            self.text_rsa_password_input.show()

    def run_worker(self, url, method="POST", data=None, files=None):
        self.worker = WorkerThread(url, method, data, files)
        self.worker.finished.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_success(self, result):
        if isinstance(result, dict):
            if "encrypted_text" in result:
                self.text_output.setPlainText(result["encrypted_text"])
            elif "decrypted_text" in result:
                self.text_output.setPlainText(result["decrypted_text"])
            elif "signature_file" in result:
                QMessageBox.information(self, "Success", "File signed successfully.")
                if "file_hash" in result:
                    self.file_hash_label.setText(f"File Hash: {result['file_hash']}")
            elif "valid" in result:
                valid_msg = "Подпись подтверждена." if result["valid"] else "Подпись недействительна."
                QMessageBox.information(self, "Результат проверки", valid_msg, QMessageBox.StandardButton.Ok)
            else:
                QMessageBox.information(self, "Успех", str(result), QMessageBox.StandardButton.Ok)

    def on_error(self, error_message):
        QMessageBox.critical(self, "Error", error_message, QMessageBox.StandardButton.Ok)

    # --- Methods ---
    # Для генерации ключей
    # Для генерации ключей
    # Для генерации ключей
    def generate_keys(self):
        url = f"{API_BASE_URL}/signature/generate-keys"
        data = {
            "key_name": self.key_name_input.text(),
            "password": self.key_password_input.text()
        }
        self.run_worker(url, method="POST", data=data)

    def delete_keys(self):
        key_name = self.key_name_input.text()
        password = self.key_password_input.text()

        if not key_name or not password:
            QMessageBox.warning(self, "Error", "Key name and password are required.")
            return

        url = f"{API_BASE_URL}/signature/remove-key"
        params = {"key_name": key_name, "password": password}
        response = requests.delete(url, params=params)

        if response.status_code == 200:
            QMessageBox.information(self, "Success", response.json()["message"], QMessageBox.StandardButton.Ok)
        else:
            QMessageBox.critical(self, "Error", f"Failed to delete key: {response.text}", QMessageBox.StandardButton.Ok)

    # Для файла
    # Для файла
    # Для файла
    def encrypt_file(self):
        algorithm = self.file_algorithm_selector.currentText()
        url = f"{API_BASE_URL}/encryption/encrypt-file"
        files = {"file": open(self.selected_file, "rb")}
        data = {"algorithm": algorithm}
        if algorithm == "AES":
            data["password"] = self.file_aes_password_input.text()
        elif algorithm == "RSA":
            data["key_name"] = self.file_rsa_key_name_input.text()
            data["password"] = self.file_rsa_password_input.text()

        self.run_worker(url, method="POST", data=data, files=files)

    def decrypt_file(self):
        algorithm = self.file_algorithm_selector.currentText()
        url = f"{API_BASE_URL}/encryption/decrypt-file"
        files = {"file": open(self.selected_file, "rb")}
        data = {"algorithm": algorithm}
        if algorithm == "AES":
            data["password"] = self.file_aes_password_input.text()
        elif algorithm == "RSA":
            data["key_name"] = self.file_rsa_key_name_input.text()
            data["password"] = self.file_rsa_password_input.text()

        self.run_worker(url, method="POST", data=data, files=files)

    # Для текста
    # Для текста
    # Для текста
    def encrypt_text(self):
        algorithm = self.text_algorithm_selector.currentText()
        url = f"{API_BASE_URL}/encryption/encrypt-text"
        data = {
            "text": self.text_input.toPlainText(),
            "algorithm": algorithm
        }
        if algorithm == "AES":
            data["password"] = self.text_aes_password_input.text()
        elif algorithm == "RSA":
            data["key_name"] = self.text_rsa_key_name_input.text()
            data["password"] = self.text_rsa_password_input.text()

        # Отправляем запрос на сервер
        self.worker = WorkerThread(url, method="POST", data=data)
        self.worker.finished.connect(self.on_encrypt_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def decrypt_text(self):
        algorithm = self.text_algorithm_selector.currentText()
        url = f"{API_BASE_URL}/encryption/decrypt-text"
        data = {
            "text": self.text_input.toPlainText(),
            "algorithm": algorithm
        }
        if algorithm == "AES":
            data["password"] = self.text_aes_password_input.text()
        elif algorithm == "RSA":
            data["key_name"] = self.text_rsa_key_name_input.text()
            data["password"] = self.text_rsa_password_input.text()

        # Отправляем запрос на сервер
        self.worker = WorkerThread(url, method="POST", data=data)
        self.worker.finished.connect(self.on_decrypt_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_encrypt_success(self, result):
        # Записываем зашифрованный текст в поле
        self.text_output.setPlainText(result["encrypted_text"])

    def on_decrypt_success(self, result):
        # Записываем расшифрованный текст в поле
        self.text_output.setPlainText(result["decrypted_text"])

    # Подпись
    # Подпись
    # Подпись
    def choose_file_to_sign(self):
        """
        Выбор файла для подписи или проверки.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose File", "", "All Files (*)")
        if file_path:
            self.file_to_sign = file_path
            self.file_to_sign_label.setText(f"Selected: {file_path}")

    def sign_file(self):
        """
        Создание цифровой подписи для файла.
        """
        url = f"{API_BASE_URL}/signature/sign-file"
        if not hasattr(self, "file_to_sign"):
            QMessageBox.warning(self, "Error", "No file selected for signing.")
            return

        files = {"file": open(self.file_to_sign, "rb")}
        data = {
            "key_name": self.sign_key_name_input.text(),
            "password": self.sign_password_input.text(),
        }

        self.run_worker(url, method="POST", data=data, files=files)

    def verify_signature(self):
        """
        Проверка подписи для файла.
        """
        if not hasattr(self, "file_to_sign"):
            QMessageBox.warning(self, "Error", "No file selected for verification.")
            return

        # Путь к подписи и сертификату
        signature_path = self.file_to_sign + ".sig"
        certificate_path = self.file_to_sign + ".cert"

        if not os.path.exists(signature_path):
            QMessageBox.critical(self, "Error", f"Signature file not found: {signature_path}")
            return

        if not os.path.exists(certificate_path):
            QMessageBox.critical(self, "Error", f"Certificate file not found: {certificate_path}")
            return

        # Отправка данных на сервер
        url = f"{API_BASE_URL}/signature/verify-file"
        files = {
            "file": open(self.file_to_sign, "rb"),
            "signature": open(signature_path, "rb"),
            "certificate": open(certificate_path, "rb"),
        }

        self.run_worker(url, method="POST", files=files)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec())
