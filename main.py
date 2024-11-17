from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import base64


class TextEncryptorDecryptor(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the UI components
        self.setWindowTitle("En-Dec ASE Tool")
        self.setGeometry(200, 200, 500, 400)


        self.layout = QVBoxLayout()


        # Text field for input
        self.text_input = QLineEdit(self)
        self.text_input.setPlaceholderText("Enter text here...")
        self.text_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 2px solid #0078d7;
            }
        """)
        self.layout.addWidget(self.text_input)

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.setStyleSheet(self.button_style())
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.setStyleSheet(self.button_style())
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.layout.addWidget(self.decrypt_button)

        # Result display area
        self.result_display = QTextEdit(self)
        self.result_display.setText(
            "Sample encrypted code: y1BtKo6PRaw+hAJicbeTvT5jIyQOOdJedXzL9g2Glob+bQBoq1IwlZYbJJnSjHVL"
        )
        self.result_display.setReadOnly(True)
        self.result_display.setStyleSheet("""
            QTextEdit {
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 5px;
                background: #f9f9f9;
                font-family: 'Courier New', monospace;
            }
        """)
        self.layout.addWidget(self.result_display)

        # Clear button
        self.clear_button = QPushButton("Clear", self)
        self.clear_button.setStyleSheet(self.button_style())
        self.clear_button.clicked.connect(self.clear_result)
        self.layout.addWidget(self.clear_button)

        self.setLayout(self.layout)

        # Generate a random AES key for this session
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)  # Fixed IV for demonstration; use different IV for each message in practice

    def encrypt_text(self):
        plaintext = self.text_input.text()
        if plaintext:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            padded_data = pad(plaintext.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            # Encode in base64 for readability and display in result area
            encrypted_text = base64.b64encode(encrypted_data).decode("utf-8")
            self.result_display.setText("Encrypted Text:\n" + encrypted_text)
        else:
            self.result_display.setText(
                "Please enter some text to encrypt or decrypt example: G08NL8azlU8P6kq0eQJopDA87/gELJAJxaI7nmVNQ1s007U/jvCKFRoW8aSe8oH2 "
            )
        self.text_input.clear()
# Contact Us: goldenpixelit@gmail.com
    def decrypt_text(self):
        encrypted_text = self.text_input.text()
        if encrypted_text:
            try:
                encrypted_data = base64.b64decode(encrypted_text)
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                decrypted_text = decrypted_data.decode("utf-8")
                self.result_display.setText("Decrypted Text:\n" + decrypted_text)
            except (ValueError, KeyError):
                self.result_display.setText("Decryption failed. Invalid encrypted text or key.")
        else:
            self.result_display.setText("Please enter some text to encrypt or decrypt.")
        self.text_input.clear()

    def clear_result(self):
        """Clear the text from the result display."""
        self.result_display.clear()
        self.text_input.clear()

    def button_style(self):
        """Return a consistent style for buttons."""
        return """
            QPushButton {
                padding: 8px 12px;
                border: none;
                background: #0078d7;
                color: white;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #005fa3;
            }
            QPushButton:pressed {
                background: #003d70;
            }
        """
        self.setStyleSheet("background-color: AE445A")


# Run the application
app = QApplication(sys.argv)
window = TextEncryptorDecryptor()
window.setStyleSheet("""
    QWidget {
        background: #f5f5f5;
        font-family: Arial, sans-serif;
    }
""")
window.show()
sys.exit(app.exec_())
