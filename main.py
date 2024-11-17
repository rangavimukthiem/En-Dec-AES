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
        self.setWindowTitle("Text Encryptor & Decryptor")
        self.setGeometry(200, 200, 400, 300)

        self.layout = QVBoxLayout()

        # Text field for input
        self.text_input = QLineEdit(self)
        self.text_input.setPlaceholderText("Enter text here...")
        self.layout.addWidget(self.text_input)

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.layout.addWidget(self.decrypt_button)


        # Result display area
        self.result_display = QTextEdit(self)
        self.result_display.setText("Sample encrypted code : y1BtKo6PRaw+hAJicbeTvT5jIyQOOdJedXzL9g2Glob+bQBoq1IwlZYbJJnSjHVL")
        self.result_display.setReadOnly(True)
        self.layout.addWidget(self.result_display)

        # clear button
        self.clear_button = QPushButton("Clear", self)
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
            encrypted_text = base64.b64encode(encrypted_data).decode('utf-8')
            self.result_display.setText("Encrypted Text:\n" + encrypted_text)
        else:
            self.result_display.setText("Please enter some text to encrypt or decrypt example: 'y1BtKo6PRaw+hAJicbeTvT5jIyQOOdJedXzL9g2Glob+bQBoq1IwlZYbJJnSjHVL'")

    def decrypt_text(self):
        encrypted_text = self.text_input.text()
        if encrypted_text:
            try:
                encrypted_data = base64.b64decode(encrypted_text)
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                decrypted_text = decrypted_data.decode('utf-8')
                self.result_display.setText("Decrypted Text:\n" + decrypted_text)
            except (ValueError, KeyError):
                self.result_display.setText("Decryption failed. Invalid encrypted text or key.")
        else:
            self.result_display.setText("Please enter some text to encrypt or decrypt.")

    def clear_result(self):
        """Clear the text from the result display."""
        self.result_display.clear()

# Run the application
app = QApplication(sys.argv)
window = TextEncryptorDecryptor()
window.show()
sys.exit(app.exec_())
