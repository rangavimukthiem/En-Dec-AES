from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit,QLabel
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
        self.setStyleSheet("background-color: #9DB2BF")


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
                background:#ECDFCC;
            }
            QLineEdit:focus {
                border: 2px solid #0078d7;
            }
        """)
        self.layout.addWidget(self.text_input)





        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.setFixedWidth(300)


        self.encrypt_button.setStyleSheet(self.button_style())
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_button,alignment=QtCore.Qt.AlignCenter)


        #key input for decryption
        # Text field for input
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Enter Key ")
        self.key_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
                background:#ddE1D1;
            }
            QLineEdit:focus {
                border: 2px solid #0078d7;
            }
        """)
        self.key_input.setFixedWidth(500)
        self.layout.addWidget(self.key_input,alignment=QtCore.Qt.AlignCenter)
        #Iv input
        self.iv_input = QLineEdit(self)
        self.iv_input.setPlaceholderText("Enter IV ")
        self.iv_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
                background:#ddE1D1;
            }
            QLineEdit:focus {
                border: 2px solid #0078d7;
            }
        """)
        self.iv_input.setFixedWidth(500)
        self.layout.addWidget(self.iv_input,alignment=QtCore.Qt.AlignCenter)


        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.setStyleSheet(self.button_style())
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.decrypt_button.setFixedWidth(300)
        self.layout.addWidget(self.decrypt_button,alignment=QtCore.Qt.AlignCenter)

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
                background: #1A120B;
                font-family: 'Courier New', monospace;
                color:#399918;
            }
        """)
        self.layout.addWidget(self.result_display)

        # Clear button
        self.clear_button = QPushButton("Clear", self)
        self.clear_button.setStyleSheet(self.button_style())
        self.clear_button.clicked.connect(self.clear_result)
        self.layout.addWidget(self.clear_button)
        # bottom lable
        self.key = get_random_bytes(16)
        print(f"encrypt key > {self.key}")
        self.iv = get_random_bytes(16)
        print(f"encrypt iv > {self.iv}")


        self.keylable = QTextEdit()

        print(f"self.key>>>>>> {self.key}")

        self.keylable.setText(f"key >> {self.key}\n IV  >> {self.iv}")

        self.keylable.setStyleSheet("""
                color: #54473F;
                font-family: Arial, sans-serif;
                font-size""")
        self.layout.addWidget(self.keylable)

        self.lable = QLabel()
        self.lable.setText(
            "En-Dec Tool Is designed As AES Encryption-Decryption tool by GoldenPixel It Solutions : Contact Us goldenpixelithelp@gmail.com     ")
        self.lable.setStyleSheet("""
                color: #5C5470;
                font-family: Arial, sans-serif;
                font-size""")
        self.layout.addWidget(self.lable)

        self.setLayout(self.layout)

        # Generate a random AES key for this session
  # Fixed IV for demonstration; use different IV for each message in practice

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
        key=self.key_input.text()
        print(f"decrypt key > {key}")
        iv=self.iv_input.text()
        print(f"decrypt iv > {iv}")


        encrypted_text = self.text_input.text()
        if encrypted_text:
            try:
                encrypted_data = base64.b64decode(encrypted_text)
                cipher = AES.new(key, AES.MODE_CBC,iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                decrypted_text = decrypted_data.decode("utf-8")
                self.result_display.setText("Decrypted Text:\n" + decrypted_text)
            except (ValueError, KeyError,Exception):
                self.result_display.setText("Decryption failed. Invalid encrypted text or key.")
                print(f"error {Exception}")

        else:
            self.result_display.setText("Please enter some text to encrypt or decrypt.")



    def clear_result(self):
        """Clear the text from the result display."""
        self.result_display.clear()
        self.text_input.clear()
    def update_key(self):

        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
        print("key $ IV updated")

    def button_style(self):
        """Return a consistent style for buttons."""
        return """
            QPushButton {
                padding: 8px 12px;
                border: none;
                background: #27374D;
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



# Run the application
app = QApplication(sys.argv)
window = TextEncryptorDecryptor()
window.setStyleSheet("""
    QWidget {
        background: #5C5470;
        font-family: Arial, sans-serif;
        font-size:14;
    }
""")
window.show()
sys.exit(app.exec_())


