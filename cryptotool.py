import tkinter as tk
from tkinter import scrolledtext, messagebox
import base64
import string
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

# Constants
ALPHABET = string.ascii_uppercase

# Encryption algorithms
def caesar_cipher(message, key, mode='encrypt'):
    shifted_alphabet = ALPHABET[key:] + ALPHABET[:key]
    table = str.maketrans(ALPHABET, shifted_alphabet) if mode == 'encrypt' else str.maketrans(shifted_alphabet, ALPHABET)
    return message.upper().translate(table)

def vigenere_cipher(message, key, mode='encrypt'):
    key = key.upper()
    key_length = len(key)
    key_as_int = [ALPHABET.index(char) for char in key]
    message = message.upper()
    translated = ""
    for i, char in enumerate(message):
        if char in ALPHABET:
            shift = key_as_int[i % key_length]
            shift = shift if mode == 'encrypt' else -shift
            translated += ALPHABET[(ALPHABET.index(char) + shift) % len(ALPHABET)]
        else:
            translated += char
    return translated

def vernam_cipher(message, key):
    message = message.upper()
    key = key.upper()
    if len(message) != len(key):
        raise ValueError("Message and key must be of the same length")
    translated = ""
    for m_char, k_char in zip(message, key):
        if m_char in ALPHABET and k_char in ALPHABET:
            shift = ALPHABET.index(k_char)
            translated += ALPHABET[(ALPHABET.index(m_char) + shift) % len(ALPHABET)]
        else:
            translated += m_char
    return translated

def rsa_encrypt(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

def rsa_decrypt(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted_message.decode()

# GUI Application
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Cryptography Suite')
        self.geometry('600x400')

        # Components
        self.create_widgets()

    def create_widgets(self):
        # Message Input
        tk.Label(self, text="Message:").pack(pady=(10,0))
        self.message_entry = scrolledtext.ScrolledText(self, height=3, width=50)
        self.message_entry.pack()

        # Key Input
        tk.Label(self, text="Key:").pack(pady=(10,0))
        self.key_entry = tk.Entry(self, width=53)
        self.key_entry.pack()

        # Cipher Selection
        tk.Label(self, text="Select Cipher:").pack(pady=(10,0))
        self.cipher_var = tk.StringVar(self)
        self.ciphers = {'Caesar': caesar_cipher, 'Vigenère': vigenere_cipher, 'Vernam': vernam_cipher}
        self.cipher_var.set('Caesar') # set default value
        self.cipher_menu = tk.OptionMenu(self, self.cipher_var, *self.ciphers.keys())
        self.cipher_menu.pack()

        # Encrypt Button
        encrypt_button = tk.Button(self, text="Encrypt", command=self.encrypt_message)
        encrypt_button.pack(pady=(10,5))

        # Decrypt Button
        decrypt_button = tk.Button(self, text="Decrypt", command=self.decrypt_message)
        decrypt_button.pack(pady=5)

        # Result Display
        tk.Label(self, text="Result:").pack(pady=(10,0))
        self.result_text = scrolledtext.ScrolledText(self, height=3, width=50)
        self.result_text.pack()

    def encrypt_message(self):
        message = self.message_entry.get('1.0', tk.END).strip()
        key = self.key_entry.get().strip()
        cipher = self.ciphers[self.cipher_var.get()]
        try:
            if isinstance(key, str) and not key.isdigit() and self.cipher_var.get() != 'Vernam':
                raise ValueError("Key must be numeric for Caesar Cipher")
            key = int(key) if self.cipher_var.get() == 'Caesar' else key
            result = cipher(message, key, mode='encrypt')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_message(self):
        message = self.message_entry.get('1.0', tk.END).strip()
        key = self.key_entry.get().strip()
        cipher = self.ciphers[self.cipher_var.get()]
        try:
            if isinstance(key, str) and not key.isdigit() and self.cipher_var.get() != 'Vernam':
                raise ValueError("Key must be numeric for Caesar Cipher")
            key = int(key) if self.cipher_var.get() == 'Caesar' else key
            result = cipher(message, key, mode='decrypt')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    app = CryptoApp()
    app.mainloop()
