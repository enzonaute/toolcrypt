import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import random
import string

# Constants
ALPHABET = string.ascii_uppercase

def caesar_cipher(message, key, mode='encrypt'):
    try:
        key = int(key)  # Ensure key is an integer
        shifted_alphabet = ALPHABET[key:] + ALPHABET[:key]
        table = str.maketrans(ALPHABET, shifted_alphabet) if mode == 'encrypt' else str.maketrans(shifted_alphabet, ALPHABET)
        return message.upper().translate(table)
    except ValueError:
        messagebox.showerror("Error", "Invalid key for Caesar Cipher. Key must be an integer.")
        return None

# GUI Application
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Cryptography Suite')
        self.geometry('600x400')
        self.create_widgets()

    def create_widgets(self):
        global message_entry, key_entry, result_text
        # Message Input
        ttk.Label(self, text="Message:").pack(pady=(10,0))
        message_entry = scrolledtext.ScrolledText(self, height=3, width=50)
        message_entry.pack()

        # Key Input
        ttk.Label(self, text="Key:").pack(pady=(10,0))
        key_entry = ttk.Entry(self, width=53)
        key_entry.pack()

        # Encrypt and Decrypt Buttons
        ttk.Button(self, text="Encrypt", command=self.encrypt_message).pack(pady=(5,2))
        ttk.Button(self, text="Decrypt", command=self.decrypt_message).pack(pady=(2,5))

        # Result Display
        ttk.Label(self, text="Result:").pack(pady=(10,0))
        result_text = scrolledtext.ScrolledText(self, height=3, width=50)
        result_text.pack()

    def encrypt_message(self):
        message = message_entry.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        encrypted_message = caesar_cipher(message, key, mode='encrypt')
        if encrypted_message:
            result_text.delete('1.0', tk.END)
            result_text.insert('1.0', encrypted_message)

    def decrypt_message(self):
        message = message_entry.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        decrypted_message = caesar_cipher(message, key, mode='decrypt')
        if decrypted_message:
            result_text.delete('1.0', tk.END)
            result_text.insert('1.0', decrypted_message)

if __name__ == '__main__':
    app = CryptoApp()
    app.mainloop()

