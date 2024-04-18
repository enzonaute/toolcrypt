import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import random
import string

# Constants
ALPHABET = string.ascii_uppercase

# Caesar Cipher functions
def caesar_cipher(message, key, mode='encrypt'):
    shifted = ALPHABET[key:] + ALPHABET[:key]
    if mode == 'decrypt':
        shifted = ALPHABET[-key:] + ALPHABET[:-key]
    trans = str.maketrans(ALPHABET, shifted)
    return message.translate(trans)

# Vigenère Cipher functions
def vigenere_cipher(message, key, mode='encrypt'):
    if len(key) == 0:  # Ensure key is not empty
        messagebox.showerror("Error", "Key cannot be empty for Vigenère cipher.")
        return ""
    key = (key * (len(message) // len(key) + 1))[:len(message)]
    trans = ''
    for i, char in enumerate(message):
        if char in ALPHABET:
            key_index = ALPHABET.index(key[i])
            shift = ALPHABET.index(char) + key_index if mode == 'encrypt' else ALPHABET.index(char) - key_index
            trans += ALPHABET[shift % 26]
        else:
            trans += char  # keep non-alphabetic characters as is
    return trans

# Vernam Cipher functions
def vernam_cipher(message, key):
    if len(key) != len(message):
        messagebox.showerror("Error", "Key must be the same length as message for Vernam cipher.")
        return ""
    return ''.join(ALPHABET[(ALPHABET.index(char) ^ ALPHABET.index(key_char)) % 26] for char, key_char in zip(message, key) if char in ALPHABET and key_char in ALPHABET)

def generate_key(cipher, message_length):
    if cipher == 'Caesar':
        return str(random.randint(1, 25))
    elif cipher in ['Vigenère', 'Vernam']:
        return ''.join(random.choice(ALPHABET) for _ in range(message_length))

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
        message_entry.bind('<KeyRelease>', lambda e: self.update_key(self.cipher_var.get()))  # Update key on text change

        # Key Input
        ttk.Label(self, text="Key (auto-generated):").pack(pady=(10,0))
        key_entry = ttk.Entry(self, width=53)
        key_entry.pack()

        # Cipher Selection
        ttk.Label(self, text="Select Cipher:").pack(pady=(10,0))
        self.cipher_var = tk.StringVar(self)
        ciphers = ['Caesar', 'Vigenère', 'Vernam']
        self.cipher_var.set('Caesar')  # Default value
        cipher_menu = ttk.OptionMenu(self, self.cipher_var, *ciphers, command=self.update_key)
        cipher_menu.pack()

        # Encrypt and Decrypt Buttons
        ttk.Button(self, text="Encrypt", command=lambda: self.process_cipher('encrypt')).pack(pady=(5,2))
        ttk.Button(self, text="Decrypt", command=lambda: self.process_cipher('decrypt')).pack(pady=(2,5))

        # Result Display
        ttk.Label(self, text="Result:").pack(pady=(10,0))
        result_text = scrolledtext.ScrolledText(self, height=3, width=50)
        result_text.pack()

    def update_key(self, cipher):
        message = message_entry.get('1.0', tk.END).strip()
        if message:
            key = generate_key(cipher, len(message))
            key_entry.delete(0, tk.END)
            key_entry.insert(0, str(key))

    def process_cipher(self, mode):
        message = message_entry.get("1.0", tk.END).strip().upper()
        key = key_entry.get().strip().upper()
        cipher = self.cipher_var.get()
        if cipher == 'Caesar':
            key = int(key)  # Convert key to int for Caesar
        result = ''
        if mode == 'encrypt':
            if cipher == 'Caesar':
                result = caesar_cipher(message, key)
            elif cipher == 'Vigenère':
                result = vigenere_cipher(message, key)
            elif cipher == 'Vernam':
                result = vernam_cipher(message, key)
        elif mode == 'decrypt':
            if cipher == 'Caesar':
                result = caesar_cipher(message, key, 'decrypt')
            elif cipher == 'Vigenère':
                result = vigenere_cipher(message, key, 'decrypt')
            elif cipher == 'Vernam':
                result = vernam_cipher(message, key)
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', result)

if __name__ == '__main__':
    app = CryptoApp()
    app.mainloop()

