import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Checkbutton, IntVar
import random
import string

# Constantes
ALPHABET = string.ascii_uppercase

# Fonction de chiffrement de César
def caesar_cipher(message, key, mode='encrypt'):
    # Crée une version décalée de l'alphabet
    shifted = ALPHABET[key:] + ALPHABET[:key]
    if mode == 'decrypt':
        # Pour le déchiffrement, on inverse le décalage
        shifted = ALPHABET[-key:] + ALPHABET[:-key]
    # Crée un tableau de traduction pour le chiffrement/déchiffrement
    trans = str.maketrans(ALPHABET, shifted)
    return message.translate(trans)

# Fonction de chiffrement de Vigenère
def vigenere_cipher(message, key, mode='encrypt'):
    if len(key) == 0:
        messagebox.showerror("Erreur", "La clé ne peut pas être vide pour le chiffrement de Vigenère.")
        return ""
    # Répète la clé pour qu'elle corresponde à la longueur du message
    key = (key * (len(message) // len(key) + 1))[:len(message)]
    trans = ''
    for i, char in enumerate(message):
        if char in ALPHABET:
            key_index = ALPHABET.index(key[i])
            shift = ALPHABET.index(char) + key_index if mode == 'encrypt' else ALPHABET.index(char) - key_index
            trans += ALPHABET[shift % 26]
        else:
            trans += char  # Conserve les caractères non alphabétiques tels quels
    return trans

# Fonction de chiffrement de Vernam
def vernam_cipher(message, key):
    if len(key) != len(message):
        messagebox.showerror("Erreur", "La clé doit être de la même longueur que le message pour le chiffrement de Vernam.")
        return ""
    return ''.join(ALPHABET[(ALPHABET.index(char) ^ ALPHABET.index(key_char)) % 26] for char, key_char in zip(message, key) if char in ALPHABET and key_char in ALPHABET)

# Génère une clé basée sur le type de chiffrement
def generate_key(cipher, message_length):
    if cipher == 'Caesar':
        return str(random.randint(1, 25))
    elif cipher in ['Vigenère', 'Vernam']:
        return ''.join(random.choice(ALPHABET) for _ in range(message_length))

# Application GUI
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('CryptoTool - EPSI')
        self.geometry('600x400')
        self.auto_key_var = IntVar(value=1)  # État de la case à cocher
        self.create_widgets()

    def create_widgets(self):
        global message_entry, key_entry, result_text
        ttk.Label(self, text="Message :").pack(pady=(10,0))
        message_entry = scrolledtext.ScrolledText(self, height=3, width=50)
        message_entry.pack()
        # Met à jour la clé automatiquement lors de la modification du texte
        message_entry.bind('<KeyRelease>', self.conditionally_update_key)

        ttk.Label(self, text="Clé (générée automatiquement) :").pack(pady=(10,0))
        key_entry = ttk.Entry(self, width=53)
        key_entry.pack()

        ttk.Label(self, text="Sélectionnez le chiffrement :").pack(pady=(10,0))
        self.cipher_var = tk.StringVar(self)
        ciphers = ['Caesar', 'Vigenère', 'Vernam']
        self.cipher_var.set('Caesar')
        cipher_menu = ttk.OptionMenu(self, self.cipher_var, self.cipher_var.get(), *ciphers, command=self.update_key)
        cipher_menu.pack()

        Checkbutton(self, text="Régénérer la clé automatiquement lors de la modification du texte", variable=self.auto_key_var).pack()

        ttk.Button(self, text="Chiffrer", command=lambda: self.process_cipher('encrypt')).pack(pady=(5,2))
        ttk.Button(self, text="Déchiffrer", command=lambda: self.process_cipher('decrypt')).pack(pady=(2,5))

        ttk.Label(self, text="Résultat :").pack(pady=(10,0))
        result_text = scrolledtext.ScrolledText(self, height=3, width=50)
        result_text.pack()

    def conditionally_update_key(self, event):
        # Met à jour la clé seulement si la case est cochée
        if self.auto_key_var.get() == 1:
            self.update_key(self.cipher_var.get())

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
            key = int(key)
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
