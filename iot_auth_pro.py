import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import os
import logging
import binascii

logging.basicConfig(filename="protocol_trace.log", level=logging.INFO, format="%(message)s")

client_private_key = None
client_public_key = None
server_private_key = None
server_public_key = None
shared_session_key = None
fuzzy_extracted_key = None
final_session_key = None

def generate_client_keys():
    global client_private_key, client_public_key
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_public_key = client_private_key.public_key()
    client_key_label.config(text="Client Keys Generated!")
    messagebox.showinfo("Success", "Client Key Pair Generated")
    logging.info(f"Client_Public_Key: {client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()}")

def generate_server_keys():
    global server_private_key, server_public_key
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()
    server_key_label.config(text="Server Keys Generated!")
    messagebox.showinfo("Success", "Server Key Pair Generated")
    logging.info(f"Server_Public_Key: {server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()}")

def fuzzy_extract(noisy_input, length=32):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'fuzzy-extraction',
    ).derive(noisy_input)

def exchange_keys():
    global shared_session_key, fuzzy_extracted_key, final_session_key
    if client_public_key and server_private_key:
        
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        logging.info(f"Shared_Secret: {shared_secret.hex()}")
        shared_session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)
        logging.info(f"Session_Key (Initial): {shared_session_key.hex()}")

        fuzzy_extracted_key = fuzzy_extract(shared_session_key)
        logging.info(f"Fuzzy_Extracted_Key: {fuzzy_extracted_key.hex()}")

        final_session_key = bytes(a ^ b for a, b in zip(shared_session_key, fuzzy_extracted_key))
        logging.info(f"Final_Session_Key: {final_session_key.hex()}")
        
        session_key_label.config(text=f"Final Session Key: {final_session_key.hex()}")
        messagebox.showinfo("Success", "Key Exchange Completed with Fuzzy Logic and XOR")
    else:
        messagebox.showerror("Error", "Keys not generated for key exchange")

def encrypt_message():
    if final_session_key:
        message = message_entry.get()
        if not message:
            messagebox.showerror("Error", "No message entered")
            return
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(final_session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        ciphertext = iv + encryptor.update(padded_message) + encryptor.finalize()

        logging.info(f"Encrypted_Message: {ciphertext.hex()}")
        messagebox.showinfo("Success", f"Message Encrypted!\nCiphertext: {ciphertext.hex()}")
    else:
        messagebox.showerror("Error", "No Session Key Available for Encryption")

def decrypt_message():
    if final_session_key:
        user_input = decrypt_entry.get()
        if not user_input:
            messagebox.showerror("Error", "No input provided for decryption")
            return

        try:
            encrypted_message = binascii.unhexlify(user_input)
        except binascii.Error:
            messagebox.showerror("Error", "Invalid ciphertext format")
            return
        
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        
        cipher = Cipher(algorithms.AES(final_session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        try:
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
            messagebox.showinfo("Decrypted Message", f"Decrypted: {decrypted_message.decode()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
    else:
        messagebox.showerror("Error", "No session key available for decryption")

root = tk.Tk()
root.title("IoT Authentication and Key Agreement")
root.geometry("500x700")

title_label = tk.Label(root, text="IoT Authentication & Key Agreement", font=("Arial", 16))
title_label.pack(pady=10)

client_frame = tk.Frame(root)
client_frame.pack(pady=10)
client_button = tk.Button(client_frame, text="Generate Client Keys", command=generate_client_keys)
client_button.pack(side=tk.LEFT, padx=10)
client_key_label = tk.Label(client_frame, text="")
client_key_label.pack(side=tk.LEFT)

server_frame = tk.Frame(root)
server_frame.pack(pady=10)
server_button = tk.Button(server_frame, text="Generate Server Keys", command=generate_server_keys)
server_button.pack(side=tk.LEFT, padx=10)
server_key_label = tk.Label(server_frame, text="")
server_key_label.pack(side=tk.LEFT)

exchange_frame = tk.Frame(root)
exchange_frame.pack(pady=10)
exchange_button = tk.Button(exchange_frame, text="Exchange Keys", command=exchange_keys)
exchange_button.pack(side=tk.LEFT, padx=10)
session_key_label = tk.Label(exchange_frame, text="")
session_key_label.pack(side=tk.LEFT)

message_label = tk.Label(root, text="Enter Message to Encrypt:")
message_label.pack(pady=5)
message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)
encrypt_button = tk.Button(root, text="Encrypt Message", command=encrypt_message)
encrypt_button.pack(pady=10)

decrypt_label = tk.Label(root, text="Enter Encrypted Message (Hex) to Decrypt:")
decrypt_label.pack(pady=5)
decrypt_entry = tk.Entry(root, width=50)
decrypt_entry.pack(pady=5)
decrypt_button = tk.Button(root, text="Decrypt Message", command=decrypt_message)
decrypt_button.pack(pady=10)

root.mainloop()