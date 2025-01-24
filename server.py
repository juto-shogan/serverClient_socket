# Server Code (server.py)
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_key(pem_key):
    return serialization.load_pem_public_key(pem_key.encode('utf-8'))

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def start_server(host, port, output_area):
    def server_logic():
        private_key, public_key = generate_keys()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        output_area.insert(tk.END, f"Server listening on {host}:{port}\n")

        conn, addr = server_socket.accept()
        output_area.insert(tk.END, f"Connected by {addr}\n")

        client_public_key_pem = conn.recv(1024).decode()
        client_public_key = deserialize_key(client_public_key_pem)
        conn.sendall(serialize_key(public_key).encode())

        while True:
            data = conn.recv(4096)
            if not data:
                break

            encrypted_data = base64.b64decode(data)
            decrypted_message = decrypt_message(encrypted_data, private_key)

            output_area.insert(tk.END, f"Client: {decrypted_message}\n")

            acknowledgment = "done" if decrypted_message else "seen"
            encrypted_response = encrypt_message(acknowledgment, client_public_key)

            output_area.insert(tk.END, f"Encrypted Acknowledgment: {base64.b64encode(encrypted_response).decode()}\n")
            conn.sendall(base64.b64encode(encrypted_response))
        conn.close()
        server_socket.close()

    threading.Thread(target=server_logic).start()

# GUI Setup
root = tk.Tk()
root.title("Secure Chat Server")
root.geometry("600x400")

server_label = tk.Label(root, text="Server Output")
server_label.pack()
server_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15)
server_output.pack()

start_server_button = tk.Button(root, text="Start Server", command=lambda: start_server('127.0.0.1', 5000, server_output))
start_server_button.pack(pady=10)

root.mainloop()