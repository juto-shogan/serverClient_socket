from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket
import threading

# Generate RSA key pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize keys for storage or exchange
def serialize_key(key):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

# Deserialize keys from storage
def deserialize_key(pem_key):
    public_key = serialization.load_pem_public_key(pem_key.encode('utf-8'))
    return public_key

# Encrypt message
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

# Decrypt message
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

# Create a socket connection
def create_connection(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        return s
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

# Handle incoming messages (for server)
def handle_client(conn, private_key):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            decrypted_data = decrypt_message(data, private_key)
            print(f"Received from client: {decrypted_data}")
            # Send response (replace with actual response logic)
            response = input("You: ")
            encrypted_response = encrypt_message(response, conn.client_public_key)
            conn.sendall(encrypted_response)
        except Exception as e:
            print(f"Error handling client: {e}")
            break
    conn.close()

# Handle outgoing messages (for client)
def handle_send(conn, public_key):
    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, public_key)
        conn.sendall(encrypted_message)
        if message.lower() == 'exit':
            break
    conn.close()

# Server
def server(host, port):
    private_key, public_key = generate_keys()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        # Receive client's public key
        client_public_key_pem = conn.recv(1024).decode()
        conn.client_public_key = deserialize_key(client_public_key_pem)
        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(conn, private_key))
        client_thread.start()

# Client
def client(host, port):
    private_key, public_key = generate_keys()
    conn = create_connection(host, port)
    if conn:
        # Send public key to server
        conn.sendall(serialize_key(public_key).encode())
        # Start a new thread to handle sending messages
        send_thread = threading.Thread(target=handle_send, args=(conn, conn.server_public_key))
        send_thread.start()

if __name__ == "__main__":
    # Choose to run as server or client
    mode = input("Run as server (s) or client (c)? ")
    host = '127.0.0.1'  
    port = 5000  

    if mode.lower() == 's':
        server(host, port)
    elif mode.lower() == 'c':
        client(host, port)
    else:
        print("Invalid mode.")

