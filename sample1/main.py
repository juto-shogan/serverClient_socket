import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ENCRYPTION LOGIC 
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

# SERVER / CLIENT
def server(host, port):
    private_key, public_key = generate_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

 
        
    client_public_key_pem = conn.recv(1024).decode()
    client_public_key = deserialize_key(client_public_key_pem)
    conn.sendall(serialize_key(public_key).encode())

    while True:
        data = conn.recv(4096)
        if not data:
                break

        encrypted_data = base64.b64decode(data)
        decrypted_message = decrypt_message(encrypted_data, private_key)
        print(f"Client: {decrypted_message}")
        acknowledgment = "done" if decrypted_message else "seen"
        encrypted_response = encrypt_message(acknowledgment, client_public_key)
            
        # Print the encrypted acknowledgment
        print(f"Encrypted Acknowledgment: {base64.b64encode(encrypted_response).decode()}")
        conn.sendall(base64.b64encode(encrypted_response))
        conn.close()
        server_socket.close()

def client(host, port):
    private_key, public_key = generate_keys()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))


    # Exchange public keys
    conn.sendall(serialize_key(public_key).encode())
    server_public_key_pem = conn.recv(1024).decode()
    server_public_key = deserialize_key(server_public_key_pem)

    while True:
        message = input("you> ")
        encrypted_message = encrypt_message(message, server_public_key)
        conn.sendall(base64.b64encode(encrypted_message))

        if message.lower() == 'exit':
            break
        
        data = conn.recv(4096)
        
        encrypted_response = base64.b64decode(data)
        acknowledgment = decrypt_message(encrypted_response, private_key)
        
        print(f"Server: {acknowledgment}")

        conn.close()

# RUNNER
if __name__ == "__main__":
    mode = input("Run as server (s) or client (c)? ")
    host = '127.0.0.1'
    port = 5000

    if mode.lower() == 's':
        server(host, port)
    elif mode.lower() == 'c':
        client(host, port)
    else:
        print("Invalid mode.")

