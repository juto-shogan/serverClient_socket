import socket 
import threading
import time

# Define network port and address and a header and a format for decoding from byte form
HEADER = 1024
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())# gets computer IP

ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECTED"

# Pick a socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        
        if msg_length:  
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
        
            if msg == DISCONNECT_MESSAGE:
                break# connected = False would work too
            
            print(f"[{addr}] {msg}")
            conn.send("msg recieved".encode(FORMAT))
    conn.close()


def start():
    server.listen()
    print(f"Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONECTIONS] { threading.activeCount() - 1}")
              

def sleeper():
    return time.sleep(2)

print("Server is starting")
sleeper()
print("Server has started")
start()

