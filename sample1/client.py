import socket

HEADER = 1024
PORT = 5050
FORMAT = 'utf-8'
SERVER = "127.0.1.1"
DISCONNECT_MESSAGE = "!DISCONNECTED"
ADDR = (SERVER,PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode())

send("hello world")

# input()    
login = input('username: ')
send(input(f'{login}> ')) 

