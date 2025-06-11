# serverClient_socket

## 📌 Overview
This project demonstrates a one-way encrypted communication system using asymmetric encryption between a Client and a Server.
A single Client connects to a Server, sends an encrypted message, which the Server then decrypts and displays in a GUI.
After decrypting the message, the Server sends back an acknowledgement to the Client.

Note: The server supports only one client connection at a time.

## 🧰 Technologies & Libraries Used
- cryptography – for RSA encryption/decryption
- socket – for TCP-based communication
- base64 – for encoding/decoding encrypted data
- tkinter – for building the server-side GUI


## ⚙️ Setup Instructions

## 1. Clone the Repository
```bash
git clone https://github.com/your-username/serverClient_socket.git
cd serverClient_socket
```
## 2. Set Up a Virtual Environment
```bash
python -m venv .venv
```
## 3. Activate the Environment
On Linux/macOS:
```bash
source .venv/bin/activate
```
On Windows:
```bash
.venv\Scripts\activate
```
## 4. Install Dependencies
On Linux/macOS:
```bash
pip3 install -r requirements.txt
```
On Windows:
```bash
pip install -r requirements.txt
```
## 🚀 Running the Application
### 1. Start the Server
```bash
python server.py
```
A GUI window will appear.

Click the "Start Server" button in the GUI to begin listening for connections.

### 2. Start the Client
```bash
python client.py
```
Enter your message in the input field.

Click "Send" to transmit the encrypted message to the server.

⚠️ Important: Only one client can be connected to the server at a time.

## ✅ Features
- Secure one-way communication using RSA encryption
- Interactive server-side GUI for message monitoring
- Simple and self-contained implementation using Python standard and third-party libraries
