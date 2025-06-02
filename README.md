# serverClient_socket

## About
This project shows a one-way asymmetric encryption line between a **Server** and a **Client**.
When a single **Client** sends an encrypted message to a **Server**, the **Server** decrypts that and then  displays the decrypted message in its GUI, The **Server** then sends back an acknowledgement.
Only one client can connect to the server at a time.

## Libraries used.
- cryptography
- socket
- base64
- Tkinter


## setup
### To run this, first set up a virtual environment:
```python
python -m venv .venv
```
## Then activate:
### For Linux 
```python
source .venv/bin/activate # for Linux
```
### For Windows
```python
.venv/Scripts/activate
```

## Install necessary libraries:
### For Windows
```bash
pip install -r requirements.txt
```

OR 

### For Linux 
```bash
pip3 install -r requirements.txt
```

## Running code

First is to start the server 
```python
python3 server.puy
```

Tap the GUI button to start the server, then: 

Start the server with the client. Note: not more than one client can connect to the server.
To start the Client:
```python
python3 client.py
```
In the small entry space, enter your message and hit the the send button.
