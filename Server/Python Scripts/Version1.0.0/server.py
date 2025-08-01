from socket import *
from threading import *

import json


HEADER = 64
DECODE_FORMAT = 'utf-8'
PORT = 3200
SERVER_IP = gethostbyname(gethostname())
with open("path/to/your/jsonfile", "r") as file:
    chat_history = json.load(file)
MessageID = len(chat_history)


active_clients = []



serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind((SERVER_IP, PORT))


def send_message_to_clients(server_message_to_be_sent, clientSocket):
    if server_message_to_be_sent == "#0000":
        for messageID in chat_history:
            send_length = str(len(chat_history[messageID])).encode(DECODE_FORMAT)
            send_length += b' ' * (HEADER - len(send_length))
            clientSocket.send(send_length)
            clientSocket.send(chat_history[messageID].encode(DECODE_FORMAT))
    else:
        for client in active_clients:
            send_length = str(len(server_message_to_be_sent)).encode(DECODE_FORMAT)
            send_length += b' ' * (HEADER - len(send_length))
            client.send(send_length)
            client.send(server_message_to_be_sent.encode(DECODE_FORMAT))


def client_handle(clientSocket, clientAddress):
    global MessageID
    print(f"[NEW CONNECTION] {clientAddress} connected.")
    try:
        while True:
            client_msg_length = clientSocket.recv(HEADER).decode(DECODE_FORMAT)
            if client_msg_length:
                client_msg_length = int(client_msg_length)
                client_msg = clientSocket.recv(client_msg_length).decode(DECODE_FORMAT)
                print(f"Incoming message from client [{clientAddress}]: {client_msg}\n")
                if client_msg == "#0100":
                    active_clients.remove(clientSocket)
                    clientSocket.close()
                    print(f"Client {clientAddress} has disconnected!")
                    print(f"[ACTIVE CONNECTION] {len(active_clients)}")
                    return
                else:
                    send_message_to_clients(client_msg, clientSocket)
                    if client_msg != "#0000":
                        MessageID += 1
                        chat_history[str(MessageID)] = client_msg
                        with open("path/to/your/jsonfile", "w") as file:
                            json.dump(chat_history, file, indent=4)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        active_clients.remove(clientSocket)
        clientSocket.close()
        print(f"Client {clientAddress} has disconnected!")
        print(f"[ACTIVE CONNECTION] {len(active_clients)}")
        return


def start():
    serverSocket.listen(100)  # Listen up to 100 clients maximum!
    print(f"[LISTENING] Server is listening on {SERVER_IP}, Port {PORT}")
    try:
        while True:
            clientSocket, clientAddress = serverSocket.accept()
            active_clients.append(clientSocket)
            Thread(target=client_handle, args=(clientSocket, clientAddress[1])).start()
            print(f"[ACTIVE CONNECTION] {len(active_clients)}")
    except KeyboardInterrupt:
        print(f"Server socket SHUT DOWN")


print("[STARTING] server is starting...")
start()