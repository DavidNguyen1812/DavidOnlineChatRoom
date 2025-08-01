from socket import *
from threading import *
from tkinter import *
from tkinter import scrolledtext


import time
import random


root = Tk()
root.geometry("600x600")
root.title("David Online Chat Room")
root.resizable(True, True)

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Times New Roman", 17)
SMALL_FONT = ("Times New Roman", 13)
HEADER = 64
DECODE_FORMAT = 'utf-8'
PORT = 3200
SERVER_IP = "127.0.0.1"
USERNAME = f"User {random.randint(0,1000)}"

clientSocket = socket(AF_INET, SOCK_STREAM)


def sendMessageToServer(msg):
    client_message_to_be_sent = msg.encode(DECODE_FORMAT)
    msg_length = len(client_message_to_be_sent)
    send_length = str(msg_length).encode(DECODE_FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    clientSocket.send(send_length)
    clientSocket.send(client_message_to_be_sent)


def updateMessageBox(message):
    main_message_box.config(state=NORMAL)
    main_message_box.insert(END, message + '\n')
    main_message_box.see(END)
    main_message_box.config(state=DISABLED)


def sendMessage():
    client_message = userinput_textbox.get()
    userinput_textbox.delete(0, 'end')
    sendMessageToServer(f"{USERNAME} sent message at {time.ctime(time.time())}:\n{client_message}")


def receive_message():
    try:
        while True:
            server_msg_length = clientSocket.recv(HEADER).decode(DECODE_FORMAT)
            if server_msg_length:
                server_msg_length = int(server_msg_length)
                server_msg = clientSocket.recv(server_msg_length).decode(DECODE_FORMAT)
                updateMessageBox(server_msg + '\n')
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, RuntimeError):
        return


def disconnection():
    sendMessageToServer(f"{USERNAME} has left the chat!       {time.ctime(time.time())}")
    sendMessageToServer("#0100")
    updateMessageBox("You have been disconnected from the chat! Please close the window!\n")
    userinput_textbox.config(state=DISABLED)
    send_button.config(state=DISABLED)
    discconection_button.config(state=DISABLED)


root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=NSEW)
middle_frame = Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=NSEW)
bottom_frame = Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=NSEW)

title = Label(top_frame, text="David Online Chat Room v1.3.0", font=FONT, bg=DARK_GREY, fg=WHITE)
title.pack(padx=10)
discconection_button = Button(top_frame, text="DISCONNECT FROM SERVER", font=FONT, bg=DARK_GREY, fg=WHITE,
                              command=disconnection)
discconection_button.pack(padx=10)

userinput_textbox = Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=45)
userinput_textbox.pack(side=LEFT, padx=10)

send_button = Button(bottom_frame, text="ENTER", font=FONT, bg=OCEAN_BLUE, fg=WHITE, command=sendMessage)
send_button.pack(side=LEFT, padx=15)

main_message_box = scrolledtext.ScrolledText(middle_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26)
main_message_box.config(state=DISABLED)
main_message_box.pack(side=TOP)


try:
    clientSocket.connect((SERVER_IP, PORT))
    Thread(target=receive_message).start()

    sendMessageToServer(f"#0000")
    sendMessageToServer(f"{USERNAME} just joined the chat!       {time.ctime(time.time())}")

    root.mainloop()

    sendMessageToServer(f"{USERNAME} has left the chat!       {time.ctime(time.time())}")
    sendMessageToServer("#0100")
except ConnectionError:
    print(f"The chat server is not online at the moment!")