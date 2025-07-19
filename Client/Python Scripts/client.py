from socket import *
from threading import *
from tkinter import *
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from better_profanity import profanity
from dotenv import load_dotenv

import time
import os
import hashlib
import base64
import re

load_dotenv()

"""
NOTE:
#0000 -> Tell server to being authentication process
#0010 -> Tell server to send the newly connected client the chat history to keep up-to-date
#0011 -> Normal messaging operation
#0100 -> Disconnect from the server
#0001a -> Tell server that the client is choosing to log in
#0001b -> Tell server that the client is choosing to sign up
"""

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
PORT = int(os.getenv('PORT'))
SERVER_IP = os.getenv('ServerIP')
SERVERPUBLICKEY = os.getenv('ServerPU')
CLIENTPUBLICKEY = os.getenv('ClientPU')
CLIENTPRIVATEKEY = os.getenv('ClientPI')
CENSOREDWORDS = os.getenv('CensoredWords')
MESSAGEUPTODATE = False

STATUS = "FIRST EXCHANGE"
USERNAME = ''
PASSWORDCHECK = False

clientSocket = socket(AF_INET, SOCK_STREAM)


def sendMessageToServer(msg):
    global STATUS
    global USERNAME
    if STATUS != "FIRST EXCHANGE":
        if msg.startswith(("#0100", "#0010")):
            tag = ""
        elif STATUS == "NEED UPDATE":
            tag = "#0000a"
        elif STATUS == "AUTHENTICATING" and msg == "LOGGING IN" or STATUS == "LOGGING IN":
            STATUS = "LOGGING IN"
            tag = "#0001a"
        elif STATUS == "AUTHENTICATING" and msg == "SIGN UP" or STATUS == "SIGN UP":
            STATUS = "SIGN UP"
            tag = "#0001b"
        elif STATUS == "IN SESSION":
            tag = "#0011"
        else:
            STATUS = "AUTHENTICATING"
            tag = "#0000b"
        if tag.startswith("#0001"):
            if USERNAME == "User inputting username":
                USERNAME = msg
            msg = hashlib.sha512(msg.encode()).hexdigest()
        if tag.startswith("#0011"):
            if msg == "I just cursed!":
                pass
            else:
                # Client generate random AES session key
                session_key = base64.b64encode(get_random_bytes(256 // 8)).decode('ascii')
                # Client encrypt message with the AES session key
                cipher = AES.new(base64.b64decode(session_key), AES.MODE_OCB)
                # Client obtain tag and nonce value
                ciphertext, AEStag = cipher.encrypt_and_digest(msg.encode('utf-8'))
                # Client bundle the AES key, tag, and nonce value
                key_bundle = f"{session_key}:{base64.b64encode(AEStag).decode('ascii')}:{base64.b64encode(cipher.nonce).decode('ascii')}"
                # Client encrypt key bundle with server public key to obtain shared secret
                cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(SERVERPUBLICKEY).read()))
                shared_secret = cipherRSA.encrypt(key_bundle.encode())
                shared_secret = base64.b64encode(shared_secret).decode('ascii')
                cipher_text = base64.b64encode(ciphertext).decode('ascii')
                # Client send shared secret and cipher text to server
                msg = f"{shared_secret} {cipher_text}"
        msg = f"{tag}{msg}"
    else:
        STATUS = "AUTHENTICATING"
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
    global USERNAME
    global PASSWORDCHECK
    client_message = userinput_textbox.get()
    userinput_textbox.delete(0, 'end')
    if len(client_message) >= 3500:
        updateMessageBox(f"Maximum message length is 3500 characters\n")
    else:
        if STATUS == "IN SESSION":
            if profanity.contains_profanity(client_message):
                sendMessageToServer("I just cursed!")
            else:
                sendMessageToServer(f"{USERNAME} sent message at {time.ctime(time.time())}:\n{client_message}")
        else:
            if PASSWORDCHECK and None in [re.search(r'[a-z]', client_message), re.search(r'[A-Z]', client_message),
                                          re.search(r'\d', client_message), re.search(r'[!@#$%&*_+=]', client_message)]\
                    and STATUS != "LOGGING IN":
                updateMessageBox(f"Password does not match the password policy!\n")
            else:
                if PASSWORDCHECK:
                    client_message = f"{client_message}{USERNAME}"
                sendMessageToServer(client_message)


def loadingMessageHistory():
    global MESSAGEUPTODATE
    terminate = False
    while True:
        if STATUS != "IN SESSION":
            server_msg_length = clientSocket.recv(HEADER).decode(DECODE_FORMAT)
            if server_msg_length:
                server_msg_length = int(server_msg_length)
                server_msg = clientSocket.recv(server_msg_length).decode(DECODE_FORMAT)
                if server_msg.startswith("LASTMESSAGE"):
                    server_msg = server_msg.strip("LASTMESSAGE")
                    terminate = True
                shared_secret = server_msg.split(" ")[0]
                cipher_text = server_msg.split(" ")[1]
                cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(CLIENTPRIVATEKEY).read()))
                key_bundle = cipherRSA.decrypt(base64.b64decode(shared_secret)).decode('utf-8')
                # Client derive the AES key, tag, and nonce from the key bundle
                key_bundle = key_bundle.split(":")
                # Client decrypt the cipher text with key, tag and nonce
                AESKey = base64.b64decode(key_bundle[0])
                AESTag = base64.b64decode(key_bundle[1])
                AESNonce = base64.b64decode(key_bundle[2])
                cipher = AES.new(AESKey, AES.MODE_OCB, nonce=AESNonce)
                decrypted_text = cipher.decrypt_and_verify(base64.b64decode(cipher_text), AESTag)
                server_msg = decrypted_text.decode()
                updateMessageBox(server_msg + '\n')
                if terminate:
                    MESSAGEUPTODATE = True
                    return


def receive_message():
    global STATUS
    global USERNAME
    global PASSWORDCHECK
    global MESSAGEUPTODATE
    listening = True
    try:
        while True:
            if listening:
                server_msg_length = clientSocket.recv(HEADER).decode(DECODE_FORMAT)
                if server_msg_length:
                    server_msg_length = int(server_msg_length)
                    server_msg = clientSocket.recv(server_msg_length).decode(DECODE_FORMAT)
                    if STATUS != "IN SESSION":
                        if (STATUS == "AUTHENTICATING" and server_msg.startswith("Invalid Server Public Key!")) or server_msg.startswith("You're not running from the correct script!") or \
                                "LOCKED" in server_msg or "TIMED OUT" in server_msg:
                            sendMessageToServer("#0100")
                            userinput_textbox.config(state=DISABLED)
                            send_button.config(state=DISABLED)
                            discconection_button.config(state=DISABLED)
                        if STATUS == "AUTHENTICATING" and server_msg.startswith("Your current client side program and data are outdated or tampered!") or STATUS == "NEED UPDATE":
                            STATUS = "NEED UPDATE"
                        if STATUS == "NEED UPDATE" and server_msg.startswith("UPDATE"):
                            main_message_box.config(state=NORMAL)
                            main_message_box.delete('1.0', END)
                            main_message_box.config(state=DISABLED)
                            server_msg = server_msg.strip("UPDATE")
                            server_msg = server_msg.split(":")
                            updateMessageBox(f"Your client code and censored wordlist are being updated!\n"
                                             f"Please do not close the application until further notice!\n")
                            updateMessageBox(f"Beginning file integrity check...\n")
                            cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(CLIENTPRIVATEKEY).read()))
                            decrypted_hashes = cipherRSA.decrypt(base64.b64decode(server_msg[2].encode())).decode('utf-8')
                            server_source_code_hash = decrypted_hashes.split(":")[0]
                            source_code = server_msg[0]
                            client_source_code_hash = hashlib.shake_128(str(base64.b64decode(source_code)).encode()).hexdigest(32)
                            server_cennsored_word_data_hash = decrypted_hashes.split(":")[1]
                            censored_word_data = server_msg[1]
                            client_censored_word_data_hash = hashlib.shake_128(str(base64.b64decode(censored_word_data)).encode()).hexdigest(32)

                            if server_source_code_hash == client_source_code_hash and server_cennsored_word_data_hash == client_censored_word_data_hash:
                                updateMessageBox(f"Check Passed! Proceeding to download the update\n")
                                os.mkdir(f"{os.getcwd()}/UpdatedFiles")
                                with open(f"{os.getcwd()}/UpdatedFiles/client.py", "wb") as newFile:
                                    newFile.write(base64.b64decode(source_code))
                                with open(f"{os.getcwd()}/UpdatedFiles/censored_wordlist.txt", "wb") as newFile:
                                    newFile.write(base64.b64decode(censored_word_data))
                                updateMessageBox(f"The update data is downloaded in the UpdatedFiles folder in the current directory that you're in!\n"
                                                 f"Please update your current script and censored wordlist to connect to the server!")
                                userinput_textbox.config(state=DISABLED)
                                send_button.config(state=DISABLED)
                                discconection_button.config(state=DISABLED)
                            else:
                                updateMessageBox(f"It's occurred that the original updated source code has been tampered!\n"
                                                 f"Terminating Downloading Process and Connection!")
                                userinput_textbox.config(state=DISABLED)
                                send_button.config(state=DISABLED)
                                discconection_button.config(state=DISABLED)
                            return
                        if "username" in server_msg:
                            USERNAME = "User inputting username"
                        if "password" in server_msg and STATUS != "AUTHENTICATING":
                            userinput_textbox.config(show="*")
                            PASSWORDCHECK = True
                        else:
                            userinput_textbox.config(show="")
                            PASSWORDCHECK = False
                        if server_msg == "AUTHENTICATION SUCCESS!":
                            userinput_textbox.config(state=DISABLED)
                            send_button.config(state=DISABLED)
                            discconection_button.config(state=DISABLED)
                            main_message_box.config(state=NORMAL)
                            main_message_box.delete('1.0', END)
                            main_message_box.config(state=DISABLED)
                            sendMessageToServer(f"#0010")
                            listening = False
                            Thread(target=loadingMessageHistory).start()
                            while not MESSAGEUPTODATE:
                                pass  # Wait for loading all chat history
                            userinput_textbox.config(state=NORMAL)
                            send_button.config(state=NORMAL)
                            discconection_button.config(state=NORMAL)
                            listening = True
                            STATUS = "IN SESSION"
                            profanity.load_censor_words_from_file(CENSOREDWORDS)
                            sendMessageToServer(f"{USERNAME} joined the chat!       {time.ctime(time.time())}")
                    else:
                        if server_msg == "Server Message: You have been timed out for 3 hours":
                            sendMessageToServer("#0100")
                            userinput_textbox.config(state=DISABLED)
                            send_button.config(state=DISABLED)
                            discconection_button.config(state=DISABLED)
                        else:
                            if not server_msg == "AUTHENTICATION SUCCESS!" and not server_msg.startswith("Server Warning Message"):
                                shared_secret = server_msg.split(" ")[0]
                                cipher_text = server_msg.split(" ")[1]
                                cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(CLIENTPRIVATEKEY).read()))
                                key_bundle = cipherRSA.decrypt(base64.b64decode(shared_secret)).decode('utf-8')
                                # Client derive the AES key, tag, and nonce from the key bundle
                                key_bundle = key_bundle.split(":")
                                # Client decrypt the cipher text with key, tag and nonce
                                AESKey = base64.b64decode(key_bundle[0])
                                AESTag = base64.b64decode(key_bundle[1])
                                AESNonce = base64.b64decode(key_bundle[2])
                                cipher = AES.new(AESKey, AES.MODE_OCB, nonce=AESNonce)
                                decrypted_text = cipher.decrypt_and_verify(base64.b64decode(cipher_text), AESTag)
                                server_msg = decrypted_text.decode()
                    if not server_msg == "AUTHENTICATION SUCCESS!":
                        updateMessageBox(server_msg + '\n')
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, RuntimeError):
        return


def disconnection():
    global STATUS
    global USERNAME
    if STATUS == "IN SESSION":
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

title = Label(top_frame, text="David Online Chat Room v1.2.0", font=FONT, bg=DARK_GREY, fg=WHITE)
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

if os.path.exists(CLIENTPRIVATEKEY):
    os.remove(CLIENTPRIVATEKEY)
if os.path.exists(CLIENTPUBLICKEY):
    os.remove(CLIENTPUBLICKEY)
updateMessageBox("Old RSA keys have been removed and new RSA keys generated!\n")

key = RSA.generate(4096)
privateKey = key.export_key()
publicKey = key.publickey().export_key()
with open(CLIENTPRIVATEKEY, "wb") as pemfile:
    pemfile.write(privateKey)
with open(CLIENTPUBLICKEY, "wb") as pemfile:
    pemfile.write(publicKey)


with open(SERVERPUBLICKEY, "rb") as file:
    data = file.read()
    hashedServerPU = hashlib.sha512(str(data).encode()).hexdigest()

with open(os.getenv("ClientSourceCode"), "rb") as file:
    data = file.read()
    hashedClientSourceCode = hashlib.shake_128(str(data).encode()).hexdigest(32)

with open(CLIENTPUBLICKEY, "rb") as file:
    clientPU = file.read()

with open(CENSOREDWORDS, "rb") as file:
    data = file.read()
    HashedCensoredWordData = hashlib.shake_128(str(data).encode()).hexdigest(32)

try:
    clientSocket.connect((SERVER_IP, PORT))
    Thread(target=receive_message).start()

    # Important first Handshake message with the server, if you modified this line, you're cooked!
    sendMessageToServer(f"#0000:{hashedServerPU}:{hashedClientSourceCode}:{clientPU.decode()}:{HashedCensoredWordData}")

    root.mainloop()

    if STATUS == "IN SESSION":
        sendMessageToServer(f"{USERNAME} has left the chat!       {time.ctime(time.time())}")
    sendMessageToServer("#0100")
except ConnectionError:
    print(f"The chat server is not online at the moment!")
