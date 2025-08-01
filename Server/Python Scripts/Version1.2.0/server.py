from socket import *
from threading import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dotenv import load_dotenv

import hashlib
import json
import os
import base64
import time
import schedule

load_dotenv()

HEADER = 64
DECODE_FORMAT = 'utf-8'
PORT = 3200
SERVER_IP = gethostbyname(gethostname())
ACCOUNTJSONPATH = os.environ.get('AccountDataPath')
CHATHISTORY = os.environ.get('ChatHistoryPath')
SERVERPUBLICKEY = os.environ.get('ServerPU')
SERVERPRIVATEKEY = os.environ.get('ServerPI')
CLIENTSPUBLICKEYPATH = os.environ.get('ClientPUPath')
LOCKEDACCOUNTPATH = os.environ.get('LockedAccount')
CENSOREDWORD = os.environ.get('CensoredWords')
TIMEOUTPATH = os.environ.get('TimeOutPath')
SHUTDOWN = False

with open(ACCOUNTJSONPATH, "r") as file:
    account_data = json.load(file)
with open(CHATHISTORY, "r") as file:
    chat_history = json.load(file)
with open(LOCKEDACCOUNTPATH, "r") as file:
    locked_accounts = json.load(file)
with open(TIMEOUTPATH, "r") as file:
    timed_out_list = json.load(file)

active_clients = {}

# Account Data JSON format: "hashed username": [hashed user password, Last time log in, last time log in since epoch time]
# Locked Account JSON format: "account ID": [hashed username, Time account was locked, Time being locked since epoch time]
# Chat History JSON format: "message ID - Data created": [shared secret/Only server can decrypt it, AES encrypted message]
# Time out JSON format: "hashed username":time since epoch time being timed out


def auto_deleting_expired_locked_accounts():
    # Auto-deleting locked account in the locked list and in-active account for more than 6 months, checking every 24 hours at 7 AM
    print(f"Starting process of checking locked accounts in file for 6 months or more...")
    account_deleted = []
    for accountId in locked_accounts:
        if time.time() - locked_accounts[accountId][1] >= 15768000:
            print(
                f"Deleting account id {accountId} with username {locked_accounts[accountId][0]} for being in the locked list for {(time.time() - locked_accounts[accountId][1]) // 2592000} month(s)...")
            del account_data[locked_accounts[accountId][0]]
            account_deleted.append(accountId)
    for account in account_deleted:
        del locked_accounts[account]
    account_deleted = []
    print(f"Starting process of checking accounts inactive for 6 months or more...")
    for user in account_data:
        if time.time() - account_data[user][2] >= 15768000:
            print(f"Deleting account {user} for being inactive for {(time.time() - account_data[user][2]) // 2592000} month(s) ...")
            account_deleted.append(user)
    for account in account_deleted:
        del account_data[account]

    with open(ACCOUNTJSONPATH, "w") as file:
        json.dump(account_data, file, indent=4)
    with open(LOCKEDACCOUNTPATH, "w") as file:
        json.dump(locked_accounts, file, indent=4)


def daily_task():
    schedule.every().day.at("07:00").do(auto_deleting_expired_locked_accounts)
    while True:
        if SHUTDOWN:
            print(f"Server shut down!")
            return
        schedule.run_pending()
        time.sleep(1)


Thread(target=daily_task).start()
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind((SERVER_IP, PORT))


def send_message_to_clients(server_message_to_be_sent, clientAddress):
    clientSocket = active_clients[clientAddress][0]
    if server_message_to_be_sent.startswith("#0010"):
        active_clients[clientAddress].append(chat_history.copy())
        counter = 0
        for msgID in active_clients[clientAddress][5]:
            shared_secret = active_clients[clientAddress][5][msgID][0]
            cipher_text = active_clients[clientAddress][5][msgID][1]
            # Server decrypt shared secret with server private key
            cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(SERVERPRIVATEKEY).read()))
            key_bundle = cipherRSA.decrypt(base64.b64decode(shared_secret)).decode('utf-8')
            # print(f"Server decrypt shared secret: {key_bundle}")
            # Server encrypt the key bundle with the client public key to obtain new shared secret
            cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(active_clients[clientAddress][3]).read()))
            shared_secret = cipherRSA.encrypt(key_bundle.encode())
            shared_secret = base64.b64encode(shared_secret).decode('ascii')
            if counter == len(active_clients[clientAddress][5]) - 1:
                server_message_to_be_sent = f"LASTMESSAGE{shared_secret} {cipher_text}"
            else:
                server_message_to_be_sent = f"{shared_secret} {cipher_text}"
            counter += 1
            send_length = str(len(server_message_to_be_sent)).encode(DECODE_FORMAT)
            send_length += b' ' * (HEADER - len(send_length))
            clientSocket.send(send_length)
            clientSocket.send(server_message_to_be_sent.encode(DECODE_FORMAT))
        active_clients[clientAddress].pop(5)
        active_clients[clientAddress][2] = 'in session'
    else:
        if server_message_to_be_sent.startswith("#0011"):
            server_message_to_be_sent = server_message_to_be_sent.split("#0011")[1]
            shared_secret = server_message_to_be_sent.split(" ")[0]
            cipher_text = server_message_to_be_sent.split(" ")[1]
            # Server decrypt shared secret with server private key
            cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(SERVERPRIVATEKEY).read()))
            key_bundle = cipherRSA.decrypt(base64.b64decode(shared_secret)).decode('utf-8')
            for client in active_clients:
                if active_clients[client][2] == 'in session':
                    # Server encrypt the key bundle with the client public key to obtain new shared secret
                    cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(active_clients[client][3]).read()))
                    new_shared_secret = cipherRSA.encrypt(key_bundle.encode())
                    new_shared_secret = base64.b64encode(new_shared_secret).decode('ascii')
                    server_message_to_be_sent = f"{new_shared_secret} {cipher_text}"
                    send_length = str(len(server_message_to_be_sent)).encode(DECODE_FORMAT)
                    send_length += b' ' * (HEADER - len(send_length))
                    active_clients[client][0].send(send_length)
                    active_clients[client][0].send(server_message_to_be_sent.encode(DECODE_FORMAT))
        else:
            send_length = str(len(server_message_to_be_sent)).encode(DECODE_FORMAT)
            send_length += b' ' * (HEADER - len(send_length))
            clientSocket.send(send_length)
            clientSocket.send(server_message_to_be_sent.encode(DECODE_FORMAT))


def client_handle(clientSocket, clientAddress):
    print(f"[NEW CONNECTION] {clientAddress} connected.")
    global timed_out_list
    client_status = ''
    client_username = ''
    server_message_to_be_sent = ''
    password_input_attempt = 7
    try:
        while True:
            client_msg_length = clientSocket.recv(HEADER).decode(DECODE_FORMAT)
            if client_msg_length:
                client_msg_length = int(client_msg_length)
                client_msg = clientSocket.recv(client_msg_length).decode(DECODE_FORMAT)
                print(f"Incoming messsage from client [{clientAddress}]: {client_msg}")
                if not client_msg.startswith(("#0000", "#0001", "#0010", "#0011", "#0100")):
                    send_message_to_clients("Invalid handshake message!\n"
                                            "Connection Terminated!", clientAddress)
                    client_msg = "#0100"
                if client_msg.startswith("#0100"):
                    if os.path.exists(active_clients[clientAddress][3]):
                        os.remove(active_clients[clientAddress][3])
                    del active_clients[clientAddress]
                    clientSocket.close()
                    print(f"Client {clientAddress} has disconnected!")
                    print(f"[ACTIVE CONNECTION] {len(active_clients)}")
                    return
                if client_msg.startswith(("#0010", "#0011")):
                    if client_msg.startswith("#0011"):
                        if "I just cursed!" in client_msg:
                            if active_clients[clientAddress][4] < 5:
                                active_clients[clientAddress][4] += 1
                                server_message_to_be_sent = f"Server Warning Message {active_clients[clientAddress][4]}: Please do not use profane language!\n"
                            else:
                                server_message_to_be_sent = "Server Message: You have been timed out for 3 hours"
                                with open(TIMEOUTPATH, "r") as file:
                                    timed_out_list = json.load(file)
                                timed_out_list[active_clients[clientAddress][1]] = time.time()
                                with open(TIMEOUTPATH, "w") as file:
                                    json.dump(timed_out_list, file, indent=4)
                        else:
                            shared_secret = client_msg.split("#0011")[1].split(" ")[0]
                            cipher_text = client_msg.split("#0011")[1].split(" ")[1]
                            chat_history[f"Message ID {len(chat_history) + 1} - {time.ctime(time.time())}"] = [shared_secret, cipher_text]
                            with open(CHATHISTORY, "w") as JSONfile:
                                json.dump(chat_history, JSONfile, indent=4)
                            server_message_to_be_sent = client_msg
                    else:
                        send_message_to_clients("#0010", clientAddress)
                if client_msg.startswith(("#0000", "#0001")):
                    if client_msg.startswith("#0000"):
                        send_message = 'Welcome to David Online Chat Room!\n' \
                                       'Type "LOGGING IN" to log in with your account\n' \
                                       'Type "SIGN UP" to create an account'
                        if not client_msg.startswith(("#0000a", "#0000b")):
                            client_msg = client_msg.split(':')
                            if len(client_msg) != 5:
                                send_message_to_clients("Invalid handshake message!\n"
                                                        "Connection Terminated!", clientAddress)
                            with open(SERVERPUBLICKEY, "rb") as Pemfile:
                                data = Pemfile.read()
                                hashedServerPU = hashlib.sha512(str(data).encode()).hexdigest()
                            with open(os.environ.get("ClientUpToDateSourceCode"), "rb") as Sourcefile:
                                data = Sourcefile.read()
                                hashedUpToDateClientCode = hashlib.shake_128(str(data).encode()).hexdigest(32)
                            with open(CENSOREDWORD, "rb") as CensoredWordfile:
                                data = CensoredWordfile.read()
                                hashedCensoredWordData = hashlib.shake_128(str(data).encode()).hexdigest(32)
                            if hashedServerPU == client_msg[1]:
                                with open(f"{CLIENTSPUBLICKEYPATH}/{clientAddress}.pem", "wb") as pemfile:
                                    pemfile.write(client_msg[3].encode())
                                active_clients[clientAddress][3] = f"{CLIENTSPUBLICKEYPATH}/{clientAddress}.pem"
                                if not (hashedUpToDateClientCode == client_msg[2] and hashedCensoredWordData == client_msg[4]):
                                    send_message = "Your current client side program and data are outdated or tampered!\n" \
                                                   'Type "UPDATE" for the server to auto update the client script!\n' \
                                                   'You must run the most up to date client script to join the server!'
                            else:
                                send_message = "Invalid Server Public Key!\n" \
                                               "Please contact the server admin at {put your own email here as a server admin} to obtain" \
                                               " the correct server public key!"
                        elif client_msg.startswith("#0000a"):
                            if client_msg.strip("#0000a") == "UPDATE":
                                with open(os.environ.get("ClientUpToDateSourceCode"), "rb") as Sourcefile:
                                    updateSourceCode = Sourcefile.read()
                                    hashedUpToDateClientCode = hashlib.shake_128(str(updateSourceCode).encode()).hexdigest(32)
                                updateSourceCode = base64.b64encode(updateSourceCode).decode('ascii')
                                with open(CENSOREDWORD, "rb") as CensoredWordfile:
                                    updateCensoredWordData = CensoredWordfile.read()
                                    hashedCensoredWordData = hashlib.shake_128(str(updateCensoredWordData).encode()).hexdigest(32)
                                updateCensoredWordData = base64.b64encode(updateCensoredWordData).decode('ascii')
                                cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(active_clients[clientAddress][3]).read()))
                                encrypted_hash_data = cipherRSA.encrypt(f"{hashedUpToDateClientCode}:{hashedCensoredWordData}".encode())
                                send_message = f"UPDATE{updateSourceCode}:{updateCensoredWordData}:{base64.b64encode(encrypted_hash_data).decode('ascii')}"
                                send_message_to_clients(send_message, clientAddress)
                                if os.path.exists(active_clients[clientAddress][3]):
                                    os.remove(active_clients[clientAddress][3])
                                del active_clients[clientAddress]
                                clientSocket.close()
                                print(f"Client {clientAddress} has disconnected!")
                                print(f"[ACTIVE CONNECTION] {len(active_clients)}")
                                return
                            else:
                                send_message = "Your current client side program and data are outdated or tampered!\n" \
                                               'Type "UPDATE" for the server to auto update the client script!\n' \
                                               'You must run the most up to date client script to join the server!'

                        server_message_to_be_sent = send_message

                    elif client_msg.startswith("#0001a"):
                        client_msg = client_msg.split("#0001a")[1]
                        if client_status == '':
                            server_message_to_be_sent = "Begin logging in process...\n" \
                                                        "What is your username?\n"
                            client_status = 'checking username'
                        elif client_status == 'checking username':
                            client_username = client_msg
                            account_locked = False
                            for accountId in locked_accounts:
                                if locked_accounts[accountId][0] == client_username:
                                    account_locked = True
                                    break
                            if account_locked:
                                server_message_to_be_sent = f"Your account has been LOCKED \n" \
                                                            f"Please contact the server admin via" \
                                                            f" davidnguyen1813@gmail.com to restore your account!"
                            else:
                                user_timed_out = False
                                if client_username in timed_out_list:
                                    if time.time() - timed_out_list[client_username] >= 10800:
                                        print(f"Removing user {client_username} from timed out list...")
                                        del timed_out_list[client_username]
                                        with open(TIMEOUTPATH, "w") as file:
                                            json.dump(timed_out_list, file, indent=4)
                                    else:
                                        user_timed_out = True
                                        current_timed_out_value = str(
                                            (10800 - (time.time() - timed_out_list[client_username])) / 3600).split(".")
                                        server_message_to_be_sent = f"You are currently being TIMED OUT for {current_timed_out_value[0]} hour(s) and {round(float(f'.{current_timed_out_value[1]}') * 60)} minute(s)!"
                                if not user_timed_out:
                                    if client_username in account_data:
                                        duplicateSession = False
                                        for client in active_clients:
                                            if active_clients[client][1] == client_username:
                                                duplicateSession = True
                                                break
                                        if duplicateSession:
                                            server_message_to_be_sent = "Another device is in sessioned with the account associate with the username.\n" \
                                                                        "For security reason, you have to provide a different valid account to log in!\n"
                                        else:
                                            active_clients[clientAddress][1] = client_username
                                            server_message_to_be_sent = "Please provide your password!\n"
                                            client_status = 'checking password'
                                            password_input_attempt -= 1
                                    else:
                                        server_message_to_be_sent = "There is no account with the provided username!\n" \
                                                                    "Please provide another username!\n" \
                                                                    "If you want to create a new account, please relaunch the application and type SIGN UP!\n"
                        elif client_status == 'checking password':
                            if account_data[client_username][0] == client_msg:
                                server_message_to_be_sent = "AUTHENTICATION SUCCESS!"
                                client_status = 'laoding chat history'
                                account_data[client_username][1] = f"Last logged in: {time.ctime(time.time())}"
                                account_data[client_username][2] = time.time()
                                with open(ACCOUNTJSONPATH, "w") as JSONfile:
                                    json.dump(account_data, JSONfile, indent=4)
                            else:
                                if password_input_attempt != 0:
                                    server_message_to_be_sent = f"Invalid password!\n" \
                                                                f"You have {password_input_attempt} left!"
                                    password_input_attempt -= 1
                                else:
                                    locked_accounts[len(locked_accounts) + 1] = [client_username, f"Time of account locked: {time.ctime(time.time())}", time.time()]
                                    with open(LOCKEDACCOUNTPATH, "w") as jsonfile:
                                        json.dump(locked_accounts, jsonfile, indent=4)
                                    server_message_to_be_sent = f"Your account is now LOCKED due to many failed login attempts!\n" \
                                                                f"Please contact the server admin via davidnguyen1813@gmail.com to restore your account!"
                    elif client_msg.startswith("#0001b"):
                        client_msg = client_msg.split("#0001b")[1]
                        if client_status == '':
                            server_message_to_be_sent = "Begin signing up process...\n" \
                                                        "Please type a username?\n"
                            client_status = "checking username"
                        elif client_status == "checking username":
                            client_username = client_msg
                            if client_username in account_data:
                                server_message_to_be_sent = "The username has been taken\n" \
                                                            "Please choose another username!\n"
                            else:
                                active_clients[clientAddress][1] = client_username
                                server_message_to_be_sent = "Please set up a password!\n" \
                                                            "Must be 12 length minimum\n" \
                                                            "Must have mixed characters and numbers\n" \
                                                            "Letters must have mixed case\n" \
                                                            "Contains the following special characters !@#$%&*_+=\n"
                                client_status = "setting password"
                        elif client_status == "setting password":
                            account_data[client_username] = [client_msg, f"Last logged in: {time.ctime(time.time())}", time.time()]
                            with open(ACCOUNTJSONPATH, "w") as jsonfile:
                                json.dump(account_data, jsonfile, indent=4)
                            server_message_to_be_sent = "AUTHENTICATION SUCCESS!"
                            client_status = 'laoding chat history'
                send_message_to_clients(server_message_to_be_sent, clientAddress)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        if os.path.exists(active_clients[clientAddress][3]):
            os.remove(active_clients[clientAddress][3])
        del active_clients[clientAddress]
        clientSocket.close()
        print(f"Client {clientAddress} has disconnected!")
        print(f"[ACTIVE CONNECTION] {len(active_clients)}")
        return


def start():
    global SHUTDOWN
    serverSocket.listen(100)  # Listen up to 100 clients maximum!
    print(f"[LISTENING] Server is listening on {SERVER_IP}, Port {PORT}")
    try:
        while True:
            clientSocket, clientAddress = serverSocket.accept()
            Thread(target=client_handle, args=(clientSocket, clientAddress[1])).start()
            active_clients[clientAddress[1]] = [clientSocket, '', '', '', 0]  # [clientSocket, username, status, public key, cursing record]
            print(f"[ACTIVE CONNECTION] {len(active_clients)}")
    except KeyboardInterrupt:
        print(f"Server socket closing...")
        SHUTDOWN = True


print("[STARTING] server is starting...")
start()
