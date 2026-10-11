from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from typing import Any, Tuple

import hashlib, hmac, json, os, base64, re, secrets, time, asyncio, aiofiles, pathlib


HEADER = 64
PORT = 3200 # Select any unused port number that you want
SERVER_IP = '127.0.0.1' # Change this to your server official public address
ROOT_DIR = pathlib.Path(__file__).parent.parent.absolute()
USER_ACCOUNT_JSON_PATH = ROOT_DIR / "JSONDatabases" / "accountData.json"
USER_CHAT_HISTORY_JSON_PATH = ROOT_DIR / "JSONDatabases" / "chatHistory.json"
USER_PENDING_NOTIFICATIONS_JSON_PATH = ROOT_DIR / "JSONDatabases" / "pendingNotificationLogs.json"
SERVER_PUBLIC_KEY = ROOT_DIR / "RSAKeys" / "ServerPermanentKeys" / "ServerRSApublicKey.pem"
SERVER_PRIVATE_KEY = ROOT_DIR / "RSAKeys" / "ServerPermanentKeys" / "ServerRSAprivateKey.pem"
CLIENTS_TEMP_PUBLIC_KEY = f"{ROOT_DIR / "RSAKeys" / "ClientTempPublicKeys"}/"
CLIENTS_REGISTERED_PUBLIC_KEY = f"{ROOT_DIR / "RSAKeys" / "ClientRegisteredPublicKeys"}/"
CLIENT_SOURCE_CODE = ROOT_DIR / "Asset" / "client.py"
SERVER_SHUTDOWN = False
MAX_MESSAGE_LENGTH = 1000000   # Hard cap on a single client message (DoS protection)
MAX_CONNECTIONS = 1000            # Connection flood limit
PBKDF2_ITERATIONS = 600000      # Work factor for PBKDF2-HMAC-SHA512
MAX_FAILED_LOGINS = 6
LOCKOUT_SECONDS = 10800
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

def hashUserPassword(password: str) -> dict:
    """PBKDF2-HMAC-SHA512 with a unique random salt."""
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, PBKDF2_ITERATIONS)
    return {"salt": base64.b64encode(salt).decode("ascii"), "hash": derived.hex(), "iterations": PBKDF2_ITERATIONS}

def verify_password(username: str, password: str, stored: Any) -> bool:
    """Constant-time verification; supports legacy SHA-512 entries for migration."""
    if isinstance(stored, dict):
        salt = base64.b64decode(stored["salt"])
        iterations = int(stored.get("iterations", PBKDF2_ITERATIONS))
        derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations).hex()
        return hmac.compare_digest(derived, stored["hash"])
    legacy = hashlib.sha512(f"{username}:{password}".encode()).hexdigest()
    return hmac.compare_digest(legacy, str(stored))

print("Starting server...")
with open(USER_ACCOUNT_JSON_PATH, "r") as file:
    account_data = json.load(file)
print("[USERS ACCOUNT DATA] Successfully loaded!")
with open(USER_CHAT_HISTORY_JSON_PATH, "r") as file:
    user_chat_history = json.load(file)
print("[USERS CHAT HISTORY] Successfully loaded!")
with open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "r") as file:
    pending_notifications = json.load(file)
print("[USERS PENDING NOTIFICATIONS] Successfully loaded!")
with open(CLIENT_SOURCE_CODE, "rb") as file:
    CLIENTSOURCEHASH = hashlib.sha512(file.read()).hexdigest()
print("[OFFICIAL CLIENT SOURCE CODE] SHA-512 Obtained!")

activeClients = {}

ACCOUNT_LOCK = asyncio.Lock()
CHAT_LOCK = asyncio.Lock()
NOTIF_LOCK = asyncio.Lock()

def clientHybridEncryption(data: Any, key: str) -> Tuple[str, str]:
    """
    Description: Perform a hybrid encryption of AES-256 and RSA-4096 on data to send to server
    :param data: Data to be encrypted
    :param key: Which client public key to use
    :return: shared secret, cipher text
    """
    # Server generate random AES session key
    sessionKey = base64.b64encode(get_random_bytes(256 // 8)).decode('ascii')
    # Server encrypt message with the AES session key
    cipher = AES.new(base64.b64decode(sessionKey), AES.MODE_OCB)
    # Server obtain tag and nonce value
    ciphertext, AEStag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Server bundle the AES key, tag, and nonce value
    keyBundle = f"{sessionKey}:{base64.b64encode(AEStag).decode('ascii')}:{base64.b64encode(cipher.nonce).decode('ascii')}"
    # Server encrypt key bundle with client public key to obtain shared secret
    cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(key).read()))
    sharedSecret = cipherRSA.encrypt(keyBundle.encode())
    sharedSecret = base64.b64encode(sharedSecret).decode('ascii')
    cipherText = base64.b64encode(ciphertext).decode('ascii')
    return sharedSecret, cipherText


def serverDigitalSignature(sendingData: str) -> str:
    """
    Description: Server Digitally Sign the data to be sent to the client
    :param sendingData: The ASCII data to be sent to the client
    :return: The Digital Signature
    """
    signingKey = RSA.import_key(open(SERVER_PRIVATE_KEY, 'rb').read())
    hashedContent = SHA256.new(sendingData.encode())
    return base64.b64encode(pss.new(signingKey).sign(hashedContent)).decode('ascii')


def clientHybridDecryption(sharedSecret: str, cipherText: str) -> Tuple[str, str]:
    """
    Description: Perform a hybrid decryption of AES-256 and RSA-4096 data received from client
    :param sharedSecret: Base64 encoded RSA-encrypted key bundle
    :param cipherText: Base64 encoded AES-encrypted data
    :return: Execution Code, Decrypted original string
    """
    try:
        # Decode the Base64 strings back to raw bytes
        encryptedKeyBundle = base64.b64decode(sharedSecret)
        cipherText = base64.b64decode(cipherText)

        # Decrypt the key bundle using the Server's Private Key
        private_key = RSA.import_key(open(SERVER_PRIVATE_KEY).read())
        cipherRSA = PKCS1_OAEP.new(private_key)
        keyBundle = cipherRSA.decrypt(encryptedKeyBundle).decode('utf-8')

        # Unbundle the session key, tag, and nonce
        # The bundle format was: sessionKey(b64) : tag(b64) : nonce(b64)
        sessionKey_b64, AEStag_b64, nonce_b64 = keyBundle.split(":")

        # Decode the extracted components from Base64 to raw bytes
        sessionKey = base64.b64decode(sessionKey_b64)
        AEStag = base64.b64decode(AEStag_b64)
        nonce = base64.b64decode(nonce_b64)

        # Reconstruct the AES cipher in OCB mode using the session key and nonce
        cipherAES = AES.new(sessionKey, AES.MODE_OCB, nonce=nonce)

        # Decrypt AND verify the ciphertext
        decryptedData = cipherAES.decrypt_and_verify(cipherText, AEStag)

        # Decode the raw decrypted bytes back to the original string
        return "Success", decryptedData.decode('utf-8')
    except Exception as e:
        return "Error", str(e)


def clientSignatureVerify(clientSignature: str, receivedData: str, key: str) -> bool:
    """
    Description: Verify the signature of the client
    :param clientSignature: Received client signature
    :param receivedData: Received data from client
    :param key: client Temp PU
    :return: Verification success or not
    """
    verifierKey = RSA.import_key(open(key, 'rb').read())
    clientSignature = base64.b64decode(clientSignature)
    hashedMsg = SHA256.new(receivedData.encode())
    verifier = pss.new(verifierKey)
    try:
        verifier.verify(hashedMsg, clientSignature)
        return True
    except (ValueError, TypeError):
        return False


async def serverSendMessage(message: str, clientUID: int) -> None:
    """
    Description: Server Sending Message
    :param message: Message content
    :param clientUID: Client UID (The unique ephemeral port number assigned by the server from the first connection)
    """
    clientSocket = activeClients[clientUID].get("Client Socket")
    sendLength = str(len(message)).encode()
    sendLength += b' ' * (HEADER - len(sendLength))
    clientSocket.write(sendLength)
    clientSocket.write(message.encode())
    await clientSocket.drain()



async def clientHandle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global SERVER_SHUTDOWN
    clientUID = writer.get_extra_info('peername')[1]
    print(f"[NEW CONNECTION] {clientUID} connected.")
    print(f"[ACTIVE CONNECTION COUNT] {len(activeClients) + 1} client(s)!")
    if len(activeClients) >= MAX_CONNECTIONS:
        writer.close()
        print("[CONNECTION ABORT] Maximum client connection count reached.")
        return
    activeClients[clientUID] = {"Client Socket": writer, "SHA-512 Username": "", "Username": "", "Current Connection Status": "First Connection", "Current Friend Interaction": "", "Authenticated": False, "Message Counter": 0, "Auth Challenge": ""}
    try:
        while True:
            clientMsgLengthBytes = await reader.read(HEADER)
            if clientMsgLengthBytes:
                clientMsgLength = int(clientMsgLengthBytes.decode())
                if clientMsgLength > MAX_MESSAGE_LENGTH:
                    raise ConnectionAbortedError
                clientMsg = (await reader.readexactly(clientMsgLength)).decode()
                # print(f"Incoming message from client [{clientUID}]: {clientMsg}")
                if activeClients[clientUID]["Current Connection Status"] == 'First Connection':
                    # DO NOT MODIFY THIS LINE
                    if clientMsg == '{"Message Code": "#0000"}':
                        async with aiofiles.open(SERVER_PUBLIC_KEY, "rb") as serverPU:
                            serverPublicKey = await serverPU.read()
                        serverPublicKey = base64.b64encode(serverPublicKey).decode('ascii')
                        serverMsg = json.dumps({"Message Code": "#0000", "Status Code": 200, "Server Public Key": f"{serverPublicKey}"})
                        await serverSendMessage(serverMsg, clientUID)
                        activeClients[clientUID]["Current Connection Status"] = 'In Session'
                    else:
                        await serverSendMessage('{"Message Code": "#0000", "Status Code": 400, "Error": "Bad Request Error"}', clientUID)
                else:
                    if len(clientMsg.split(':')) == 2:
                        clientSharedSecret = clientMsg.split(':')[0]
                        encryptedClientData = clientMsg.split(':')[1]
                        decryptionStatus, decryptedClientData = await asyncio.to_thread(clientHybridDecryption, clientSharedSecret, encryptedClientData)
                        if decryptionStatus == "Success":
                            clientMsg = json.loads(decryptedClientData)
                            msgCounter = clientMsg.get("Counter", -1)
                            if not isinstance(msgCounter, int) or isinstance(msgCounter, bool) or msgCounter <= activeClients[clientUID]["Message Counter"]:
                                print(f"[REPLAY ERROR] Client {clientUID} sent request with a stale or missing counter!")
                                serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                await serverSendMessage(f'{{"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                                continue
                            activeClients[clientUID]["Message Counter"] = msgCounter
                            if clientMsg.get("Message Code", "") not in ("#0001", "#0002", "#0003") and not activeClients[clientUID]["Authenticated"]:
                                print(f"[AUTH ERROR] Unauthenticated client {clientUID} attempted {clientMsg.get('Message Code', '')}! Rejected.")
                                serverSignature = await asyncio.to_thread(serverDigitalSignature, "Unauthorized Request!")
                                await serverSendMessage(f'{{"Status Code": 401, "Server Message": "Unauthorized Request!", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                                continue

                            # Client Source Code and Temp PU
                            if clientMsg.get("Message Code", "") == "#0001":
                                print(f"[CLIENT SOURCE CODE CHECK] Checking Source Code For Client {clientUID} is pending...")
                                hashedClientSourceCode = hashlib.sha512(base64.b64decode(clientMsg.get("Client Message", "").split(':')[0])).hexdigest()
                                clientTempPU = clientMsg.get("Client Message", "").split(':')[1]
                                async with aiofiles.open(f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem", "wb") as clientTempPublicKey:
                                    await clientTempPublicKey.write(base64.b64decode(clientTempPU))
                                if await asyncio.to_thread(clientSignatureVerify, clientMsg.get("Client Digital Signature", ''), clientMsg.get("Client Message", ""), f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem"):
                                    if hashedClientSourceCode == CLIENTSOURCEHASH:
                                        print(f"[CLIENT SOURCE CODE CHECK] Source code of client {clientUID} hash MATCHED!")
                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Client Source Code Verification Success")
                                        serverMsg = json.dumps({"Message Code": "#0001", "Status Code": 200, "Server Message": "Client Source Code Verification Success", "Server Digital Signature": f"{serverSignature}"})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                    else:
                                        print(f"[CLIENT SOURCE CODE CHECK] Source code of client {clientUID} hash NOT MATCHED!")
                                        async with aiofiles.open(CLIENT_SOURCE_CODE,"rb") as clientSource:
                                            clientSourceBytes = await clientSource.read()
                                        hashedClientSourceCode = hashlib.sha512(clientSourceBytes).hexdigest()
                                        clientSourceBytes = base64.b64encode(clientSourceBytes).decode('ascii')
                                        serverSignature = await asyncio.to_thread(serverDigitalSignature,f"{clientSourceBytes}:{hashedClientSourceCode}")
                                        serverMsg = json.dumps({"Message Code": "#0001", "Status Code": 202, "Server Message": f"{clientSourceBytes}:{hashedClientSourceCode}", "Server Digital Signature": f"{serverSignature}"})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                else:
                                    print(f"[CRYPTO ERROR] Client {clientUID} Signature Verification Failed!")
                                    serverSignature = await asyncio.to_thread(serverDigitalSignature,"Server Can Not Verify Client Digital Signature")
                                    await serverSendMessage(f'{{"Status Code": 501, "Server Message": "Server Can Not Verify Client Digital Signature", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                            else:
                                if await asyncio.to_thread(clientSignatureVerify, clientMsg.get("Client Digital Signature", ''), clientMsg.get("Client Message", ""), f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem"):

                                    # User submit authentication credential
                                    if clientMsg.get("Message Code", "") == "#0002":
                                        clientUserName = clientMsg.get("Client Message", "").split(':')[0]
                                        clientPassword = clientMsg.get("Client Message", "").split(':')[1]
                                        if clientUserName in account_data.keys():
                                            account = account_data[clientUserName]
                                            if account.get("Current Lock Out Time", 0) < time.time():
                                                if verify_password(clientUserName, clientPassword, account["Password"]):
                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} Credential VALID!")
                                                    print(f"[AUTHENTICATION CHECK] Sending an AUTH CHALLENGE to {clientUID}!")
                                                    account["Failed Attempts"] = 0
                                                    authChallenge = secrets.token_hex(32)
                                                    activeClients[clientUID]["Auth Challenge"] = authChallenge
                                                    activeClients[clientUID]["SHA-512 Username"] = hashlib.sha512(clientUserName.encode()).hexdigest()
                                                    activeClients[clientUID]["Username"] = clientUserName
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "Authentication Success!")
                                                    serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 200, "Server Message": "Authentication Success!", "Auth Challenge": authChallenge, "Server Digital Signature": f"{serverSignature}"})
                                                else:
                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} Credential INVALID!")
                                                    failedAttempts = account.get("Failed Attempts", 0) + 1
                                                    account["Failed Attempts"] = failedAttempts
                                                    if failedAttempts >= MAX_FAILED_LOGINS:
                                                        account["Current Lock Out Time"] = time.time() + LOCKOUT_SECONDS
                                                        account.setdefault("Locked Out Record", []).append(time.ctime(time.time()))
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Too Many Invalid Log In Attempt!\nAccount is locked for 3 hr!")
                                                        serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 401, "Server Message": "Too Many Invalid Log In Attempt!\nAccount is locked for 3 hr!", "Server Digital Signature": f"{serverSignature}"})
                                                    else:
                                                        remaining = MAX_FAILED_LOGINS - failedAttempts
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, f"Invalid Credential Provided!\nYou have {remaining} login attempts remaining!")
                                                        serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 401, "Server Message": f"Invalid Credential Provided!\nYou have {remaining} login attempts remaining!", "Server Digital Signature": f"{serverSignature}"})
                                                async with ACCOUNT_LOCK:
                                                    async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                        await accountDataFile.write(json.dumps(account_data, indent=4))
                                            else:
                                                lockedTimeRemaining = account["Current Lock Out Time"] - time.time()
                                                lockedTimeRemainingFormat = time.strftime('%H:%M:%S', time.gmtime(lockedTimeRemaining))
                                                serverSignature = await asyncio.to_thread(serverDigitalSignature, f"Your account is currently locked for {lockedTimeRemainingFormat}")
                                                serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 403, "Server Message": f"Your account is currently locked for {lockedTimeRemainingFormat}", "Server Digital Signature": f"{serverSignature}"})
                                        else:
                                            print(f"[AUTHENTICATION CHECK] Client {clientUID} provided Account '{clientUserName}' need registration!")
                                            activeClients[clientUID]["SHA-512 Username"] = hashlib.sha512(clientUserName.encode()).hexdigest()
                                            activeClients[clientUID]["Username"] = clientUserName
                                            serverSignature = await asyncio.to_thread(serverDigitalSignature, f"There is no registered account with user name [{clientUserName}] yet!")
                                            serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 401, "Server Message": f"There is no registered account with user name [{clientUserName}] yet!", "Server Digital Signature": f"{serverSignature}"})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)

                                    # User submit an authentication challenge to confirm login or finishing a new account registration
                                    elif clientMsg.get("Message Code", "") == "#0003":
                                        clientMessageParts = clientMsg.get("Client Message", "").split(':')
                                        if len(clientMessageParts) == 4:

                                            if clientMessageParts[3] == "Confirm Login":
                                                # ---- LOGGING IN CONFIRM----
                                                clientProvidedPUHashed, clientChallenge, clientPermSignature, _ = clientMessageParts
                                                registeredPUPath = f"{CLIENTS_REGISTERED_PUBLIC_KEY}{activeClients[clientUID]['SHA-512 Username']}.pem"
                                                serverSideClientPUHashed = ""
                                                if os.path.exists(registeredPUPath):
                                                    async with aiofiles.open(registeredPUPath, "rb") as clientPermPU:
                                                        serverSideClientPUHashed = hashlib.sha512(await clientPermPU.read()).hexdigest()
                                                expectedChallenge = activeClients[clientUID].get("Auth Challenge", "")
                                                activeClients[clientUID]["Auth Challenge"] = ""  # single-use
                                                if expectedChallenge and hmac.compare_digest(clientChallenge, expectedChallenge):
                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} provide a valid AUTH CHALLENGE!")
                                                    if clientProvidedPUHashed == serverSideClientPUHashed and await asyncio.to_thread(clientSignatureVerify, clientPermSignature, f"{clientProvidedPUHashed}:{clientChallenge}", registeredPUPath):
                                                        print(f"[AUTHENTICATION CHECK] Client {clientUID} provide a valid registered permanent pubic key for the '{activeClients[clientUID]['Username']}'")
                                                        activeClients[clientUID]["Authenticated"] = True
                                                        print(f"[AUTHENTICATION CHECK] Client {clientUID} successfully authenticated account '{activeClients[clientUID]['Username']}'")
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Logging Successful!")
                                                        serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 200, "Server Message": "Logging Successful!", "Server Digital Signature": f"{serverSignature}"})
                                                        account_data[activeClients[clientUID]["Username"]]["Last Log In"] = time.ctime(time.time())
                                                        async with ACCOUNT_LOCK:
                                                            async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                                await accountDataFile.write(json.dumps(account_data, indent=4))
                                                    else:
                                                        print(f"[AUTHENTICATION CHECK] Client {clientUID} permanent key verification failure!")
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Client Account Public Key Verification Error!")
                                                        serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 403, "Server Message": "Client Account Public Key Verification Error!", "Server Digital Signature": f"{serverSignature}"})
                                                else:
                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} AUTH CHALLENGE failure!")
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "Client AUTH CHALLENGE failure!")
                                                    serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 403, "Server Message": "Client AUTH CHALLENGE failure!", "Server Digital Signature": f"{serverSignature}"})

                                            elif clientMessageParts[3] == "Register":
                                                clientUserName, clientPassword, clientPermPUB64, _ = clientMessageParts
                                                clientPUHash = hashlib.sha512(clientUserName.encode()).hexdigest()
                                                registeredPUPath = f"{CLIENTS_REGISTERED_PUBLIC_KEY}{clientPUHash}.pem"
                                                try:
                                                    clientPermPUBytes = base64.b64decode(clientPermPUB64, validate=True)
                                                    RSA.import_key(clientPermPUBytes)
                                                except (ValueError, TypeError):
                                                    clientPermPUBytes = b""
                                                async with ACCOUNT_LOCK:
                                                    account_data[clientUserName] = {"Password": hashUserPassword(clientPassword), "Last Log In": time.ctime(time.time()), "Current Lock Out Time": 0, "Failed Attempts": 0, "Locked Out Record": [], "Friends": []}
                                                    pending_notifications[clientUserName] = {"Unread Messages": {}, "Pending Friend Requests": [], "Friend Request Answers": {}}
                                                    user_chat_history[clientUserName] = {}
                                                    async with aiofiles.open(registeredPUPath, "wb") as clientPermPU:
                                                        await clientPermPU.write(clientPermPUBytes)
                                                    async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                        await accountDataFile.write(json.dumps(account_data, indent=4))
                                                if not clientPermPUBytes:
                                                    print(f"[REGISTRATION BAD REQUEST ERROR] Recieved data from client {clientUID} provided invalid Permanent RSA Public Key!")
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                                    serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                                else:
                                                    async with NOTIF_LOCK:
                                                        async with aiofiles.open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "w") as pendingNotificationFile:
                                                            await pendingNotificationFile.write(json.dumps(pending_notifications, indent=4))
                                                    async with CHAT_LOCK:
                                                        async with aiofiles.open(USER_CHAT_HISTORY_JSON_PATH, "w") as chathistoryFile:
                                                            await chathistoryFile.write(json.dumps(user_chat_history, indent=4))
                                                    activeClients[clientUID]["Authenticated"] = True
                                                    activeClients[clientUID]["SHA-512 Username"] = clientPUHash
                                                    activeClients[clientUID]["Username"] = clientUserName
                                                    print(f"[NEW ACCOUNT REGISTRATION] Client {clientUID} registered account '{clientUserName}'")
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "New Account Registration Successful!")
                                                    serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 200, "Server Message": "New Account Registration Successful!", "Server Digital Signature": f"{serverSignature}"})
                                        else:
                                            print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} for #0003 in invalid format!")
                                            serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                            serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                        if activeClients[clientUID]["Authenticated"]:
                                            clientUserName = activeClients[clientUID]["Username"]
                                            for otherClientUID, otherClientData in activeClients.items():
                                                if otherClientUID != clientUID:
                                                    otherClientAuthenticatedStatus = otherClientData["Authenticated"]
                                                    otherClientUserName = otherClientData["Username"]
                                                    if otherClientAuthenticatedStatus:
                                                        print(f"[NEW CONNECTION] Updating current online user list and friend list with client {otherClientUID} - account '{otherClientUserName}'")
                                                        if clientUserName in account_data[otherClientUserName]["Friends"]:
                                                            relationship = "Friend"
                                                        else:
                                                            if clientUserName in pending_notifications[otherClientUserName]["Pending Friend Requests"] or otherClientUserName in pending_notifications[clientUserName]["Pending Friend Requests"]:
                                                                relationship = "Pending Friend Invitation"
                                                            else:
                                                                relationship = "None"
                                                        message = json.dumps({"New Client Connected": clientUserName, "Relationship": relationship})
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, message)
                                                        serverMsg = json.dumps({"Message Code": "#0007", "Server Message": message, "Server Digital Signature": serverSignature})
                                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{otherClientUID}.pem")
                                                        await serverSendMessage(f"{shareSecret}:{cipherText}", otherClientUID)

                                    # User requested current online users list, friend list, and pending notification
                                    elif clientMsg.get("Message Code", "") == "#0004":
                                        serverMsg = {}
                                        clientUserName = activeClients[clientUID]["Username"]
                                        print(f"[CURRENT ONLINE USER LIST] Client {clientUID} - user account '{clientUserName}' request current online users list")
                                        clientFriends = account_data[clientUserName]["Friends"]
                                        allOnlineUsers = {}
                                        for _, otherClientData in activeClients.items():
                                            otherClientUsername = otherClientData["Username"]
                                            if otherClientData["Authenticated"]:
                                                if otherClientUsername in clientFriends:
                                                    allOnlineUsers[otherClientUsername] = "Friend"
                                                else:
                                                    if otherClientUsername in pending_notifications[clientUserName]["Pending Friend Requests"] or clientUserName in pending_notifications[otherClientUsername]["Pending Friend Requests"]:
                                                        allOnlineUsers[otherClientUsername] = "Pending Friend Invitation"
                                                    elif otherClientUsername == clientUserName:
                                                        allOnlineUsers[otherClientUsername] = "Self"
                                                    else:
                                                        allOnlineUsers[otherClientUsername] = "None"
                                        serverMsg["Current Online Users"] = allOnlineUsers
                                        print(f"[CURRENT ONLINE USER LIST]  Current online users list is ready to send to client {clientUID}")

                                        print(f"[FRIEND LIST] Client {clientUID} - user account '{clientUserName}' request current friend list")
                                        clientFriendsOnlineStatus = []
                                        for friend in clientFriends:
                                            if friend in allOnlineUsers.keys():
                                                clientFriendsOnlineStatus.append({"name": friend, "online": True})
                                            else:
                                                clientFriendsOnlineStatus.append({"name": friend, "online": False})
                                        serverMsg["Current Friend List"] = clientFriendsOnlineStatus
                                        print(f"[FRIEND LIST] Friend list for user account '{clientUserName}' is ready to send to client {clientUID}")

                                        print(f"[PENDING NOTIFICATIONS] Client {clientUID} - user account '{clientUserName}' request pending notifications")
                                        unreadMessages = pending_notifications[clientUserName]["Unread Messages"]
                                        pendingFriendRequests = pending_notifications[clientUserName]["Pending Friend Requests"]
                                        friendRequestResponses = pending_notifications[clientUserName]["Friend Request Answers"]
                                        notifications = {"unread_messages": [], "friend_request": [], "request_accepted": [], "request_rejected": []}
                                        for otherClientUsername, unreadMessageCount in unreadMessages.items():
                                            notifications["unread_messages"].append({f"{otherClientUsername}": f"{unreadMessageCount}"})
                                        for otherClientUsername in pendingFriendRequests:
                                            notifications["friend_request"].append(otherClientUsername)
                                        for otherClientUsername, decision in friendRequestResponses.items():
                                            if decision == "accept":
                                                notifications["request_accepted"].append(otherClientUsername)
                                            elif decision == "reject":
                                                notifications["request_rejected"].append(otherClientUsername)
                                        serverMsg["Current Pending Notifications"] = notifications
                                        print(f"[PENDING NOTIFICATIONS] Pending notifications for user account '{clientUserName}' is ready to send to client {clientUID}")

                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, json.dumps(serverMsg))
                                        serverMsg = json.dumps({"Message Code": "#0004", "Status Code": 200, "Server Message": json.dumps(serverMsg), "Server Digital Signature": serverSignature})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                        print(f"[PENDING NOTIFICATIONS] All current online users, friend list, and pending notifications for user account '{clientUserName}' sent to client {clientUID}")

                                    # User requested chat history with friend
                                    elif clientMsg.get("Message Code", "") == "#0005":
                                        friendUsername = clientMsg.get("Client Message", "")
                                        clientUserName = activeClients[clientUID]["Username"]

                                        # The Client-side UI already programed to only send #0005 by user based on the displayed valid friends, the following is server-side validation that the user requested friend username is indeed already friend with the user
                                        if friendUsername not in account_data.get(clientUserName, {}).get("Friends", []):
                                            print(f"[CHAT HISTORY ERROR] Client {clientUID} - user account '{clientUserName}' request encrypted chat history with user '{friendUsername}' BUT neither is FRIEND to each other!!!")
                                            continue

                                        activeClients[clientUID]["Current Friend Interaction"] = friendUsername
                                        print(f"[CHAT HISTORY] Client {clientUID} - user account '{clientUserName}' request encrypted chat history with user '{friendUsername}'")
                                        async with aiofiles.open(f"{CLIENTS_REGISTERED_PUBLIC_KEY}{hashlib.sha512(friendUsername.encode()).hexdigest()}.pem", "rb") as friendPU:
                                            data = await friendPU.read()
                                            friendRegPU = base64.b64encode(data).decode('ascii')
                                        if friendUsername in user_chat_history[clientUserName].keys():
                                            friendChatHistory = user_chat_history[clientUserName][friendUsername]
                                        elif clientUserName in user_chat_history[friendUsername].keys():
                                            friendChatHistory = user_chat_history[friendUsername][clientUserName]
                                        else:
                                            user_chat_history[clientUserName][friendUsername] = []
                                            friendChatHistory = []
                                        serverMsg = {"Friend Registered PU": friendRegPU, "Encrypted Chat History": friendChatHistory}
                                        serverSignature = await asyncio.to_thread(serverDigitalSignature,json.dumps(serverMsg))
                                        serverMsg = json.dumps({"Message Code": "#0005", "Status Code": 200, "Server Message": json.dumps(serverMsg), "Server Digital Signature": serverSignature})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                        print(f"[CHAT HISTORY] Encrypted chat history with user '{friendUsername}' sent to client {clientUID} - user account '{clientUserName}'")

                                    # User sent message to friend
                                    elif clientMsg.get("Message Code", "") == "#0006":
                                        clientChatMessage = json.loads(clientMsg.get("Client Message", ""))
                                        clientUserName = activeClients[clientUID]["Username"]
                                        friendUsername = clientChatMessage.get("To", "")

                                        # The Client-side UI already programed to only send #0006 by user based on the displayed valid friends, the following is server-side validation that the user requested friend username is indeed already friend with the user
                                        if friendUsername not in account_data.get(clientUserName, {}).get("Friends", []):
                                            print(f"[CHAT MESSAGE ERROR] Received encrypted chat message from client {clientUID} - user '{clientUserName}' to user '{friendUsername}' BUT neither is FRIEND to each other!!!")
                                            continue

                                        friendOnlineAndCurrentlyInteractingWithClient = False
                                        friendOnline = False
                                        friendSocketUID = 0
                                        print(f"[CHAT MESSAGE] Received encrypted chat message from client {clientUID} - user '{clientUserName}' to user '{friendUsername}'")
                                        if friendUsername in user_chat_history[clientUserName].keys():
                                            user_chat_history[clientUserName][friendUsername].append(clientChatMessage)
                                        elif clientUserName in user_chat_history[friendUsername].keys():
                                            user_chat_history[friendUsername][clientUserName].append(clientChatMessage)
                                        else:
                                            user_chat_history[clientUserName][friendUsername] = [clientChatMessage]
                                        async with CHAT_LOCK:
                                            async with aiofiles.open(USER_CHAT_HISTORY_JSON_PATH, "w") as chatLog:
                                                await chatLog.write(json.dumps(user_chat_history, indent=4))
                                        print(f"[CHAT MESSAGE] Server successfully store the encrypted chat message from client {clientUID} - user '{clientUserName}' to user {friendUsername}")
                                        for otherClientSocketUID, otherClientData in activeClients.items():
                                            if friendUsername == otherClientData["Username"] and otherClientData["Authenticated"]:
                                                friendSocketUID = otherClientSocketUID
                                                if otherClientData["Current Friend Interaction"] == clientUserName:
                                                    friendOnlineAndCurrentlyInteractingWithClient = True
                                                friendOnline = True
                                                break
                                        if friendOnlineAndCurrentlyInteractingWithClient:
                                            serverSignature = await asyncio.to_thread(serverDigitalSignature,json.dumps(clientChatMessage))
                                            serverMsg = json.dumps({"Message Code": "#0006", "Status Code": 200, "Server Message": json.dumps(clientChatMessage), "Server Digital Signature": serverSignature})
                                            shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{friendSocketUID}.pem")
                                            await serverSendMessage(f"{shareSecret}:{cipherText}", friendSocketUID)
                                            print(f"[CHAT MESSAGE] Received encrypted chat message from client {clientUID} - user '{clientUserName}' was sent to user '{friendUsername}'")
                                        else:
                                            if friendOnline:
                                                print(f"[CHAT MESSAGE] User '{friendUsername}' is currently online but not chatting with the sender '{clientUserName}'!")
                                            else:
                                                print(f"[CHAT MESSAGE] User '{friendUsername}' not currently online!")
                                            if pending_notifications[friendUsername]["Unread Messages"].get(clientUserName, ""):
                                                pending_notifications[friendUsername]["Unread Messages"][clientUserName] += 1
                                            else:
                                                pending_notifications[friendUsername]["Unread Messages"][clientUserName] = 1
                                            async with NOTIF_LOCK:
                                                async with aiofiles.open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "w") as pendingNotificationsFile:
                                                    await pendingNotificationsFile.write(json.dumps(pending_notifications, indent=4))
                                            print(f"[CHAT MESSAGE] An unread message pending notification from '{clientUserName}' was added for '{friendUsername}'!")
                                            if friendOnline:
                                                notificationMessage = json.dumps({"Notification Type": "unread_messages", "From": clientUserName, "Current Unread Messages": pending_notifications[friendUsername]["Unread Messages"][clientUserName]})
                                                serverSignature = await asyncio.to_thread(serverDigitalSignature, notificationMessage)
                                                serverMsg = json.dumps({"Message Code": "#0009", "Server Message": notificationMessage, "Server Digital Signature": serverSignature})
                                                shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg,f"{CLIENTS_TEMP_PUBLIC_KEY}{friendSocketUID}.pem")
                                                await serverSendMessage(f"{shareSecret}:{cipherText}", friendSocketUID)
                                                print(f"[PENDING NOTIFICATIONS] Live unread message notification from client {clientUID} - user '{clientUserName}' was sent to user '{friendUsername}'")
                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Message Deliver Success!")
                                        serverMsg = json.dumps({"Message Code": "#0006", "Status Code": 200, "Server Message": "Message Deliver Success!", "Server Digital Signature": serverSignature})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                        print(f"[CHAT MESSAGE] The delivery acknowledgement of the encrypted chat message from client {clientUID} - user '{clientUserName}' to user '{friendUsername}' was sent to the original sender")

                                    # Notification Update
                                    elif clientMsg.get("Message Code", "") == "#0010":
                                        notificationMessage = json.loads(clientMsg.get("Client Message", ""))
                                        clientUserName = activeClients[clientUID]["Username"]
                                        notificationType = notificationMessage.get("Notification Type", "")
                                        notificationSender = notificationMessage.get("From", "")
                                        if notificationType == "unread_messages":
                                            # User read unread messages
                                            print(f"[NOTIFICATION ACKNOWLEDGEMENT] Client {clientUID} - user '{clientUserName}' read unread messages from user '{notificationSender}'")
                                            pending_notifications[clientUserName]["Unread Messages"].pop(notificationSender, None)
                                        elif notificationType in ["request_accepted", "request_rejected"] and notificationSender in pending_notifications[clientUserName]["Pending Friend Requests"]:
                                            # User decline or accept friend request from other
                                            pending_notifications[clientUserName]["Pending Friend Requests"].remove(notificationSender)
                                            decision = "reject" if notificationType == "request_rejected" else "accept"
                                            print(f"[FRIEND REQUEST DECISION] Client {clientUID} - user '{clientUserName}' {decision} friend request from user '{notificationSender}'")
                                            pending_notifications[notificationSender]["Friend Request Answers"][clientUserName] = decision
                                            if decision == "accept":
                                                account_data[clientUserName]["Friends"].append(notificationSender)
                                                account_data[notificationSender]["Friends"].append(clientUserName)
                                                async with ACCOUNT_LOCK:
                                                    async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                        await accountDataFile.write(json.dumps(account_data, indent=4))
                                                print(f"[FRIEND LIST] Add new friend {notificationSender} to user '{clientUserName}' friend list")
                                                print(f"[FRIEND LIST] Add new friend {clientUserName} to user '{notificationSender}' friend list")
                                            for otherClientSocketUID, otherClientData in activeClients.items():
                                                if notificationSender == otherClientData["Username"] and otherClientData["Authenticated"]:
                                                    notificationMessage = json.dumps({"Notification Type": notificationType, "From": clientUserName})
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature,notificationMessage)
                                                    serverMsg = json.dumps({"Message Code": "#0009", "Server Message": notificationMessage, "Server Digital Signature": serverSignature})
                                                    shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{otherClientSocketUID}.pem")
                                                    await serverSendMessage(f"{shareSecret}:{cipherText}", otherClientSocketUID)
                                                    print(f"[PENDING NOTIFICATIONS] Live friend request decision notification from client {clientUID} - user '{clientUserName}' was sent to user '{otherClientData['Username']}'")
                                                    break
                                        elif notificationType in ["request_accepted", "request_rejected"]:
                                            # User acknowledge other friend request decision
                                            print(f"[NOTIFICATION ACKNOWLEDGEMENT] Client {clientUID} - user '{clientUserName}' acknowledge friend request decision from user '{notificationSender}'")
                                            pending_notifications[clientUserName]["Friend Request Answers"].pop(notificationSender, None)
                                        async with NOTIF_LOCK:
                                            async with aiofiles.open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "w") as pendingNotificationFile:
                                                await pendingNotificationFile.write(json.dumps(pending_notifications, indent=4))

                                    # Friend Request
                                    elif clientMsg.get("Message Code", "") == "#0011":
                                        clientUserName = activeClients[clientUID]["Username"]
                                        otherClientUsername = clientMsg.get("Client Message", "")

                                        # Client-side application is already programmed to prevent user from sending friend request to non-existing user, self, or friend request already sent by either one of them, the following just a serveer-side validation
                                        if otherClientUsername not in account_data.keys() or otherClientUsername == clientUserName or clientUserName in pending_notifications[otherClientUsername]["Pending Friend Requests"] or otherClientUsername in pending_notifications[clientUserName]["Pending Friend Requests"]:
                                            if otherClientUsername not in account_data.keys():
                                                print(f"[FRIEND REQUEST ERROR] Client {clientUID} - user '{clientUserName}' sent a friend request to user '{otherClientUsername}' that does not exists!")
                                            elif otherClientUsername == clientUserName:
                                                print(f"[FRIEND REQUEST ERROR] Client {clientUID} - user '{clientUserName}' sent a friend request to user '{otherClientUsername}' - You cannot friend yourself, lol!")
                                            else:
                                                print(f"[FRIEND REQUEST ERROR] Client {clientUID} - user '{clientUserName}' sent a friend request to user '{otherClientUsername}' - Friend Request already sent!")
                                            continue

                                        if not otherClientUsername in pending_notifications[clientUserName]["Pending Friend Requests"]:
                                            pending_notifications[otherClientUsername]["Pending Friend Requests"].append(clientUserName)
                                            print(f"[FRIEND REQUEST] Client {clientUID} - user '{clientUserName}' sent a friend request to user '{otherClientUsername}'")
                                            for otherClientSocketUID, otherClientData in activeClients.items():
                                                if otherClientData["Username"] == otherClientUsername and otherClientData["Authenticated"]:
                                                    notificationMessage = json.dumps({"Notification Type": "friend_request", "From": clientUserName})
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature,notificationMessage)
                                                    serverMsg = json.dumps({"Message Code": "#0009", "Server Message": notificationMessage, "Server Digital Signature": serverSignature})
                                                    shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{otherClientSocketUID}.pem")
                                                    await serverSendMessage(f"{shareSecret}:{cipherText}", otherClientSocketUID)
                                                    print(f"[PENDING NOTIFICATIONS] Live friend request notification from client {clientUID} - user '{clientUserName}' was sent to user '{otherClientData['Username']}'")
                                                    break
                                            async with NOTIF_LOCK:
                                                async with aiofiles.open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "w") as pendingNotificationFile:
                                                    await pendingNotificationFile.write(json.dumps(pending_notifications, indent=4))
                                else:
                                    print(f"[CRYPTO ERROR] Client {clientUID} Signature Verification Failed!")
                                    serverSignature = await asyncio.to_thread(serverDigitalSignature,"Server Can Not Verify Client Digital Signature")
                                    await serverSendMessage(f'{{"Status Code": 501, "Server Message": "Server Can Not Verify Client Digital Signature", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                        else:
                            print(f"[CRYPTO ERROR] Decryption of data sent by client {clientUID} Failed!")
                            serverSignature = await asyncio.to_thread(serverDigitalSignature,"Server Can Not Decrypt the client-sent data")
                            await serverSendMessage(f'{{"Status Code": 500, "Server Message": "Server Can Not Decrypt the client-sent data", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                    else:
                        print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} does not match the expected format!")
                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                        await serverSendMessage(f'{{"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": "{serverSignature}"}}', clientUID)
            else:
                raise ConnectionAbortedError
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.CancelledError):
        pass
    except Exception: # A device try to connect to the server that did not use the official client.py
        await serverSendMessage("Status Code: 400 - Bad Request", clientUID)
    if not SERVER_SHUTDOWN:
        print(f"[CLIENT DISCONNECT] Client {clientUID} has disconnected")
        if os.path.exists(f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem"):
            os.remove(f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
            print(f"[CLIENT DISCONNECT] Deleting temp client PU {clientUID}.pem")
        if activeClients[clientUID]["Authenticated"]:
            clientUserName = activeClients[clientUID]["Username"]
            for otherClientUID, otherClientData in activeClients.items():
                otherClientAuthenticatedStatus = otherClientData["Authenticated"]
                if otherClientAuthenticatedStatus and otherClientData["Username"] != clientUserName:
                    print(f"[CLIENT DISCONNECT] Updating current online user list and friend list with client {otherClientUID} - account '{otherClientData['Username']}'")
                    serverSignature = await asyncio.to_thread(serverDigitalSignature, clientUserName)
                    serverMsg = json.dumps({"Message Code": "#0008", "Server Message": clientUserName, "Server Digital Signature": serverSignature})
                    shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{otherClientUID}.pem")
                    await serverSendMessage(f"{shareSecret}:{cipherText}", otherClientUID)
        activeClients.pop(clientUID, None)
        writer.close()
        print(f"[ACTIVE CONNECTION COUNT] {len(activeClients)} client(s)!")
        return


async def main():
    global SERVER_SHUTDOWN
    server = await asyncio.start_server(clientHandle, SERVER_IP, PORT)
    print(f"[SERVER SOCKET INITIALIZE] IP Address: {SERVER_IP}, Port: {PORT}")
    print(f"[LISTENING] Server is listening on {SERVER_IP}, Port {PORT}")

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        SERVER_SHUTDOWN = True
        print(f"[SERVER SHUTDOWN] Server is shutting down...")
        server.close()
        for clientUID, clientData in list(activeClients.items()):
            clientSocket = clientData["Client Socket"]
            print(f"[SERVER SHUTDOWN] Aborting active connection with Client {clientUID}")
            if os.path.exists(f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem"):
                os.remove(f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                print(f"[SERVER SHUTDOWN] Deleting temp client PU {clientUID}.pem")
            try:
                clientSocket.transport.abort()
            except Exception:
                pass
        activeClients.clear()
        print(f"[SHUTDOWN] All Connections are closed!")


if __name__ == "__main__":
    print("[SERVER STARTING] server is starting...")
    asyncio.run(main())
