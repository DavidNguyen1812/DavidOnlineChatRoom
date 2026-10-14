from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from typing import Any, Tuple
from dotenv import load_dotenv
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError

import hashlib, hmac, json, os, base64, re, secrets, time, asyncio, aiofiles, pathlib, smtplib, ssl, random

load_dotenv()

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
MAX_AUTHENTICATE_CONNECTIONS = 1000            # Connection flood limit
PBKDF2_ITERATIONS = 600000      # Work factor for PBKDF2-HMAC-SHA512
MAX_FAILED_LOGINS = 7
LOCKOUT_SECONDS = 10800 # 3 hr
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
REQUEST_RATE_LIMIT = 50  # 50 requests per 30 secs
SERVER_EMAIL_ADDRESS = "noreplycyberbot7777@gmail.com" # You need to use your own registered email for your server
SERVER_EMAIL_CRED = os.environ["EMAIL_CRED"]
USER_CRED_MAXIMUM_AGE = 8035200 # 93 days -> 3 month of (31 days)
USER_CRED_MINIMUM_AGE = 10800 # 3 hr
CONFIRM_TOKEN_EXPIRY = 180 # 3 minutes duration for temp confirm token
temp_tokens = {"Log In": {}, "Account Registration": {}, "Reset Password": {}}
UNAUTHENTICATE_SESSION_TIME_LIMIT = 300
emailQueue = asyncio.Queue(maxsize=150) # Maximum background email worker job. Email is sent as another job to improve authentication response latency
clientPermQueue = asyncio.Queue(maxsize=150) # Maximum background client Perm RSA key pairs generation worker job.
AUTH_MIN_PROCESSING_TIME = 1.0 # Minimum amount of time the authentication (#0002) request should spend processing before returning a response. This helps reduce timing-based username/email enumeration.

registered_pu_hashes = {}
for clientPU in os.listdir(CLIENTS_REGISTERED_PUBLIC_KEY):
    if os.path.isfile(os.path.join(CLIENTS_REGISTERED_PUBLIC_KEY, clientPU)):
        with open(os.path.join(CLIENTS_REGISTERED_PUBLIC_KEY, clientPU), "rb") as f:
            registered_pu_hashes[clientPU.replace(".pem", '')] = hashlib.sha512(f.read()).hexdigest()
print(f"[REGISTERED PUBLIC KEY] Successfully obtain SHA-512 hashes of all stored registered permanent public key for all registered user")

def sendEmail(subject: str, content: str, receiver_email: str) -> bool:
    """
    Description: Sending email
    :param subject: Email subject
    :param content: Email content
    :param receiver_email: Destination email address
    :return: Email sent status of either failed or successes
    """
    # Credit https://www.youtube.com/watch?v=g_j6ILT-X0k
    sender_email = SERVER_EMAIL_ADDRESS

    # Validate the destination email is valid
    try:
        validate_email(receiver_email, check_deliverability=True)
    except EmailNotValidError as error:
        print(f"[Email Validation Fail] Email '{receiver_email}' is invalid!: {error}")
        return False

    # Create a multipart message and set headers
    email = EmailMessage()
    email["From"] = sender_email
    email["To"] = receiver_email
    email["Subject"] = subject

    # Add body to email
    email.set_content(content)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, SERVER_EMAIL_CRED)
            server.sendmail(sender_email, receiver_email, email.as_string())
    except smtplib.SMTPRecipientsRefused as clientError:
        print(f"[Email Validation Fail] Error sending email to {receiver_email}: {clientError}")
        return False
    except Exception as other_error:
        print(f"[Email Validation Fail] Error sending email to {receiver_email}: {other_error}")
        return False
    print(f"[Email Sent Success] Email sent to {receiver_email} successfully!")
    return True


def hashUserPassword(password: str, pastCreds: list) -> dict:
    """PBKDF2-HMAC-SHA512 with a unique random salt."""
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, PBKDF2_ITERATIONS)
    if pastCreds:
        return {"salt": base64.b64encode(salt).decode("ascii"), "hash": derived.hex(), "iterations": PBKDF2_ITERATIONS, "Past Credentials": pastCreds.append(derived.hex()), "Minimum Age": 0, "Maximum Age": time.time() + USER_CRED_MAXIMUM_AGE}
    else:
        return {"salt": base64.b64encode(salt).decode("ascii"), "hash": derived.hex(), "iterations": PBKDF2_ITERATIONS, "Past Credentials": [derived.hex()], "Minimum Age": time.time() + USER_CRED_MINIMUM_AGE, "Maximum Age": time.time() + USER_CRED_MAXIMUM_AGE}

DUMMY_PASSWORD_HASH = hashUserPassword(secrets.token_urlsafe(32), []) # This allows non-existing accounts to perform the same expensive password verification operation as existing accounts without exposing whether the account exists.

def verify_password(password: str, stored: Any, checkReuse: bool, checkMinimumAge: bool, checkExpire: bool) -> bool:
    """Constant-time verification"""
    salt = base64.b64decode(stored["salt"])
    iterations = int(stored.get("iterations", PBKDF2_ITERATIONS))
    derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations).hex()
    if hmac.compare_digest(derived, stored["hash"]):
        if checkReuse:
            if derived in stored["Past Credentials"]: # Credential re-use
                return False
        if checkMinimumAge:
            if time.time() <= stored["Minimum Age"]:
                return False
        if checkExpire:
            if time.time() >= stored["Maximum Age"]:
                return False
        return True
    return False

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


async def rateLimitReset() -> None:
    """
    Description: Background worker for resetting current active clients Rate Limit
    :return: None
    """
    print(f"[SCHEDULE TASK] Starting scheduled background task 'RATE LIMIT RESET'")
    while True:
        for _, clientData in activeClients.items():
            clientData["Request Count"] = 0
        await asyncio.sleep(30)

async def clearExpireConfirmTokens() -> None:
    """
    Description: Background worker for cleaning expire confirmation tokens
    :return: None
    """
    print(f"[SCHEDULE TASK] Starting scheduled background task 'CLEANING EXPIRE CONFIRM TOKEN'")
    while True:
        for authType in temp_tokens:
            tokenToBeDeletes = []
            for email, token in temp_tokens.get(authType, {}).items():
                if time.time() >= token.get("expire", 0):
                    tokenToBeDeletes.append(email)
            for email in tokenToBeDeletes:
                print(f"[EXPIRE CONFIRM TOKEN]Deleting expire {authType} confirmation token for email {email}")
                temp_tokens[authType].pop(email, None)
        await asyncio.sleep(30)


async def emailWorker() -> None:
    """
    Description: Background worker for sending emails without blocking the authentication request.
    """
    print(f"[SCHEDULE TASK] Starting background task for processing email notifications awaiting in email queue")
    while True:
        emailData = await emailQueue.get()
        try:
            await asyncio.to_thread(sendEmail,emailData["Subject"],emailData["Content"], emailData["Receiver Email"])
        except Exception as other_error:
            print(f"[Email Worker Error] Error processing email queue: {other_error}")
        finally:
            emailQueue.task_done()


async def clientRSAAssigningWorker() -> None:
    """
    Description: Background worker for assigning permanent RSA key pairs with a newly registered account.
    """
    print(f"[SCHEDULE TASK] Starting background task for sending permanent RSA key pairs to a newly registered account")
    while True:
        data = await clientPermQueue.get()
        clientUsername = data["Username"]
        clientUID = data["Client UID"]
        nonAvailableHashes = [h for _, h in registered_pu_hashes.items()]
        while True:
            print(f"[NEW REGISTERED ACCOUNT RSA ASSIGNMENT] Generating new permanent RSA key pairs for '{clientUsername}'")
            key = RSA.generate(4096)
            privateKey = key.export_key()
            publicKey = key.publickey().export_key()
            if hashlib.sha512(publicKey).hexdigest() not in nonAvailableHashes:
                break
        print(f"[NEW REGISTERED ACCOUNT RSA ASSIGNMENT] New permanent RSA key pairs for '{clientUsername}' successfully generated!")
        clientPIb64 = base64.b64encode(privateKey).decode('ascii')
        clientPUb64 = base64.b64encode(publicKey).decode('ascii')
        message = f"{clientPIb64}:{clientPUb64}:Your account official permanent RSA key pairs!"
        serverSignature = await asyncio.to_thread(serverDigitalSignature, message)
        serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 200, "Server Message": message, "Auth Type": "Account Registration", "Server Digital Signature": f"{serverSignature}"})
        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
        registered_pu_hashes[hashlib.sha512(clientUsername.encode()).hexdigest()] = hashlib.sha512(publicKey).hexdigest() # For future verification to prevent the client from sending a completely different Public key from the server-assigned upon final verification
        print(f"[NEW REGISTERED ACCOUNT RSA ASSIGNMENT] Sending newly generated permanent RSA key pairs for '{clientUsername}' to {clientUID} for user confirmation!")
        privateKey = ''
        publicKey = ''
        clientPIb64 = ''
        clientPUb64 = ''
        print(f"[NEW REGISTERED ACCOUNT RSA ASSIGNMENT] Clearing newly generated permanent RSA key pairs for '{clientUsername}' from memory!")
        clientPermQueue.task_done()

async def clientHandle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global SERVER_SHUTDOWN
    clientUID = writer.get_extra_info('peername')[1]
    print(f"[NEW CONNECTION] {clientUID} connected.")
    print(f"[ACTIVE CONNECTION COUNT] {len(activeClients) + 1} client(s)!")
    if len(activeClients) >= MAX_AUTHENTICATE_CONNECTIONS:
        writer.close()
        print("[CONNECTION ABORT] Maximum client connection count reached.")
        return
    activeClients[clientUID] = {"Client Socket": writer, "SHA-512 Username": "", "Username": "", "Current Connection Status": "First Connection", "Current Friend Interaction": "", "Authenticated": False, "Message Counter": 0, "Auth Challenge": "", "Request Count": 0, "Log In Confirm Code Request Count": 0, "Account Registration Confirm Code Request Count": 0, "Reset Password Confirm Code Request Count": 0, "Unauthenticated Connection Time Limit": time.time() + UNAUTHENTICATE_SESSION_TIME_LIMIT}
    try:
        while True:
            activeClients[clientUID]["Request Count"] += 1
            if not activeClients[clientUID]["Authenticated"]:
                idleTimeout = 120 # Idle time for unauthenticated session is 2 minutes
            else:
                idleTimeout = 300 # Idle time for authenticated session is 5 minutes
            clientMsgLengthBytes = await asyncio.wait_for(reader.read(HEADER), timeout=idleTimeout)
            if not activeClients[clientUID]["Authenticated"] and time.time() >= activeClients[clientUID]["Unauthenticated Connection Time Limit"]: # Maximum Session for unauthenticated client is according to UNAUTHENTICATE_SESSION_TIME_LIMIT
                print(f"[UNAUTHENTICATE CONNECTION REACH LIMIT] Client {clientUID} been connecting to the server for too long and not authenticate yet!")
                raise ConnectionAbortedError
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
                            if activeClients[clientUID]["Request Count"] > REQUEST_RATE_LIMIT:
                                print(f"[TOO MANY REQUEST] Client {clientUID} send too many requests - Rate Limit Initiate!")
                                serverSignature = await asyncio.to_thread(serverDigitalSignature,"Too Many Request!")
                                await serverSendMessage(f'{{"Status Code": 429, "Server Message": "Too Many Request!", "Server Digital Signature": "{serverSignature}"}}', clientUID)
                                await asyncio.sleep(60)

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

                                    # User Attempt Log-In or Registering An Account or Account Reset Password
                                    if clientMsg.get("Message Code", "") == "#0002":

                                        authenticationStartTime = time.monotonic()

                                        clientMessageParts = clientMsg.get("Client Message", "").split(':')
                                        if len(clientMessageParts) == 5:
                                            authType = clientMessageParts[4]
                                            clientPassword = clientMessageParts[2] if authType == "Account Registration" else clientMessageParts[1]
                                            clientConfirmCode = clientMessageParts[3]
                                            clientUserName = clientMessageParts[0]

                                            confirmCodeRequestType = f"{authType} Confirm Code Request Count"
                                            if authType in ["Log In", "Account Registration", "Reset Password"]:

                                                # Log In, Registration and Reset Password Confirmation Code Brute-Force Prevention
                                                if activeClients[clientUID][confirmCodeRequestType] >= MAX_FAILED_LOGINS:
                                                    print(f"[{authType.upper()} FAIL] Client {clientUID} is suspicious for potential confirm code brute-force!")
                                                    if activeClients[clientUID][confirmCodeRequestType] >= 50:
                                                        raise ConnectionAbortedError
                                                    elif activeClients[clientUID][confirmCodeRequestType] >= 40:
                                                        trollMessage = "Nice Try Diddy!"
                                                    elif activeClients[clientUID][confirmCodeRequestType] >= 10:
                                                        trollMessage = "Still trying to brute force?"
                                                    else:
                                                        trollMessage = "Too Many Invalid Code Attempt!"
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, trollMessage)
                                                    serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 401, "Server Message": trollMessage, "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})

                                                else:
                                                    accountExist = False
                                                    if authType == "Account Registration":
                                                        # Account already exist, but we will mirror the same response structure as if the account does not exist, this prevents username enumeration by malicious user!
                                                        clientEmail = clientMessageParts[1]

                                                        if not clientUserName in account_data.keys(): # Username does not exist, check email
                                                            for _, accountData in account_data.items():
                                                                if clientEmail == accountData.get("Email"):
                                                                    accountExist = True
                                                        else:
                                                            for _, accountData in account_data.items(): # Still perform the email look up to prevent response timing different
                                                                if clientEmail == accountData.get("Email"):
                                                                    accountExist = True
                                                            accountExist = True
                                                        if clientEmail == SERVER_EMAIL_ADDRESS:
                                                            accountExist = True
                                                    else:
                                                        accountExist = False
                                                        # Account does not exist, but we will mirror the same response structure as if the account does exist, this prevents username enumeration by malicious user!
                                                        if clientUserName not in account_data.keys(): # If user provide an email, try to get client username to verify account exist
                                                            clientEmail = clientUserName
                                                            clientUserName = ''
                                                            for username, accountData in account_data.items():
                                                                if accountData.get("Email", '') == clientEmail:
                                                                    clientUserName = username
                                                                    accountExist = True
                                                        else: # If user provide an account username, and it exists, get the registered email with the account
                                                            accountExist = True
                                                            clientEmail = account_data.get(clientUserName, {}).get("Email", "")
                                                            for _, accountData in account_data.items():
                                                                if accountData.get("Email", '') == clientEmail:
                                                                    pass
                                                        if clientEmail == SERVER_EMAIL_ADDRESS:
                                                            accountExist = True
                                                    sendCode = False
                                                    message = ""
                                                    statusCode = 0
                                                    if (authType == "Account Registration" and not accountExist) or (authType in ["Log In", "Reset Password"] and accountExist):
                                                        if clientConfirmCode:
                                                            if clientEmail in temp_tokens[authType].keys():
                                                                tokenData = temp_tokens[authType].get(clientEmail, {})
                                                                if clientConfirmCode == tokenData["token"]:
                                                                    if time.time() < tokenData["expire"]:
                                                                        temp_tokens[authType].pop(clientEmail, None)

                                                                        # ----LOG IN (CONFIRM CODE ALREADY SENT)---
                                                                        if authType == "Log In":
                                                                            if account_data[clientUserName]["Current Lock Out Time"] >= LOCKOUT_SECONDS:
                                                                                print(f"[AUTHENTICATION CHECK] Client {clientUID} - Account '{clientUserName}' is locked!")
                                                                                lockedTimeRemaining = account_data[clientUserName]["Current Lock Out Time"] - time.time()
                                                                                lockedTimeRemainingFormat = time.strftime('%H:%M:%S', time.gmtime(lockedTimeRemaining))
                                                                                message = f"Your account is currently locked for {lockedTimeRemainingFormat}"
                                                                                statusCode = 403
                                                                            else:
                                                                                if verify_password(clientPassword, account_data[clientUserName]["Password"], checkReuse=False, checkMinimumAge=False, checkExpire=True):
                                                                                    print(f"[AUTHENTICATION CHECK] Client LOG IN CONFIRM CODE is VALID!")
                                                                                    print(f"[AUTHENTICATION CHECK] Sending an AUTH CHALLENGE to {clientUID}!")
                                                                                    authChallenge = secrets.token_hex(32)
                                                                                    activeClients[clientUID]["Auth Challenge"] = authChallenge
                                                                                    activeClients[clientUID]["SHA-512 Username"] = hashlib.sha512(clientUserName.encode()).hexdigest()
                                                                                    activeClients[clientUID]["Username"] = clientUserName
                                                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "Server is verifying your account public key!")
                                                                                    serverMsg = json.dumps({"Message Code": "#0002", "Status Code": 200, "Server Message": "Server is verifying your account public key!", "Auth Type": authType, "Auth Challenge": authChallenge, "Server Digital Signature": f"{serverSignature}"})
                                                                                    authenticationElapsedTime = time.monotonic() - authenticationStartTime
                                                                                    authenticationRemainingTime = AUTH_MIN_PROCESSING_TIME - authenticationElapsedTime
                                                                                    if authenticationRemainingTime > 0:
                                                                                        await asyncio.sleep(authenticationRemainingTime)

                                                                                    shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                                                                    await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)
                                                                                    continue
                                                                                else:
                                                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} Credential VALID, but expired!")
                                                                                    message = f"Your password has been expired!\nPlease reset for a new one!"
                                                                                    statusCode = 403

                                                                        # ----ACCOUNT REGISTRATION (CONFIRM CODE ALREADY SENT)---
                                                                        elif authType == "Account Registration":
                                                                            print(f"[NEW ACCOUNT REGISTRATION] Client {clientUID} sent a valid account registration code!")
                                                                            try:
                                                                                clientPermQueue.put_nowait({
                                                                                    "Username": clientUserName,
                                                                                    "Client UID":  clientUID,
                                                                                })
                                                                            except asyncio.QueueFull:
                                                                                print(f"[New RSA Key Generator Queue] RSA Generator queue is full! {authType} Verification Code was not queued for '{clientUserName}'!")
                                                                                message = "Unable to process request at this time.\nPlease try again later."
                                                                                statusCode = 503

                                                                        # ----RESET PASSWORD (CONFIRM CODE ALREADY SENT)---
                                                                        elif authType == "Reset Password":
                                                                            # Check if account is locked
                                                                            if account_data[clientUserName]["Current Lock Out Time"] >= LOCKOUT_SECONDS:
                                                                                lockedTimeRemaining = account_data[clientUserName]["Current Lock Out Time"] - time.time()
                                                                                lockedTimeRemainingFormat = time.strftime('%H:%M:%S', time.gmtime(lockedTimeRemaining))
                                                                                print(f"[NEW PASSWORD RESET FAIL] Account {clientUserName} is currently locked for {lockedTimeRemainingFormat}")
                                                                                message = f"Your account is currently locked for {lockedTimeRemainingFormat}"
                                                                                statusCode = 403
                                                                            else:
                                                                                if clientPassword == clientUserName:
                                                                                    print(f"[NEW PASSWORD RESET FAIL] Client {clientUID} set new password THE SAME AS the account username!")
                                                                                    message = "Your new password can not be the same as your username!"
                                                                                    statusCode = 401
                                                                                else:
                                                                                    # Check if credential reuse and just set
                                                                                    if verify_password(clientPassword, account_data[clientUserName]["Password"], checkReuse=False, checkMinimumAge=True, checkExpire=False):
                                                                                        if verify_password(clientPassword, account_data[clientUserName]["Password"], checkReuse=True, checkMinimumAge=False, checkExpire=False):
                                                                                            account_data[clientUserName]["Password"] = hashUserPassword(clientPassword, account_data[clientUserName]["Password"]["Past Credentials"])
                                                                                            async with ACCOUNT_LOCK:
                                                                                                async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                                                                    await accountDataFile.write(json.dumps(account_data, indent=4))
                                                                                            print(f"[NEW PASSWORD RESET SUCCESS] Client {clientUID} password reset SUCCESSFUL for account '{clientUserName}'")
                                                                                            message = f"Your password has been updated!"
                                                                                            statusCode = 200
                                                                                        else:
                                                                                            print(f"[NEW PASSWORD RESET FAIL] Client {clientUID} reuse password for account '{clientUserName}'")
                                                                                            message = f"Password reset failed. You can not use any of your previous passwords!"
                                                                                            statusCode = 401
                                                                                    else:
                                                                                        # Uh-Oh, user just change their password, but want to change again! Could be a potential attack for malicious user to abuse unlimited password reset!
                                                                                        print(f"[NEW PASSWORD RESET FAIL] Client {clientUID} think password reset is not rate limit for account '{clientUserName}'")
                                                                                        message = f"Password reset failed. You just changed your password!"
                                                                                        statusCode = 401

                                                                    else:
                                                                        # Code expire -> resend
                                                                        sendCode = True
                                                                        print(f"[{authType.upper()} FAIL] Client {clientUID} provided expired {authType.upper()} CODE!")
                                                                        temp_tokens[authType].pop(clientEmail, None)

                                                                else:
                                                                    print(f"[{authType.upper()} FAIL] Client {clientUID} provided INVALID {authType.upper()} CODE!")
                                                                    activeClients[clientUID][confirmCodeRequestType] += 1
                                                                    message = f"Invalid {authType} Code!"
                                                                    statusCode = 401
                                                            else:
                                                                # Code expire -> resend
                                                                activeClients[clientUID][confirmCodeRequestType] = 0
                                                                sendCode = True
                                                                print(f"[{authType.upper()} FAIL] Client {clientUID} provided expired {authType.upper()} CODE!")
                                                        else:
                                                            # ----LOG IN (CONFIRM CODE NOT SENT YET)---
                                                            if authType == "Log In":
                                                                if verify_password(clientPassword, account_data[clientUserName]["Password"], checkReuse=False, checkMinimumAge=False, checkExpire=False):
                                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} Credential VALID!")
                                                                    print(f"[AUTHENTICATION CHECK] Sending a LOG IN CONFIRM CODE to {clientUID}!")
                                                                    async with ACCOUNT_LOCK:
                                                                        async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                                            await accountDataFile.write(json.dumps(account_data, indent=4))
                                                                    sendCode = True
                                                                else:
                                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} Credential INVALID!")
                                                                    account_data[clientUserName]["Failed Attempts"] += 1
                                                                    if account_data[clientUserName]["Failed Attempts"] >= MAX_FAILED_LOGINS:
                                                                        print(f"[AUTHENTICATION CHECK] Client {clientUID} - Too many INVALID login attempt for account '{clientUserName}'!")
                                                                        account_data[clientUserName]["Current Lock Out Time"] = time.time() + LOCKOUT_SECONDS
                                                                        account_data[clientUserName]["Locked Out Record"].append(time.ctime(time.time()))
                                                                        message = "Too Many Invalid Log In Attempt!\nAccount is locked for 3 hr!"
                                                                        try:
                                                                            emailQueue.put_nowait({
                                                                                "Subject": "Account Lockout",
                                                                                "Content": f"Your 'David Secure Chatroom' account {clientUserName} is being locked out for 3 hr due to so many invalid login attempts!\n\nIf you suspect a malicious activity has been conducted against your account, please report to the server owner at (put-your-server-abuse-or-IT-email-here)",
                                                                                "Receiver Email": clientEmail
                                                                            })
                                                                        except asyncio.QueueFull:
                                                                            print(f"[Email Queue] Email queue is full! Account Lockout notification was not queued for account '{clientUserName}'!")
                                                                        else:
                                                                            print(f"[AUTHENTICATION CHECK] Account Lockout Notification email queued for registered email of account '{clientUserName}'!")
                                                                        statusCode = 403
                                                                    else:
                                                                        remaining = MAX_FAILED_LOGINS - account_data[clientUserName]["Failed Attempts"]
                                                                        message = f"Invalid Credential Provided!\nYou have {remaining} login attempts remaining!"
                                                                        statusCode = 401

                                                            # ----ACCOUNT REGISTRATION (CONFIRM CODE NOT SENT YET)---
                                                            elif authType == "Account Registration":
                                                                if clientUserName == clientPassword:
                                                                    print(f"[NEW ACCOUNT REGISTRATION FAIL] Client {clientUID} set new password THE SAME AS the account username!")
                                                                    message = "Your username can not be the same as your password!"
                                                                    statusCode = 401
                                                                else:
                                                                    match = re.match(USERNAME_PATTERN, clientUserName)
                                                                    if not match or clientUserName in account_data:
                                                                        print(f"[NEW ACCOUNT REGISTRATION FAIL] Client {clientUID} set account username DOES NOT pass the username policy!")
                                                                        message = "Username can only have mixed case ASCII letters, numbers and -._"
                                                                        statusCode = 401
                                                                    else:
                                                                        if len(clientPassword) < 12 or None in [re.search(r'[a-z]', clientPassword), re.search(r'[A-Z]', clientPassword), re.search(r'\d', clientPassword), re.search(r'[!@#$%&*_+=]', clientPassword)]:
                                                                            print(f"[NEW ACCOUNT REGISTRATION FAIL] Client {clientUID} set new password DOES NOT pass the secure password policy!")
                                                                            message = "Password must at least 12 characters!\nHave mixed case ASCII letters and numbers!\nHave any of the following special characters below:\n@#$%&*_+="
                                                                            statusCode = 401
                                                                        else:
                                                                            sendCode = True

                                                            # ----RESET PASSWORD (CONFIRM CODE NOT SENT YET)---
                                                            elif authType == "Reset Password":
                                                                if len(clientPassword) < 12 or None in [re.search(r'[a-z]', clientPassword), re.search(r'[A-Z]', clientPassword), re.search(r'\d', clientPassword), re.search(r'[!@#$%&*_+=]', clientPassword)]:
                                                                    print(f"[NEW PASSWORD RESET FAIL] Client {clientUID} set new password DOES NOT pass the secure password policy!")
                                                                    message = "Password must at least 12 characters!\nHave mixed case ASCII letters and numbers!\nHave any of the following special characters below:\n@#$%&*_+="
                                                                    statusCode = 401
                                                                else:
                                                                    sendCode = True

                                                        if sendCode:
                                                            confirmToken = ""
                                                            for i in range(random.randint(7, 30)):
                                                                confirmToken += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
                                                            temp_tokens[authType][clientEmail] = {"token": confirmToken, "expire": time.time() + CONFIRM_TOKEN_EXPIRY}
                                                            emailTitle = f"{authType} Verification Code"
                                                            try:
                                                                emailQueue.put_nowait({
                                                                    "Subject": emailTitle,
                                                                    "Content": f"Your 'David Secure Chatroom' {emailTitle} is {confirmToken}\n\nThis code will expire in {CONFIRM_TOKEN_EXPIRY // 60} minutes!\nIf you did not request this, please ignore this email.",
                                                                    "Receiver Email": clientEmail
                                                                })
                                                                statusCode = 200
                                                                message = f"If an account with the provided username or email {'doest not exist' if authType == "Account Registration" else 'does exist'}\nAn {authType} Verification Code will be sent to\nThe registered email with the account!"
                                                            except asyncio.QueueFull:
                                                                print(f"[Email Queue] Email queue is full! {authType} Verification Code was not queued for '{clientEmail}'!")
                                                                message = "Unable to process request at this time.\nPlease try again later."
                                                                statusCode = 503

                                                    else:
                                                        if authType == "Log In":
                                                            print(f"[AUTHENTICATION CHECK] Client {clientUID} provided NON-EXISTING account!")
                                                            # Always perform password verification. If the account does not exist, use DUMMY_PASSWORD_HASH so an attacker cannot distinguish account existence by password-hashing time.
                                                            activeClients[clientUID][confirmCodeRequestType] += 1
                                                            verify_password(clientPassword, DUMMY_PASSWORD_HASH, checkReuse=False, checkMinimumAge=False, checkExpire=False)
                                                            if activeClients[clientUID][confirmCodeRequestType] >= MAX_FAILED_LOGINS:
                                                                message = "Too Many Invalid Log In Attempt!\nAccount is locked for 3 hr!"
                                                                statusCode = 403
                                                            else:
                                                                message = f"Invalid Credential Provided!\nYou have {MAX_FAILED_LOGINS - activeClients[clientUID][confirmCodeRequestType]} login attempts remaining!"
                                                                statusCode = 401
                                                        else:
                                                            print(f"[{authType.upper()} FAIL] Client {clientUID} provided account {'already exist' if authType == "Account Registration" else 'does not exist'}!")
                                                            if clientConfirmCode:
                                                                activeClients[clientUID][confirmCodeRequestType] += 1
                                                                message = f"Invalid {authType} Code!"
                                                                statusCode = 401
                                                            else:
                                                                message = f"If an account with the provided username or email {'doest not exist' if authType == "Account Registration" else 'does exist'}\nAn {authType} Verification Code will be sent to\nThe registered email with the account!"
                                                                statusCode = 200

                                                    authenticationElapsedTime = time.monotonic() - authenticationStartTime
                                                    authenticationRemainingTime = AUTH_MIN_PROCESSING_TIME - authenticationElapsedTime
                                                    if authenticationRemainingTime > 0:
                                                        await asyncio.sleep(authenticationRemainingTime)

                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, message)
                                                    serverMsg = json.dumps({"Message Code": "#0002", "Status Code": statusCode, "Server Message": message, "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})

                                            #----INVALID METHOD--
                                            else:
                                                print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} for #0002 in invalid format!")
                                                serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                                serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                                await serverSendMessage(serverMsg, clientUID)
                                                continue
                                        else:
                                            print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} for #0002 in invalid format!")
                                            serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                            serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                            await serverSendMessage(serverMsg, clientUID)
                                            continue

                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)


                                    # User submit an authentication challenge and Perm PU hash to finalize login confirmation OR the final new account data for account registration confirmation
                                    elif clientMsg.get("Message Code", "") == "#0003":
                                        clientMessageParts = clientMsg.get("Client Message", "").split(':')
                                        if len(clientMessageParts) == 5:
                                            authType = clientMessageParts[4]
                                            if authType == "Log In":
                                                clientProvidedPUHashed, clientChallenge, clientPermSignature, _, __ = clientMessageParts
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
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Authentication Success!")
                                                        serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 200, "Server Message": "Authentication Success!", "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})
                                                        account_data[activeClients[clientUID]["Username"]]["Failed Attempts"] = 0
                                                        account_data[activeClients[clientUID]["Username"]]["Last Log In"] = time.ctime(time.time())
                                                        async with ACCOUNT_LOCK:
                                                            async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                                await accountDataFile.write(json.dumps(account_data, indent=4))
                                                    else:
                                                        print(f"[AUTHENTICATION CHECK] Client {clientUID} permanent key verification failure!")
                                                        serverSignature = await asyncio.to_thread(serverDigitalSignature, "Client Account Public Key Verification Error!")
                                                        serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 403, "Server Message": "Client Account Public Key Verification Error!", "Auth Type": authType,  "Server Digital Signature": f"{serverSignature}"})
                                                else:
                                                    print(f"[AUTHENTICATION CHECK] Client {clientUID} AUTH CHALLENGE failure!")
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "Client AUTH CHALLENGE failure!")
                                                    serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 403, "Server Message": "Client AUTH CHALLENGE failure!", "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})
                                            elif authType == "Account Registration":
                                                clientUserName, clientEmail, clientPassword, clientPermB64PU, _ = clientMessageParts
                                                clientPermPUBytes = base64.b64decode(clientPermB64PU)
                                                clientUserNameHash = hashlib.sha512(clientUserName.encode()).hexdigest()
                                                if hashlib.sha512(clientPermPUBytes).hexdigest() != registered_pu_hashes.get(clientUserNameHash, ''):
                                                    registered_pu_hashes.pop(clientUserNameHash, None)
                                                    print(f"[NEW ACCOUNT REGISTRATION FAIL] Client {clientUID} provided a different registered public key upon final confirmation!")
                                                    trollMessage = "Uh-OH!\nYou Provided...\nA Completely Different Public Key Than The Server Sent You!\nAccount Registration Fail!"
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, trollMessage)
                                                    serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 403, "Server Message": trollMessage, "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})
                                                else:
                                                    print(f"[NEW ACCOUNT REGISTRATION FAIL] Client {clientUID} final account registration confirmation acknowledge!")
                                                    async with ACCOUNT_LOCK:
                                                        storedPassword = hashUserPassword(clientPassword, [])
                                                        account_data[clientUserName] = {"Email": clientEmail, "Password": storedPassword, "Last Log In": time.ctime(time.time()), "Current Lock Out Time": 0, "Failed Attempts": 0, "Locked Out Record": [], "Friends": []}
                                                        pending_notifications[clientUserName] = {"Unread Messages": {}, "Pending Friend Requests": [], "Friend Request Answers": {}}
                                                        user_chat_history[clientUserName] = {}
                                                        async with aiofiles.open(f"{CLIENTS_REGISTERED_PUBLIC_KEY}{clientUserNameHash}.pem", "wb") as clientPermPU:
                                                            await clientPermPU.write(clientPermPUBytes)
                                                        async with aiofiles.open(USER_ACCOUNT_JSON_PATH, "w") as accountDataFile:
                                                            await accountDataFile.write(json.dumps(account_data, indent=4))
                                                    async with NOTIF_LOCK:
                                                        async with aiofiles.open(USER_PENDING_NOTIFICATIONS_JSON_PATH, "w") as pendingNotificationFile:
                                                            await pendingNotificationFile.write(json.dumps(pending_notifications, indent=4))
                                                    async with CHAT_LOCK:
                                                        async with aiofiles.open(USER_CHAT_HISTORY_JSON_PATH, "w") as chathistoryFile:
                                                            await chathistoryFile.write(json.dumps(user_chat_history, indent=4))
                                                    activeClients[clientUID]["Authenticated"] = True
                                                    activeClients[clientUID]["SHA-512 Username"] = clientUserNameHash
                                                    activeClients[clientUID]["Username"] = clientUserName
                                                    print(f"[NEW ACCOUNT REGISTRATION] Client {clientUID} registered account '{clientUserName}'")
                                                    serverSignature = await asyncio.to_thread(serverDigitalSignature, "New Account Registration Successful!")
                                                    serverMsg = json.dumps({"Message Code": "#0003", "Status Code": 200, "Server Message": "New Account Registration Successful!", "Auth Type": authType, "Server Digital Signature": f"{serverSignature}"})
                                            else:
                                                print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} for #0003 in invalid format!")
                                                serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                                serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                        else:
                                            print(f"[BAD REQUEST ERROR] Recieved data from client {clientUID} for #0003 in invalid format!")
                                            serverSignature = await asyncio.to_thread(serverDigitalSignature, "Bad Request Error")
                                            serverMsg = json.dumps({"Status Code": 400, "Server Message": "Bad Request Error", "Server Digital Signature": f"{serverSignature}"})
                                        shareSecret, cipherText = await asyncio.to_thread(clientHybridEncryption, serverMsg, f"{CLIENTS_TEMP_PUBLIC_KEY}{clientUID}.pem")
                                        await serverSendMessage(f"{shareSecret}:{cipherText}", clientUID)

                                        # Broadcast new user just joined to all current active authenticated users
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
    except (asyncio.TimeoutError, TimeoutError):
        print(f"[IDLE TIMEOUT] {'Authenticated' if activeClients[clientUID]["Authenticated"] else 'Unauthenticated'} client {clientUID} idle too long. Disconnecting.")
    except ValueError: # A device try to connect to the server that did not use the official client.py
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
        asyncio.create_task(rateLimitReset())
        asyncio.create_task(clearExpireConfirmTokens())
        asyncio.create_task(emailWorker())
        asyncio.create_task(clientRSAAssigningWorker())
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
