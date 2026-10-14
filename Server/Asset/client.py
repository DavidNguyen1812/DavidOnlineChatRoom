import sys
import asyncio
from qasync import QEventLoop, asyncSlot
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSpacerItem, QSizePolicy, QStyledItemDelegate, QStyle,
    QSplitter, QLabel, QTextEdit, QLineEdit, QPushButton, QMessageBox, QListWidget, QListWidgetItem, QDialog, QTabWidget
)
from PySide6.QtCore import Qt, QSize, QObject, Signal, Slot
from PySide6.QtGui import QFont, QColor, QCloseEvent, QPainter, QPen, QGuiApplication

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from typing import Any, Tuple, Literal

import time, os, hashlib, base64, json, pathlib


HEADER = 64 # HEADER value must match the server header value
PORT = 3200 # Client port number must match the server port to have a successful socket connection
SERVER_IP = '127.0.0.1' # Server IP must be a public IP and valid and the server must be up to have a successful socket connection
ROOT_DIR = pathlib.Path(__file__).parent.parent.absolute()
SERVER_PUBLIC_KEY = str(ROOT_DIR / "RSAKeys" / "ServerPU" / "ServerRSApublicKey.pem")
CLIENT_TEMP_PUBLIC_KEY = str(ROOT_DIR / "RSAKeys" / "Ephemeral" / "ClientRSApublicKey.pem")
CLIENT_TEMP_PRIVATE_KEY = str(ROOT_DIR / "RSAKeys" / "Ephemeral" / "ClientRSAprivateKey.pem")
CLIENT_PERMANENT_KEY_FOLDER = str(ROOT_DIR / "RSAKeys" / "Permanent")
CLIENT_SOURCE_CODE = pathlib.Path(__file__).absolute()
CURRENT_FRIEND_PUBLIC_KEY = f"{ROOT_DIR / "RSAKeys" / "CurrentFriendPU"}/"

# DO NOT MODIFY THIS
SERVERPUBLICKEYHASH = "3d33af6e392df3dd32584e5a74549790ec0ded67fc7dd95ce56ba7a8cb85208fab54479e722f2d2f16488c3b2c66ec4e9ac624c947a4a4732d5d678e2506d16d"

STATUS = "FIRST CONNECTION"
USERNAME = ''

client_reader = None
client_writer = None
message_counter = 0

def nextCounter() -> int:
    """Monotonic per-connection message counter (Safeguard against replay attack)."""
    global message_counter
    message_counter += 1
    return message_counter


if os.path.exists(CLIENT_TEMP_PRIVATE_KEY):
    os.remove(CLIENT_TEMP_PRIVATE_KEY)
if os.path.exists(CLIENT_TEMP_PUBLIC_KEY):
    os.remove(CLIENT_TEMP_PUBLIC_KEY)

key = RSA.generate(4096)
privateKey = key.export_key()
publicKey = key.publickey().export_key()
with open(CLIENT_TEMP_PRIVATE_KEY, "wb") as pemfile:
    pemfile.write(privateKey)
with open(CLIENT_TEMP_PUBLIC_KEY, "wb") as pemfile:
    pemfile.write(publicKey)
print("New Ephemeral RSA keys have been generated")

async def sendMessageToServer(message: str) -> None:
    """
    Description: Sending message to the server
    :param message: The message content
    """
    sendLength = str(len(message)).encode()
    sendLength += b' ' * (HEADER - len(sendLength))
    client_writer.write(sendLength)
    client_writer.write(message.encode())
    await client_writer.drain()


def serverHybridEncryption(data: Any) -> Tuple[str, str]:
    """
    Description: Perform a hybrid encryption of AES-256 and RSA-4096 on data to send to server
    :param data: Data to be encrypted
    :return: shared secret, cipher text
    """
    # Client generate random AES session key
    sessionKey = base64.b64encode(get_random_bytes(256 // 8)).decode('ascii')
    # Client encrypt message with the AES session key
    cipher = AES.new(base64.b64decode(sessionKey), AES.MODE_OCB)
    # Client obtain tag and nonce value
    ciphertext, AEStag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Client bundle the AES key, tag, and nonce value
    keyBundle = f"{sessionKey}:{base64.b64encode(AEStag).decode('ascii')}:{base64.b64encode(cipher.nonce).decode('ascii')}"
    # Client encrypt key bundle with server public key to obtain shared secret
    cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(SERVER_PUBLIC_KEY).read()))
    sharedSecret = cipherRSA.encrypt(keyBundle.encode())
    sharedSecret = base64.b64encode(sharedSecret).decode('ascii')
    cipherText = base64.b64encode(ciphertext).decode('ascii')
    return sharedSecret, cipherText


def DigitalSignatureVerification(signature: str, receivedData: str, key: str) -> bool:
    """
    Description: Verify an RSA digital signature
    :param signature: Received signature
    :param receivedData: Received data from server
    :param key: Which RSA Public key to use
    :return: Verification success or not
    """
    verifierKey = RSA.import_key(open(key, 'rb').read())
    signature = base64.b64decode(signature)
    hashedMsg = SHA256.new(receivedData.encode())
    verifier = pss.new(verifierKey)
    try:
        verifier.verify(hashedMsg, signature)
        return True
    except (ValueError, TypeError):
        return False


def serverHybridDecryption(sharedSecret: str, cipherText: str) -> Tuple[bool, str]:
    """
    Description: Perform a hybrid decryption of AES-256 and RSA-4096 data received from server
    :param sharedSecret: Base64 encoded RSA-encrypted key bundle
    :param cipherText: Base64 encoded AES-encrypted data
    :return: Decryption Status, Decrypted original string
    """
    try:
        # Decode the Base64 strings back to raw bytes
        encryptedKeyBundle = base64.b64decode(sharedSecret)
        cipherText = base64.b64decode(cipherText)

        # Decrypt the key bundle using the Client's Private Key
        private_key = RSA.import_key(open(CLIENT_TEMP_PRIVATE_KEY).read())
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
        return True, decryptedData.decode()
    except Exception as e:
        return False, str(e)


def clientDigitalSignature(sendingData: str, key: str) -> str:
    """
    Description: Client Digitally Sign the data to be sent to the Server
    :param sendingData: The ASCII data to be sent to the client
    :param key: Which private key to use (Temp/Permanent)
    :return: The Digital Signature
    """
    signingKey = RSA.import_key(open(key, 'rb').read())
    hashedContent = SHA256.new(sendingData.encode())
    return base64.b64encode(pss.new(signingKey).sign(hashedContent)).decode('ascii')


def RSAencrypt(data: Any, key: str) -> str:
    """
    Description: Encrypt data using RSA-4096
    :param data: Data to be encrypted
    :param key: Which public key to use (Temp/Perm)
    :return: Encrypted data
    """
    cipherRSA = PKCS1_OAEP.new(RSA.import_key(open(key).read()))
    return base64.b64encode(cipherRSA.encrypt(data.encode())).decode('ascii')


def RSAdecrypt(cipherText: str, key: str) -> Tuple[bool, str]:
    """
    Description: Perform an RSA-4096 decryption to obtain the AES-256 key bundle
    :param cipherText: Base64 encoded RSA-4096-encrypted data
    :param key: Which private key to use
    :return: Decryption Status, Decrypted original string
    """
    try:
        # Decode the Base64 strings back to raw bytes
        cipherText = base64.b64decode(cipherText)
        # Decryption
        private_key = RSA.import_key(open(key).read())
        cipherRSA = PKCS1_OAEP.new(private_key)
        return True, cipherRSA.decrypt(cipherText).decode('utf-8')
    except Exception as e:
        return False, str(e)


def aesEncryption(data: Any) -> Tuple[str, str]:
    """
    Description: Encrypt data using AES-256
    :param data: Original data to be encrypted
    :return: AES Key Bundle, AES cipher text
    """
    # Generate random AES session key
    sessionKey = base64.b64encode(get_random_bytes(256 // 8)).decode('ascii')
    # Encrypt message with the AES session key
    cipher = AES.new(base64.b64decode(sessionKey), AES.MODE_OCB)
    # Obtain tag and nonce value
    ciphertext, AEStag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Bundle the AES key, tag, and nonce value
    ciphertext = base64.b64encode(ciphertext).decode('ascii')
    return f"{sessionKey}:{base64.b64encode(AEStag).decode('ascii')}:{base64.b64encode(cipher.nonce).decode('ascii')}", ciphertext


def aesDecryption(aesKeyBundle: str, cipherText: str) -> Tuple[bool, str]:
    """
    Description: Perform an AES-256 decryption to obtain the original message
    :param aesKeyBundle: AES-256 key bundle
    :param cipherText: The AES-256 encrypted data
    :return: Decryption Status, Decrypted original string
    """
    try:
        cipherText = base64.b64decode(cipherText)
        sessionKey_b64, AEStag_b64, nonce_b64 = aesKeyBundle.split(":")

        # Decode the extracted components from Base64 to raw bytes
        sessionKey = base64.b64decode(sessionKey_b64)
        AEStag = base64.b64decode(AEStag_b64)
        nonce = base64.b64decode(nonce_b64)

        # Reconstruct the AES cipher in OCB mode using the session key and nonce
        cipherAES = AES.new(sessionKey, AES.MODE_OCB, nonce=nonce)

        # Decrypt AND verify the ciphertext
        return True, cipherAES.decrypt_and_verify(cipherText, AEStag).decode()
    except Exception as e:
        return False, str(e)


class ThreadSignals(QObject):
    server_connection_error = Signal()
    bad_request = Signal()
    invalid_request = Signal()
    rate_limit = Signal()
    server_pu_verification_failure = Signal()
    sending_source_code_and_temp_pu = Signal()
    server_ds_verification_failure = Signal()
    server_client_ds_verification_failure = Signal()
    client_code_update = Signal(bytes, str)
    server_decryption_failure = Signal()
    client_decryption_failure = Signal()
    launch_authentication_window = Signal()
    show_server_message_in_login_form = Signal(str, bool)
    disable_login_form_input = Signal(bool)
    show_server_message_in_registration_form = Signal(str, bool)
    disable_registration_form_input = Signal(bool)
    show_server_message_in_reset_form = Signal(str, bool)
    disable_reset_form_input = Signal(bool)
    authentication_success = Signal(bool)
    update_current_online_user_list = Signal(str, str)
    update_current_friend_list = Signal(dict)
    update_pending_notifications = Signal(str, str, int)
    decrypt_chat_history = Signal(bool, list)
    message_delivered_success = Signal(bool)
    remove_current_online_user = Signal(str)


signals = ThreadSignals()


async def receiveMessage() -> None:
    """
    Description: Continuous listening for message from the server
    """
    global STATUS
    try:
        while True:
            serverMsgLengthBytes = await client_reader.read(HEADER)
            serverMsg = b""
            if serverMsgLengthBytes:
                serverMsgLength = int(serverMsgLengthBytes.decode())
                try:
                    serverMsg = await client_reader.readexactly(serverMsgLength)
                except asyncio.IncompleteReadError:
                    signals.server_connection_error.emit()
                    return
            else:
                raise ConnectionAbortedError
            serverMsg = serverMsg.decode()

            if STATUS == "FIRST CONNECTION":
                serverMsg = json.loads(serverMsg)
                if serverMsg.get("Message Code", '') == "#0000":
                    if serverMsg.get("Status Code", 0) == 400:
                        signals.bad_request.emit()
                    if serverMsg.get("Status Code", 0) == 200:
                        ServerPU = serverMsg.get("Server Public Key", "")
                        ServerPU = base64.b64decode(ServerPU)
                        ServerPUHash = hashlib.sha512(ServerPU).hexdigest()
                        if ServerPUHash == SERVERPUBLICKEYHASH:
                            STATUS = "IN SESSION"
                            with open(SERVER_PUBLIC_KEY, "wb") as pemfile:
                                pemfile.write(ServerPU)
                            signals.sending_source_code_and_temp_pu.emit()
                        else:
                            signals.server_pu_verification_failure.emit()
                else:
                    signals.server_connection_error.emit()
            elif STATUS == "IN SESSION":
                try:
                    serverMsg = json.loads(serverMsg)
                    if await asyncio.to_thread(DigitalSignatureVerification, serverMsg.get("Server Digital Signature", ''), serverMsg.get("Server Message", ''), SERVER_PUBLIC_KEY):
                        if serverMsg.get("Status Code", 0) == 400:
                            signals.bad_request.emit()
                        elif serverMsg.get("Status Code", 0) == 401:
                            signals.invalid_request.emit()
                        elif serverMsg.get("Status Code", 0) == 429:
                            signals.rate_limit.emit()
                        elif serverMsg.get("Status Code", 0) == 500:
                            signals.server_decryption_failure.emit()
                        elif serverMsg.get("Status Code", 0) == 501:
                            signals.server_client_ds_verification_failure.emit()
                    else:
                        signals.server_ds_verification_failure.emit()
                except (TypeError, ValueError, SyntaxError):
                    if len(serverMsg.split(':')) == 2:
                        serverSharedSecret = serverMsg.split(':')[0]
                        encryptedServerData = serverMsg.split(':')[1]
                        decryptionStatus, decryptedServerData = await asyncio.to_thread(serverHybridDecryption,serverSharedSecret, encryptedServerData)
                        if decryptionStatus:
                            serverMsg = json.loads(decryptedServerData)
                            if await asyncio.to_thread(DigitalSignatureVerification, serverMsg.get("Server Digital Signature", ''), serverMsg.get("Server Message", ''), SERVER_PUBLIC_KEY):
                                if serverMsg.get("Message Code", '') == "#0001":
                                    statusCode = serverMsg.get("Status Code", 0)
                                    if statusCode == 200:
                                        # DO NOT MODIFY THIS LINE
                                        if serverMsg.get("Server Message", '') == "Client Source Code Verification Success":
                                            signals.launch_authentication_window.emit()
                                    elif statusCode == 202:
                                        updateSourceCode = base64.b64decode(serverMsg.get("Server Message", '').split(":")[0])
                                        hashSourceCode = serverMsg.get("Server Message", '').split(":")[1]
                                        signals.client_code_update.emit(updateSourceCode, hashSourceCode)

                                elif serverMsg.get("Message Code", '') == "#0002":
                                    statusCode = serverMsg.get("Status Code", 0)
                                    authType = serverMsg.get("Auth Type", "")
                                    serverMessage = serverMsg.get('Server Message', '')
                                    if authType in ["Log In", "Account Registration", "Reset Password"]:
                                        showServerMsgSignal = signals.show_server_message_in_login_form if authType == "Log In" else signals.show_server_message_in_registration_form if authType == "Account Registration" else signals.show_server_message_in_reset_form
                                        disableFormInputSignal = signals.disable_login_form_input if authType == "Log In" else signals.disable_registration_form_input if authType == "Account Registration" else signals.disable_reset_form_input
                                        if statusCode == 200:
                                            if "Your account official permanent RSA key pairs!" in serverMessage:
                                                if len(serverMessage.split(":")) == 3:
                                                    serverAssignedPI, serverAssignedPU, _ = serverMessage.split(":")
                                                    with open(f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSAprivateKey.pem", 'wb') as clientPI:
                                                        clientPI.write(base64.b64decode(serverAssignedPI))
                                                    with open(f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSApublicKey.pem", 'wb') as clientPU:
                                                        clientPU.write(base64.b64decode(serverAssignedPU))
                                                showServerMsgSignal.emit(f"The server sent you the assigned RSA keys!\nIt can be locate at RSAKeys/Permanent/ from your Client folder\nThese keys are linked to your account data!\nThe private key is never store on the server!\nIf you loose the key, you will lose access to your account forever!", False)
                                            else:
                                                showServerMsgSignal.emit(serverMessage, False)
                                                if authType == "Log In":
                                                    if serverMessage.startswith("If an account with"):
                                                        showServerMsgSignal.emit("Confirm Code", False)
                                                        disableFormInputSignal.emit(False)
                                                    if serverMessage == "Server is verifying your account public key!":
                                                        authChallenge = serverMsg.get("Auth Challenge", "")
                                                        with open(f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSApublicKey.pem", 'rb') as clientPU:
                                                            clientPermPU = clientPU.read()
                                                        hashedClientPermPU = hashlib.sha512(clientPermPU).hexdigest()
                                                        permSignature = await asyncio.to_thread(clientDigitalSignature, f"{hashedClientPermPU}:{authChallenge}", f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSAprivateKey.pem")
                                                        clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{hashedClientPermPU}:{authChallenge}:{permSignature}::Log In", CLIENT_TEMP_PRIVATE_KEY)
                                                        clientMsg = json.dumps({"Message Code": "#0003", "Client Message": f"{hashedClientPermPU}:{authChallenge}:{permSignature}::Log In", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                                                        sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption,clientMsg)
                                                        await sendMessageToServer(f"{sharedSecret}:{cipherText}")
                                                else:
                                                    disableFormInputSignal.emit(False)
                                        else:
                                            showServerMsgSignal.emit(serverMessage, True)
                                            if statusCode == 403:
                                                await asyncio.sleep(4)
                                                signals.authentication_success.emit(False)
                                            else:
                                                await asyncio.sleep(2)
                                                disableFormInputSignal.emit(False)

                                elif serverMsg.get("Message Code", '') == "#0003":
                                    authType = serverMsg.get("Auth Type", '')
                                    statusCode = serverMsg.get("Status Code", 0)
                                    showServerMsgSignal = signals.show_server_message_in_login_form if authType == "Log In" else signals.show_server_message_in_registration_form
                                    disableFormInputSignal = signals.disable_login_form_input if authType == "Log In" else signals.disable_registration_form_input
                                    showServerMsgSignal.emit(serverMsg.get("Server Message", ''), statusCode == 403)
                                    disableFormInputSignal.emit(statusCode != 403)
                                    if statusCode == 403:
                                        await asyncio.sleep(5)
                                    else:
                                        await asyncio.sleep(1)
                                    signals.authentication_success.emit(statusCode == 200)

                                elif serverMsg.get("Message Code", '') == "#0004":
                                    try:
                                        bigBoyData = json.loads(serverMsg.get("Server Message", ""))
                                        allOnlineUsers = bigBoyData.get("Current Online Users", {})
                                        allFriends = bigBoyData.get("Current Friend List", [])
                                        pendingNotifications = bigBoyData.get("Current Pending Notifications", {})
                                        for username, relationship in allOnlineUsers.items():
                                            signals.update_current_online_user_list.emit(username, relationship)
                                        for friendData in allFriends:
                                            signals.update_current_friend_list.emit(friendData)
                                        unreadMessages = pendingNotifications.get("unread_messages", {})
                                        friendRequests = pendingNotifications.get("friend_request", [])
                                        friendAccept = pendingNotifications.get("request_accepted", [])
                                        friendReject = pendingNotifications.get("request_rejected", [])
                                        for notification in unreadMessages:
                                            for username, unreadMessage in notification.items():
                                                signals.update_pending_notifications.emit("unread_messages", username,int(unreadMessage))
                                        for friend in friendRequests:
                                            signals.update_pending_notifications.emit("friend_request", friend, 0)
                                        for user in friendAccept:
                                            signals.update_pending_notifications.emit("request_accepted", user, 0)
                                        for user in friendReject:
                                            signals.update_pending_notifications.emit("request_rejected", user, 0)
                                    except (TypeError, ValueError):
                                        signals.client_decryption_failure.emit()
                                elif serverMsg.get("Message Code", '') == "#0005":
                                    try:
                                        bigBoyData = json.loads(serverMsg.get("Server Message", ""))
                                        friendPUBytes = base64.b64decode(bigBoyData.get("Friend Registered PU", ""))
                                        friendEncryptedChatHistory = bigBoyData.get("Encrypted Chat History", [])
                                        with open(f"{CURRENT_FRIEND_PUBLIC_KEY}PublicKey.pem", "wb") as friendPU:
                                            friendPU.write(friendPUBytes)
                                        signals.decrypt_chat_history.emit(True, friendEncryptedChatHistory)
                                    except (TypeError, ValueError):
                                        signals.client_decryption_failure.emit()
                                elif serverMsg.get("Message Code", '') == "#0006":
                                    if serverMsg.get("Server Message", "") == "Message Deliver Success!":
                                        signals.message_delivered_success.emit(True)
                                    else:
                                        signals.decrypt_chat_history.emit(False, [json.loads(serverMsg.get("Server Message", ""))])
                                elif serverMsg.get("Message Code", '') == "#0007":
                                    bigBoyData = json.loads(serverMsg.get("Server Message", ""))
                                    newClientUsername = bigBoyData.get("New Client Connected", "")
                                    relationship = bigBoyData.get("Relationship", "")
                                    signals.update_current_online_user_list.emit(newClientUsername, relationship)
                                    if relationship == 'Friend':
                                        signals.update_current_friend_list.emit({"name": newClientUsername, "online": relationship == "Friend"})
                                elif serverMsg.get("Message Code", '') == "#0008":
                                    signals.remove_current_online_user.emit(serverMsg.get("Server Message"))
                                elif serverMsg.get("Message Code", '') == "#0009":
                                    bigBoyData = json.loads(serverMsg.get("Server Message", ""))
                                    notificationType = bigBoyData.get("Notification Type")
                                    username = bigBoyData.get("From", "")
                                    if notificationType:
                                        if notificationType == "unread_messages":
                                            signals.update_pending_notifications.emit("unread_messages", username, bigBoyData.get("Current Unread Messages", 0))
                                        else:
                                            signals.update_pending_notifications.emit(notificationType, username, 0)
                                        if notificationType == "friend_request":
                                            signals.update_current_online_user_list.emit(username, "Pending Friend Invitation")
                                        if notificationType == "request_accepted":
                                            signals.update_current_online_user_list.emit(username, "Friend")
                                            signals.update_current_friend_list.emit({"name": username, "online": True})
                                        elif notificationType == "request_rejected":
                                            signals.update_current_online_user_list.emit(username, "None")
                            else:
                                signals.server_ds_verification_failure.emit()
                        else:
                            signals.client_decryption_failure.emit()
                    else:
                        signals.client_decryption_failure.emit()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        signals.server_connection_error.emit()
        return
    except OSError:
        return

def applyColoringTheme(self, scheme: Qt.ColorScheme):
    if scheme == Qt.ColorScheme.Dark:
        self.setStyleSheet("""
            QDialog {
                background-color: #121212;
            }
            QLabel#titleLabel {
                font-size: 30px;
                font-weight: bold;
                color: #ffffff;
                margin-bottom: 20px;
            }
            QLabel {
                font-size: 13px;
                font-weight: bold;
                color: #e0e0e0;
            }
            QLabel#serverMessageLabel {
                font-size: 12px;
                font-weight: bold;
                font-style: italic;
                color: #ff6b6b; /* Lighter red to stand out against dark background */
                margin-top: 5px;
            }
            QLineEdit {
                padding: 10px;
                font-size: 14px;
                border: 1px solid #444444;
                border-radius: 6px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLineEdit:focus { 
                border: 2px solid #3498db; 
            }
            QPushButton {
                background-color: #2980b9;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
                margin-top: 10px;
            }
            QPushButton:hover { 
                background-color: #3498db; 
            }
            QPushButton:pressed { 
                background-color: #1f618d; 
            }
        """)
    else:
        self.setStyleSheet("""
            QDialog {background-color: #f7f9fc;}
            QLabel#titleLabel {
                font-size: 30px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 20px;
            }
            QLabel {
                font-size: 13px;
                font-weight: bold;
                color: #34495e;
            }
            QLabel#serverMessageLabel {
                font-size: 12px;
                font-weight: bold;
                font-style: italic;
                color: #e74c3c;
                margin-top: 5px;
            }
            QLineEdit {
                padding: 10px;
                font-size: 14px;
                border: 1px solid #bdc3c7;
                border-radius: 6px;
                background-color: #ffffff;
                color: #2c3e50;
            }
            QLineEdit:focus { border: 2px solid #3498db; }
            QPushButton {
                background-color: #3498db;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
                margin-top: 10px;
            }
            QPushButton:hover { background-color: #2980b9; }
            QPushButton:pressed { background-color: #1f618d; }
        """)

class LoginTab(QWidget):
    def __init__(self):
        super().__init__()
        self.code_confirmation_state = False
        # Apply initial theme on startup
        applyColoringTheme(self, QGuiApplication.styleHints().colorScheme())
        # Listen for OS theme changes
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda colorScheme, myself=self: applyColoringTheme(myself, colorScheme))

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(15)

        title_label = QLabel("Log In")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setObjectName("titleLabel")  # Set object name for specific CSS targeting

        self.username_label = QLabel("Username")
        self.username_input = QLineEdit()
        self.username_input.setMaxLength(40)
        self.username_input.setPlaceholderText("Enter your username or gmail")

        self.password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setMaxLength(40)
        # Mask the password input with dots
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_code_label = QLabel("Log In Confirm Code")
        self.confirm_code_input = QLineEdit()
        self.confirm_code_input.setMaxLength(40)
        self.confirm_code_input.setPlaceholderText("Enter a valid confirmation code")
        self.confirm_code_label.hide()
        self.confirm_code_input.hide()

        self.password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setMaxLength(40)
        # Mask the password input with dots
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.submit_button = QPushButton("Submit")
        self.submit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_button.setAutoDefault(True)  # Click upon Enter key is pressed
        self.submit_button.clicked.connect(self.sendingFormInput)

        self.username_input.returnPressed.connect(self.submit_button.click)
        self.password_input.returnPressed.connect(self.submit_button.click)
        self.confirm_code_input.returnPressed.connect(self.submit_button.click)

        self.server_message_label = QLabel("")
        self.server_message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.server_message_label.setObjectName("serverMessageLabel")
        self.server_message_label.hide()  # Hidden by default

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        main_layout.addWidget(title_label)
        main_layout.addWidget(self.username_label)
        main_layout.addWidget(self.username_input)
        main_layout.addWidget(self.password_label)
        main_layout.addWidget(self.password_input)
        main_layout.addWidget(self.confirm_code_label)
        main_layout.addWidget(self.confirm_code_input)
        main_layout.addWidget(self.submit_button)
        main_layout.addWidget(self.server_message_label)

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        signals.show_server_message_in_login_form.connect(self.showInfoMessage)
        signals.disable_login_form_input.connect(self.lockedFormInput)

    @Slot(bool)
    def lockedFormInput(self, locked):
        if not self.code_confirmation_state:
            self.username_input.setDisabled(locked)
            self.password_input.setDisabled(locked)
        else:
            self.username_input.setDisabled(True)
            self.password_input.setDisabled(True)
            self.confirm_code_input.setDisabled(locked)
        self.submit_button.setDisabled(locked)

    @asyncSlot()
    async def sendingFormInput(self):
        if not self.submit_button.isEnabled():
            return
        self.lockedFormInput(True)
        username = self.username_input.text()
        password = self.password_input.text()
        if not self.code_confirmation_state:
            if username and password:
                clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{password}:::Log In", CLIENT_TEMP_PRIVATE_KEY)
                clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{password}:::Log In", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                await sendMessageToServer(f"{sharedSecret}:{cipherText}")
            else:
                self.showInfoMessage("Input fields can not be empty!")
                self.lockedFormInput(False)
        else:
            if self.confirm_code_input.text():
                clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{password}::{self.confirm_code_input.text()}:Log In", CLIENT_TEMP_PRIVATE_KEY)
                clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{password}::{self.confirm_code_input.text()}:Log In", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                await sendMessageToServer(f"{sharedSecret}:{cipherText}")
            else:
                self.showInfoMessage("Input fields can not be empty!")
                self.lockedFormInput(False)

    @Slot(str, bool)
    def showInfoMessage(self, message: str, is_error: bool = True):
        if message == "Confirm Code" and "Please try again later." not in message:
            self.code_confirmation_state = True
            self.username_label.hide()
            self.username_input.hide()
            self.password_label.hide()
            self.password_input.hide()
            self.confirm_code_label.show()
            self.confirm_code_input.show()
        else:
            self.server_message_label.setText(message)
            if not is_error:
                self.server_message_label.setStyleSheet("color: #27ae60;")
            else:
                self.server_message_label.setStyleSheet("")
            self.server_message_label.show()


class RegisterTab(QWidget):
    def __init__(self):
        super().__init__()
        self.code_confirmation_state = False
        self.confirm_registration = False
        # Apply initial theme on startup
        applyColoringTheme(self, QGuiApplication.styleHints().colorScheme())
        # Listen for OS theme changes
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda colorScheme, myself=self: applyColoringTheme(myself, colorScheme))
        signals.show_server_message_in_registration_form.connect(self.showInfoMessage)
        signals.disable_registration_form_input.connect(self.lockedFormInput)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(15)

        title_label = QLabel("Register An Account")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setObjectName("titleLabel")  # Set object name for specific CSS targeting

        self.email_label = QLabel("Email")
        self.email_input = QLineEdit()
        self.email_input.setMaxLength(40)
        self.email_input.setPlaceholderText("Enter an email address")

        self.username_label = QLabel("Username")
        self.username_input = QLineEdit()
        self.username_input.setMaxLength(40)
        self.username_input.setPlaceholderText("Enter a username")

        self.password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter a password")
        self.password_input.setMaxLength(40)
        # Mask the password input with dots
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_code_label = QLabel("Account Registration Confirm Code")
        self.confirm_code_input = QLineEdit()
        self.confirm_code_input.setPlaceholderText("Enter a valid confirmation code")
        self.confirm_code_input.setMaxLength(40)
        self.confirm_code_label.hide()
        self.confirm_code_input.hide()

        self.submit_button = QPushButton("Submit")
        self.submit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_button.setAutoDefault(True) # Click upon Enter key is pressed
        self.submit_button.clicked.connect(self.sendingFormInput)

        self.email_input.returnPressed.connect(self.submit_button.click)
        self.username_input.returnPressed.connect(self.submit_button.click)
        self.password_input.returnPressed.connect(self.submit_button.click)
        self.confirm_code_input.returnPressed.connect(self.submit_button.click)

        self.server_message_label = QLabel("")
        self.server_message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.server_message_label.setObjectName("serverMessageLabel")
        self.server_message_label.hide()  # Hidden by default

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        main_layout.addWidget(title_label)
        main_layout.addWidget(self.email_label)
        main_layout.addWidget(self.email_input)
        main_layout.addWidget(self.username_label)
        main_layout.addWidget(self.username_input)
        main_layout.addWidget(self.password_label)
        main_layout.addWidget(self.password_input)
        main_layout.addWidget(self.confirm_code_label)
        main_layout.addWidget(self.confirm_code_input)
        main_layout.addWidget(self.submit_button)
        main_layout.addWidget(self.server_message_label)

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

    @Slot(bool)
    def lockedFormInput(self, locked):
        if not self.confirm_registration:
            if not self.confirm_registration:
                if not self.code_confirmation_state:
                    self.email_input.setDisabled(locked)
                    self.username_input.setDisabled(locked)
                    self.password_input.setDisabled(locked)
                else:
                    self.email_input.setDisabled(True)
                    self.username_input.setDisabled(True)
                    self.password_input.setDisabled(True)
                    self.confirm_code_input.setDisabled(locked)
        self.submit_button.setDisabled(locked)

    @asyncSlot()
    async def sendingFormInput(self):
        if not self.submit_button.isEnabled():
            return
        self.lockedFormInput(True)
        username = self.username_input.text()
        password = self.password_input.text()
        email = self.email_input.text()
        if not self.confirm_registration:
            if not self.code_confirmation_state:
                if username and password and email:
                    clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{email}:{password}::Account Registration", CLIENT_TEMP_PRIVATE_KEY)
                    clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{email}:{password}::Account Registration", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                    sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                    await sendMessageToServer(f"{sharedSecret}:{cipherText}")
                else:
                    self.showInfoMessage("Input fields can not be empty!")
                    self.lockedFormInput(False)
            else:
                if self.confirm_code_input.text():
                    clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{email}:{password}:{self.confirm_code_input.text()}:Account Registration", CLIENT_TEMP_PRIVATE_KEY)
                    clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{email}:{password}:{self.confirm_code_input.text()}:Account Registration", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                    sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                    await sendMessageToServer(f"{sharedSecret}:{cipherText}")
                else:
                    self.showInfoMessage("Input fields can not be empty!")
                    self.lockedFormInput(False)
        else:
            with open(f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSApublicKey.pem", 'rb') as clientPU:
                clientPermPU = clientPU.read()
            clientPermPU = base64.b64encode(clientPermPU).decode('ascii')
            clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{email}:{password}:{clientPermPU}:Account Registration", CLIENT_TEMP_PRIVATE_KEY)
            clientMsg = json.dumps({"Message Code": "#0003", "Client Message": f"{username}:{email}:{password}:{clientPermPU}:Account Registration", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
            sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
            await sendMessageToServer(f"{sharedSecret}:{cipherText}")

    @Slot(str, bool)
    def showInfoMessage(self, message: str, is_error: bool = True):
        self.server_message_label.setText(message)
        if not is_error:
            self.server_message_label.setStyleSheet("color: #27ae60;")
        else:
            self.server_message_label.setStyleSheet("")
        self.server_message_label.show()
        if not self.code_confirmation_state:
            if not is_error:
                self.code_confirmation_state = True
                self.email_label.hide()
                self.email_input.hide()
                self.username_label.hide()
                self.username_input.hide()
                self.password_label.hide()
                self.password_input.hide()
                self.confirm_code_label.show()
                self.confirm_code_input.show()
        if "Please try again later." in message:
            self.code_confirmation_state = True
            self.email_label.show()
            self.email_input.show()
            self.username_label.show()
            self.username_input.show()
            self.password_label.show()
            self.password_input.show()
            self.confirm_code_label.hide()
            self.confirm_code_input.hide()
        if "The server sent you the assigned RSA keys!" in message:
            if not self.confirm_registration:
                self.confirm_registration = True
                self.email_label.hide()
                self.email_input.hide()
                self.username_label.hide()
                self.username_input.hide()
                self.password_label.hide()
                self.password_input.hide()
                self.confirm_code_label.hide()
                self.confirm_code_input.hide()
                self.submit_button.setText("I Acknowledge The Info")
                self.submit_button.setEnabled(True)


class ResetPasswordTab(QWidget):
    def __init__(self):
        super().__init__()
        self.code_confirmation_state = False
        # Apply initial theme on startup
        applyColoringTheme(self, QGuiApplication.styleHints().colorScheme())
        # Listen for OS theme changes
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda colorScheme, myself=self: applyColoringTheme(myself, colorScheme))
        signals.show_server_message_in_reset_form.connect(self.showInfoMessage)
        signals.disable_reset_form_input.connect(self.lockedFormInput)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(15)

        title_label = QLabel("Reset Password")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setObjectName("titleLabel")  # Set object name for specific CSS targeting

        self.account_id_label = QLabel("Account ID")
        self.account_id_input = QLineEdit()
        self.account_id_input.setMaxLength(40)
        self.account_id_input.setPlaceholderText("Enter a username or email address")

        self.new_password_label = QLabel("New Password")
        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText("Enter a new password")
        self.new_password_input.setMaxLength(40)
        # Mask the password input with dots
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_new_password_input = QLineEdit()
        self.confirm_new_password_input.setPlaceholderText("Confirm your new password")
        self.confirm_new_password_input.setMaxLength(40)
        # Mask the password input with dots
        self.confirm_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_code_label = QLabel("Reset Password Confirm Code")
        self.confirm_code_input = QLineEdit()
        self.confirm_code_input.setPlaceholderText("Enter a valid confirmation code")
        self.confirm_code_input.setMaxLength(40)
        self.confirm_code_label.hide()
        self.confirm_code_input.hide()

        self.submit_button = QPushButton("Submit")
        self.submit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_button.setAutoDefault(True)  # Click upon Enter key is pressed
        self.submit_button.clicked.connect(self.sendingFormInput)

        self.account_id_input.returnPressed.connect(self.submit_button.click)
        self.new_password_input.returnPressed.connect(self.submit_button.click)
        self.confirm_new_password_input.returnPressed.connect(self.submit_button.click)
        self.confirm_code_input.returnPressed.connect(self.submit_button.click)

        self.server_message_label = QLabel("")
        self.server_message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.server_message_label.setObjectName("serverMessageLabel")
        self.server_message_label.hide()  # Hidden by default

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        main_layout.addWidget(title_label)
        main_layout.addWidget(self.account_id_label)
        main_layout.addWidget(self.account_id_input)
        main_layout.addWidget(self.new_password_label)
        main_layout.addWidget(self.new_password_input)
        main_layout.addWidget(self.confirm_new_password_input)
        main_layout.addWidget(self.confirm_code_label)
        main_layout.addWidget(self.confirm_code_input)
        main_layout.addWidget(self.submit_button)
        main_layout.addWidget(self.server_message_label)

        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

    @Slot(bool)
    def lockedFormInput(self, locked):
        if not self.code_confirmation_state:
            self.account_id_input.setDisabled(locked)
            self.new_password_input.setDisabled(locked)
            self.confirm_new_password_input.setDisabled(locked)
        else:
            self.account_id_input.setDisabled(True)
            self.new_password_input.setDisabled(True)
            self.confirm_new_password_input.setDisabled(True)
            self.confirm_code_input.setDisabled(locked)
        self.submit_button.setDisabled(locked)

    @asyncSlot()
    async def sendingFormInput(self):
        if not self.submit_button.isEnabled():
            return
        self.lockedFormInput(True)
        username = self.account_id_input.text()
        password = self.new_password_input.text()
        confirm_password = self.confirm_new_password_input.text()
        if not self.code_confirmation_state:
            if username and password and confirm_password:
                clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{password}:::Reset Password", CLIENT_TEMP_PRIVATE_KEY)
                clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{password}:::Reset Password", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                await sendMessageToServer(f"{sharedSecret}:{cipherText}")
            else:
                self.showInfoMessage("Input fields can not be empty!")
                self.lockedFormInput(False)
        else:
            if self.confirm_code_input.text():
                clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{username}:{password}::{self.confirm_code_input.text()}:Reset Password", CLIENT_TEMP_PRIVATE_KEY)
                clientMsg = json.dumps({"Message Code": "#0002", "Client Message": f"{username}:{password}::{self.confirm_code_input.text()}:Reset Password", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
                sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
                await sendMessageToServer(f"{sharedSecret}:{cipherText}")
            else:
                self.showInfoMessage("Input fields can not be empty!")
                self.lockedFormInput(False)

    @Slot(str, bool)
    def showInfoMessage(self, message: str, is_error: bool = True):
        self.server_message_label.setText(message)
        if not is_error:
            self.server_message_label.setStyleSheet("color: #27ae60;")
        else:
            self.server_message_label.setStyleSheet("")
        self.server_message_label.show()
        if not self.code_confirmation_state:
            if not is_error:
                self.code_confirmation_state = True
                self.account_id_label.hide()
                self.account_id_input.hide()
                self.new_password_label.hide()
                self.new_password_input.hide()
                self.confirm_new_password_input.hide()
                self.confirm_code_label.show()
                self.confirm_code_input.show()
        if "You can not use any of your previous passwords!" in message or "new password can not be the same as your username" in message or "Please try again later." in message:
            self.code_confirmation_state = False
            self.account_id_label.show()
            self.account_id_input.show()
            self.new_password_label.show()
            self.new_password_input.show()
            self.confirm_new_password_input.show()
            self.confirm_code_label.hide()
            self.confirm_code_input.hide()


class AuthenticationForm(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)  # This guarantees the C++ object is destroyed when closed
        self.setWindowTitle("Welcome To David Secure Messaging App")
        self.setFixedSize(550, 600)
        # Apply initial theme on startup
        applyColoringTheme(self, QGuiApplication.styleHints().colorScheme())
        # Listen for OS theme changes
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda colorScheme, myself=self: applyColoringTheme(myself, colorScheme))
        self.tabs = QTabWidget()
        self.login_tab = LoginTab()
        self.register_tab = RegisterTab()
        self.reset_password_tab = ResetPasswordTab()
        self.tabs.addTab(self.login_tab, "Log In")
        self.tabs.addTab(self.register_tab, "Register An Account")
        self.tabs.addTab(self.reset_password_tab, "Reset Password")
        QVBoxLayout(self).addWidget(self.tabs)

        signals.authentication_success.connect(self.finishAuthentication)


    @Slot(bool)
    def finishAuthentication(self, success: bool):
        if not success:
            self.reject()
        else:
            self.accept()



class FriendListItemDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option, index):
        data = index.data(Qt.ItemDataRole.UserRole)
        if not data:
            return

        name = data.get("name", "Unknown")
        is_online = data.get("online", False)

        # 1. Detect the current OS Theme
        is_dark_mode = QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark

        # 2. Define colors based on the active theme
        if is_dark_mode:
            default_bg = QColor("#1e1e1e")
            default_text = QColor("#e0e0e0")
            selected_bg = QColor("#2c3e50")
            selected_text = QColor("#ffffff")
            border_color = QColor("#333333")
            offline_dot_bg = QColor("#1e1e1e")
            offline_dot_border = QColor("#555555")
        else:
            default_bg = QColor("#ffffff")
            default_text = QColor("#2c3e50")
            selected_bg = QColor("#eff6ff")
            selected_text = QColor("#1e3a8a")
            border_color = QColor("#f3f4f6")
            offline_dot_bg = QColor("#ffffff")
            offline_dot_border = QColor("#bdc3c7")

        # 3. Apply Selection State
        is_selected = option.state & QStyle.StateFlag.State_Selected
        bg_color = selected_bg if is_selected else default_bg
        text_color = selected_text if is_selected else default_text

        # --- PAINT BACKGROUND ---
        painter.save()
        painter.fillRect(option.rect, bg_color)

        # Add a subtle bottom border
        painter.setPen(border_color)
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())

        # --- PAINT ONLINE/OFFLINE DOT ---
        dot_radius = 5
        dot_x = option.rect.left() + 15
        dot_y = option.rect.center().y()

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)  # Smooth circle edges

        if is_online:
            painter.setBrush(QColor("#2ecc71"))  # Bright green (works in both themes)
            painter.setPen(Qt.PenStyle.NoPen)
        else:
            painter.setBrush(offline_dot_bg)
            painter.setPen(QPen(offline_dot_border, 2))  # Hollow circle matching theme

        painter.drawEllipse(dot_x - dot_radius, dot_y - dot_radius, dot_radius * 2, dot_radius * 2)

        # --- PAINT NAME ---
        painter.setPen(text_color)
        font = painter.font()
        font.setBold(True)
        font.setPointSize(11)
        painter.setFont(font)

        # Shift text to the right of the dot
        text_rect = option.rect.adjusted(35, 0, -10, 0)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, name)

        painter.restore()

    def sizeHint(self, option, index):
        return QSize(200, 50)  # Taller rows for a cleaner look


class MessagingApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("David Secure Messaging Desktop App")
        self.resize(1100, 750)
        self.emptyChat = False
        self.authenticate = False
        self.selfShutDown = False
        self._is_officially_closing = False
        self.currentOnlineUsers = {}
        self.currentFriends = {}
        self.currentPendingNotifications = {"friend_request": {}, "request_accepted": {}, "request_rejected": {}, "unread_messages": {}}
        # Apply initial theme on startup
        self.applyColoringTheme(QGuiApplication.styleHints().colorScheme())
        # Listen for OS theme changes
        QGuiApplication.styleHints().colorSchemeChanged.connect(self.applyColoringTheme)
        signals.server_connection_error.connect(self.showServerConnectionError)
        signals.bad_request.connect(self.showBadRequestError)
        signals.invalid_request.connect(self.showInvalidRequestError)
        signals.rate_limit.connect(self.showRateLimit)
        signals.server_pu_verification_failure.connect(self.showPUVerificationError)
        signals.sending_source_code_and_temp_pu.connect(self.sendingClientSourceCodeAndTempPU)
        signals.server_ds_verification_failure.connect(self.serverDSVerificationError)
        signals.server_client_ds_verification_failure.connect(self.serverClientDSVerificationError)
        signals.client_code_update.connect(self.clientCodeUpdate)
        signals.server_decryption_failure.connect(self.serverDecryptionFailure)
        signals.client_decryption_failure.connect(self.clientDecryptionFailure)
        self.authenticationForm = AuthenticationForm(self)
        signals.launch_authentication_window.connect(self.launchAuthenticationForm)
        signals.update_current_online_user_list.connect(self.addNewOnlineUserToList)
        signals.update_current_friend_list.connect(self.updateCurrentFriendList)
        signals.update_pending_notifications.connect(self.addNotification)
        signals.decrypt_chat_history.connect(self.decryptingChatHistory)
        signals.message_delivered_success.connect(self.unlockGUI)
        signals.remove_current_online_user.connect(self.removeOnlineUserFromList)

        header_font = QFont()
        header_font.setPointSize(12)
        header_font.setBold(True)

        large_header_font = QFont()
        large_header_font.setPointSize(16)
        large_header_font.setBold(True)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(self.splitter)

        # ==========================================
        # LEFT PANEL (Chat)
        # ==========================================
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(0, 0, 10, 0)

        self.chat_header = QLabel("No friend selected")
        self.chat_header.setFont(large_header_font)
        self.chat_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.chat_header.setObjectName("chatHeader")

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("Select a friend to chat...")

        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setMinimumHeight(40)

        self.send_btn = QPushButton("Send")
        self.send_btn.setMinimumHeight(40)
        self.send_btn.setMinimumWidth(80)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.message_input.returnPressed.connect(self.send_btn.click)
        self.send_btn.clicked.connect(self.sendMessageToFriend)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_btn)

        chat_layout.addWidget(self.chat_header)
        chat_layout.addWidget(self.chat_history)
        chat_layout.addLayout(input_layout)

        # ==========================================
        # RIGHT PANEL (Notifications, Friend, and Current User Online Lists)
        # ==========================================
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(10, 0, 0, 0)

        # --- Notifications ---
        notifications_label = QLabel("Notifications")
        notifications_label.setFont(header_font)
        self.notifications_list = QListWidget()
        self.notifications_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)

        # --- Friends List ---
        friends_label = QLabel("My Friends")
        friends_label.setFont(header_font)

        self.friends_list = QListWidget()
        self.friend_delegate = FriendListItemDelegate()
        self.friends_list.setItemDelegate(self.friend_delegate)
        self.friends_list.itemClicked.connect(self.initiateChatHistoryLoading)

        # --- Online Users ---
        all_users_label = QLabel("Online Users (Server)")
        all_users_label.setFont(header_font)
        self.all_users_list = QListWidget()
        self.all_users_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)

        right_layout.addWidget(notifications_label)
        right_layout.addWidget(self.notifications_list, stretch=1)
        right_layout.addSpacing(10)
        right_layout.addWidget(friends_label)
        right_layout.addWidget(self.friends_list, stretch=2)
        right_layout.addSpacing(10)
        right_layout.addWidget(all_users_label)
        right_layout.addWidget(self.all_users_list, stretch=2)

        self.splitter.addWidget(chat_container)
        self.splitter.addWidget(right_container)
        self.splitter.setSizes([650, 450])

        # Initially disable inputs until a friend is loaded
        self.message_input.setEnabled(False)
        self.send_btn.setEnabled(False)


    async def connect_to_server(self):
        global client_reader, client_writer
        try:
            client_reader, client_writer = await asyncio.open_connection(SERVER_IP, PORT)
            asyncio.create_task(receiveMessage())
            await sendMessageToServer('{"Message Code": "#0000"}')
        except ConnectionError:
            signals.server_connection_error.emit()
        except OSError:
            signals.server_connection_error.emit()

    def applyColoringTheme(self, scheme: Qt.ColorScheme):
        if scheme == Qt.ColorScheme.Dark:
            self.setStyleSheet("""
            QMainWindow, QMessageBox { background-color: #121212; color: #e0e0e0; }
            QLabel { color: #e0e0e0; }
            QTextEdit, QListWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333333;
                border-radius: 8px;
                padding: 5px;
            }
            QLineEdit {
                border: 1px solid #444444;
                border-radius: 20px;
                padding: 0px 15px;
                font-size: 14px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLineEdit:focus { border: 2px solid #3498db; }
            QPushButton {
                background-color: #2980b9;
                color: white;
                border: none;
                border-radius: 15px;
                font-weight: bold;
                padding: 5px 10px;
            }
            QPushButton:hover { background-color: #3498db; }
            QPushButton:pressed { background-color: #1f618d; }
            QPushButton:disabled { background-color: #555555; color: #888888; }  
            QPushButton[class="accept"] { background-color: #059669; }
            QPushButton[class="accept"]:hover { background-color: #10b981; }
            QPushButton[class="decline"] { background-color: #dc2626; }
            QPushButton[class="decline"]:hover { background-color: #ef4444; }   
            QPushButton[class="add"] { background-color: #4f46e5; border-radius: 12px; }
            QPushButton[class="add"]:hover { background-color: #6366f1; }
            QLabel[class="avatar"] {
                background-color: #3b82f6;
                color: white;
                border-radius: 15px; 
                font-weight: bold;
                font-size: 14px;
            }
            QListWidget::item:selected { background-color: #2c3e50; color: #ffffff; }
            """)
        else:
            self.setStyleSheet("""
                    QMainWindow { background-color: #f4f5f7; }
                    QTextEdit, QListWidget {
                        background-color: #ffffff;
                        border: 1px solid #d1d5db;
                        border-radius: 8px;
                        padding: 5px;
                    }
                    QLineEdit {
                        border: 1px solid #bdc3c7;
                        border-radius: 20px;
                        padding: 0 15px;
                        font-size: 14px;
                        background-color: #ffffff;
                    }
                    QLineEdit:focus { border: 2px solid #3498db; }
                    QPushButton {
                        background-color: #3498db;
                        color: white;
                        border: none;
                        border-radius: 15px;
                        font-weight: bold;
                        padding: 5px 10px;
                    }
                    QPushButton:hover { background-color: #2980b9; }
                    QPushButton:pressed { background-color: #1f618d; }
                    QPushButton:disabled { background-color: #9ca3af; color: #f3f4f6; }
                    QPushButton[class="accept"] { background-color: #10b981; }
                    QPushButton[class="accept"]:hover { background-color: #059669; }
                    QPushButton[class="decline"] { background-color: #ef4444; }
                    QPushButton[class="decline"]:hover { background-color: #dc2626; }
                    QPushButton[class="add"] { background-color: #6366f1; border-radius: 12px; }
                    QPushButton[class="add"]:hover { background-color: #4f46e5; }
                    QLabel[class="avatar"] {
                        background-color: #34495e;
                        color: white;
                        border-radius: 15px; 
                        font-weight: bold;
                        font-size: 14px;
                    }
            """)

    def show_critical_error_and_close(self, title: str, message: str, critical_error: bool=True):
        """Helper to show an error and close the app without freezing the async loop."""
        crit_box = QMessageBox(self)
        crit_box.setWindowTitle(title)
        crit_box.setText(message)
        if critical_error:
            crit_box.setIcon(QMessageBox.Icon.Critical)
            crit_box.finished.connect(self.close)
        else:
            crit_box.setIcon(QMessageBox.Icon.Information)
        crit_box.open()

    @Slot()
    def showServerConnectionError(self):
        if not self.selfShutDown:
            self.show_critical_error_and_close("Connection Error", "Can't Connect To Server!")

    @Slot()
    def showBadRequestError(self):
        self.show_critical_error_and_close("Bad Request Error", "The server returned a Bad Request (Status Code 400).")

    @Slot()
    def showInvalidRequestError(self):
        self.show_critical_error_and_close("Invalid Request Error", "Your request is not Not Accepted (Status Code 401).")

    @Slot()
    def showRateLimit(self):
        self.show_critical_error_and_close("Rate Limit", "Chill out! You are sending too many requests in a short amount of time.\nPlease wait 60 seconds to receive the response and continue the session! (Status Code 429).", False)

    @Slot()
    def showPUVerificationError(self):
        self.show_critical_error_and_close("Server Public Key Verification Error", "Server Public Key Verification Failure!")

    @asyncSlot()
    async def sendingClientSourceCodeAndTempPU(self):
        with open(CLIENT_SOURCE_CODE, 'rb') as file:
            base64ClientSourceCode = base64.b64encode(file.read()).decode('ascii')
        with open(CLIENT_TEMP_PUBLIC_KEY, 'rb') as clientPU:
            clientTempPU = clientPU.read()
        clientTempPU = base64.b64encode(clientTempPU).decode('ascii')
        clientSignature = await asyncio.to_thread(clientDigitalSignature, f"{base64ClientSourceCode}:{clientTempPU}", CLIENT_TEMP_PRIVATE_KEY)
        clientMsg = json.dumps({"Message Code": "#0001", "Client Message": f"{base64ClientSourceCode}:{clientTempPU}", "Counter": nextCounter(), "Client Digital Signature": f"{clientSignature}"})
        sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
        await sendMessageToServer(f"{sharedSecret}:{cipherText}")

    @Slot()
    def serverDSVerificationError(self):
        self.show_critical_error_and_close("Server Digital Signature Verification Error", "A Potential Man-In-The-Middle attack due to server digital signature verification failure.")

    @Slot()
    def serverClientDSVerificationError(self):
        self.show_critical_error_and_close("Client Digital Signature Verification Error", "A Potential Man-In-The-Middle attack due to server fail to verify client digital signature.")

    @Slot(bytes, str)
    def clientCodeUpdate(self, sourceCode: bytes, checksum: str):
        update_box = QMessageBox(self)
        update_box.setWindowTitle("Outdated Client Version")
        update_box.setText("Your current client source code does not match the server version. In order to continue, do you want to download the correct version?")
        update_box.setIcon(QMessageBox.Icon.Information)
        update_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        update_box.setDefaultButton(QMessageBox.StandardButton.No)
        update_box.finished.connect(lambda result, sc=sourceCode, cs=checksum: self.handleClientCodeUpdateDecision(result, sc, cs))
        update_box.open()

    def handleClientCodeUpdateDecision(self, result, sourceCode, checksum):
        result_box = QMessageBox(self)
        if result == QMessageBox.StandardButton.Yes:
            if hashlib.sha512(sourceCode).hexdigest() == checksum:
                result_box.setIcon(QMessageBox.Icon.Information)
                with open("UpToDateClientSourceCodeDownload.py", "wb") as file:
                    file.write(sourceCode)
                result_box.setWindowTitle("Download Update Success")
                result_box.setText("Download Success, please replace your source code with the downloaded version!")
            else:
                result_box.setIcon(QMessageBox.Icon.Critical)
                result_box.setWindowTitle("Download Verification Failure")
                result_box.setText("The downloaded update source code did not match the server checksum! Potential Man-In-The-Middle attack!")
        else:
            result_box.setIcon(QMessageBox.Icon.Critical)
            result_box.setWindowTitle("Update Requirement")
            result_box.setText("You must use the correct client version to continue the connection with the server!")
        result_box.finished.connect(self.close)
        result_box.open()

    @Slot()
    def serverDecryptionFailure(self):
        self.show_critical_error_and_close("Server Decryption Error", "Server Internal Server Error: Server Can Not Decrypt Requested Data!")

    @Slot()
    def clientDecryptionFailure(self):
        self.show_critical_error_and_close("Client Decryption Error", "Client Internal Error: Can Not Decrypt Received Data From The Server!")

    @Slot()
    def launchAuthenticationForm(self):
        """Non-blocking dialog launch"""
        # Connect signals to handle the result asynchronously
        self.authenticationForm.accepted.connect(self.onAuthenticationAccepted)
        self.authenticationForm.rejected.connect(self.onAuthenticationRejected)
        self.authenticationForm.open()

    @asyncSlot()
    async def onAuthenticationAccepted(self):
        """Triggered when the dialog calls self.accept() upon successful login"""
        self.authenticate = True
        clientSignature = await asyncio.to_thread(clientDigitalSignature,"Tung Tung Tung Sahur Request COU, FL, and PN", CLIENT_TEMP_PRIVATE_KEY)
        clientMsg = json.dumps({"Message Code": "#0004", "Client Message": "Tung Tung Tung Sahur Request COU, FL, and PN", "Counter": nextCounter(), "Client Digital Signature": clientSignature})
        sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
        await sendMessageToServer(f"{sharedSecret}:{cipherText}")

    @Slot()
    def onAuthenticationRejected(self):
        self.close()

    @asyncSlot()
    async def initiateChatHistoryLoading(self, item: QListWidgetItem) -> None:
        """
        Description: Asking the server to send the encrypted chat history with the selected friend
        :param item: The selected friend username data
        :return:
        """
        friendUsername = item.data(Qt.ItemDataRole.UserRole).get("name", "")
        if friendUsername in self.currentPendingNotifications["unread_messages"].keys():
            await self.removeNotification("unread_messages", friendUsername, True)
        if self.chat_header.text().replace("Chatting with ", "") == friendUsername:
            return
        self.chat_header.setText(f"Chatting with {friendUsername}")
        self.chat_history.setHtml(f"<div style='text-align: center; color: #7f8c8d; '><br><br><br><b>Loading encrypted history with {friendUsername}...</b></div>")

        # Lock UI
        self.unlockGUI(False)

        clientSignature = await asyncio.to_thread(clientDigitalSignature, friendUsername, CLIENT_TEMP_PRIVATE_KEY)
        clientMsg = json.dumps({"Message Code": "#0005", "Client Message": friendUsername, "Counter": nextCounter(), "Client Digital Signature": clientSignature})
        sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
        await sendMessageToServer(f"{sharedSecret}:{cipherText}")

    @asyncSlot()
    async def decryptingChatHistory(self, newChat: bool, messageHistory: list) -> None:
        """
        Description: Decrypting the chat history with a friend from server
        :param newChat: New Chat Session?
        :param messageHistory: A dictionary of all the chat history data
        :return: None
        """
        if newChat:
            self.chat_history.clear()
        if messageHistory:
            self.emptyChat = False
            chatHistory = []
            recipient = self.chat_header.text().replace("Chatting with ", "")
            for message in messageHistory:
                date = message.get("Date", "")
                if message.get("To", "") == recipient:
                    verifyKey = f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSApublicKey.pem"
                    myMessage = True
                    decryptionStatus, aesKey = await asyncio.to_thread(RSAdecrypt, message.get("Key For Self", ""), f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSAprivateKey.pem")
                    if not decryptionStatus:
                        self.clientDecryptionFailure()
                        return
                else:
                    verifyKey = f"{CURRENT_FRIEND_PUBLIC_KEY}PublicKey.pem"
                    myMessage = False
                    decryptionStatus, aesKey = await asyncio.to_thread(RSAdecrypt, message.get("Key For Recipient", ""), f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSAprivateKey.pem")
                    if not decryptionStatus:
                        self.clientDecryptionFailure()
                        return
                decryptionStatus, decryptedMessage = await asyncio.to_thread(aesDecryption, aesKey, message.get("Message", ""))
                if not decryptionStatus:
                    self.clientDecryptionFailure()
                    return
                decryptedMessage = json.loads(decryptedMessage)
                is_verified = await asyncio.to_thread(DigitalSignatureVerification,decryptedMessage.get("Sender Signature", ""), decryptedMessage.get("Message", ""), verifyKey)
                if is_verified:
                    if myMessage:
                        chatHistory.append(f"""
                        <table width="100%" border="0" cellspacing="0" cellpadding="0">
                            <tr>
                                <td width="25%"></td>
                                <td width="75%" align="right">
                                    <span style="color: #95a5a6; font-size: 11px;">{date}</span><br>
                                    <span style="color: #2980b9; font-weight: bold; font-size: 13px;">You</span><br>
                                    <table border="0" cellspacing="0" cellpadding="8" bgcolor="#e1f5fe" align="right">
                                        <tr><td style="color: #0277bd;" align="left">{decryptedMessage.get("Message", "")}</td></tr>
                                    </table>
                                </td>
                            </tr>
                        </table><br>
                        """)
                    else:
                        chatHistory.append(f"""
                        <table width="100%" border="0" cellspacing="0" cellpadding="0">
                            <tr>
                                <td width="75%" align="left">
                                    <span style="color: #95a5a6; font-size: 11px;">{date}</span><br>
                                    <span style="color: #2c3e50; font-weight: bold; font-size: 13px;">{recipient}</span><br>
                                    <table border="0" cellspacing="0" cellpadding="8" bgcolor="#f1f5f9">
                                        <tr><td style="color: #334155;">{decryptedMessage.get("Message", "")}</td></tr>
                                    </table>
                                </td>
                                <td width="25%"></td>
                            </tr>
                        </table><br>
                        """)
                else:
                    self.serverDSVerificationError()
                    return
            for chat in chatHistory:
                self.chat_history.append(chat)
        else:
            self.chat_history.setHtml(f"<div style='text-align: center; color: #7f8c8d; '><br><br><br><b>The chat history is empty. You can be the first one to send a message :)</b></div>")
            self.emptyChat = True
        # Unlock UI
        self.unlockGUI(True)

    @asyncSlot()
    async def addNotification(self, notifType: Literal["friend_request", "request_accepted", "request_rejected", "unread_messages"], username: str, unreadMessagesCount: int = 0) -> None:
        """
        Description: Adding a new pending notification
        :param notifType: Type of notification
        :param username: From who?
        :param unreadMessagesCount: Only applied to unread_messages notifications
        :return:
        """
        if self.currentPendingNotifications[notifType].get(username, ""):
            await self.removeNotification(notifType, username, False)
        notificationItem = QListWidgetItem()
        notificationItem.setSizeHint(QSize(0, 65))
        self.notifications_list.insertItem(0, notificationItem)

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(10, 5, 10, 5)

        avatar_label = QLabel(username[0].upper())
        avatar_label.setFixedSize(30, 30)
        avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar_label.setProperty("class", "avatar")

        text_label = QLabel()
        text_label.setWordWrap(True)
        font = QFont()
        font.setPointSize(10)
        text_label.setFont(font)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(5)

        if notifType == "friend_request":
            text_label.setText(f"<b>{username}</b> sent you a friend request.")

            accept_btn = QPushButton("Accept")
            accept_btn.setProperty("class", "accept")
            accept_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            accept_btn.clicked.connect(lambda checked=False, u=username: asyncio.create_task(self.handleFriendRequest(u, True)))

            decline_btn = QPushButton("Decline")
            decline_btn.setProperty("class", "decline")
            decline_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            decline_btn.clicked.connect(lambda checked=False, u=username: asyncio.create_task(self.handleFriendRequest(u, False)))

            btn_layout.addWidget(accept_btn)
            btn_layout.addWidget(decline_btn)

        elif notifType in ["request_accepted", "request_rejected"]:
            text_label.setText(f"<b>{username}</b> {notifType.replace('request_', '')} your friend request!")
            dismiss_btn = QPushButton("Dismiss")
            dismiss_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            dismiss_btn.clicked.connect(lambda checked=False, nt=notifType, u=username: asyncio.create_task(self.removeNotification(nt, u, True)))

            btn_layout.addWidget(dismiss_btn)

        elif notifType == "unread_messages":
            text_label.setText(f"You have <b>{unreadMessagesCount} unread messages</b> from <b>{username}</b>.")

            view_btn = QPushButton("View")
            view_btn.setProperty("class", "add")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.clicked.connect(lambda checked=False, u=username: asyncio.create_task(self.viewUnreadMessages(u)))

            btn_layout.addWidget(view_btn)

        row_layout.addWidget(avatar_label)
        row_layout.addWidget(text_label, stretch=1)
        row_layout.addLayout(btn_layout)
        self.notifications_list.setItemWidget(notificationItem, row_widget)
        self.currentPendingNotifications[notifType][username] = notificationItem

    async def removeNotification(self, notifType: Literal["friend_request", "request_accepted", "request_rejected", "unread_messages"], username: str, sendToServer: bool, friendRequestDecision: str='' ) -> None:
        """
        Description: Remove a read notification from the notifications list.
        :param notifType: Type of notification
        :param username: From who?
        :param sendToServer: Send Notification ACK To server?
        :param friendRequestDecision: Friend Request Decision (Only Apply for friend_request Notification)
        :return:
        """
        row = self.notifications_list.row(self.currentPendingNotifications[notifType][username])
        self.notifications_list.takeItem(row)
        if sendToServer:
            if notifType == "friend_request":
                notificationMessage = json.dumps({"Notification Type": friendRequestDecision, "From": username})
            else:
                notificationMessage = json.dumps({"Notification Type": notifType, "From": username})
            clientSignature = await asyncio.to_thread(clientDigitalSignature, notificationMessage, CLIENT_TEMP_PRIVATE_KEY)
            clientMsg = json.dumps({"Message Code": "#0010", "Client Message": notificationMessage, "Counter": nextCounter(), "Client Digital Signature": clientSignature})
            sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, clientMsg)
            await sendMessageToServer(f"{sharedSecret}:{cipherText}")

    async def handleFriendRequest(self, username: str, accepted: bool) -> None:
        """
        Description: Send the server the user friend request decision
        :param notification: The friend request notification
        :param username: The username of the original friend request sender
        :param accepted: The decision of the friend request
        :return:
        """
        if accepted:
            decision = "request_accepted"
            if self.currentOnlineUsers.get(username, None) is not None:
                self.addNewOnlineUserToList(username, "Friend")
                self.updateCurrentFriendList({"name": username, "online": True})
            else:
                self.updateCurrentFriendList({"name": username, "online": False})
        else:
            decision = "request_rejected"
            if self.currentOnlineUsers.get(username, None) is not None:
                self.addNewOnlineUserToList(username, "None")
        await self.removeNotification("friend_request", username, True, decision)

    async def viewUnreadMessages(self, username: str) -> None:
        """
        Description: Finds the friend in the list, highlights them, and initiates the loading sequence.
        :param notification: The unread message notification
        :param username: The friend username of the original unread message notification
        :return:
        """
        await self.removeNotification("unread_messages", username, True)
        if self.chat_header.text().replace("Chatting with ", "") != username:
            for i in range(self.friends_list.count()):
                friend_item = self.friends_list.item(i)
                friend_data = friend_item.data(Qt.ItemDataRole.UserRole)

                if friend_data and friend_data.get("name") == username:
                    self.friends_list.setCurrentItem(friend_item)
                    await self.initiateChatHistoryLoading(friend_item)
                    return

    @Slot(str, str)
    def addNewOnlineUserToList(self, username: str, relationship: Literal["Friend", "Pending Friend Invitation", "None", "Self"]) -> None:
        """
        Description: Add new online user to the user online list
        :param username: The username of the online user
        :param relationship: Is the user friend, pending friend invite, or stranger?
        :return:
        """
        if self.currentOnlineUsers.get(username, None) is not None:
            self.all_users_list.takeItem(self.all_users_list.row(self.currentOnlineUsers[username]))
        newUser = QListWidgetItem()
        newUser.setSizeHint(QSize(0, 55))
        self.all_users_list.insertItem(0, newUser)

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(10, 5, 10, 5)

        avatar_label = QLabel(username[0].upper())
        avatar_label.setFixedSize(30, 30)
        avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar_label.setProperty("class", "avatar")
        row_layout.addWidget(avatar_label)

        name_layout = QVBoxLayout()
        name_label = QLabel(username)
        font = QFont()
        font.setPointSize(11)
        font.setBold(True)
        name_label.setFont(font)
        name_layout.addWidget(name_label)

        if relationship == 'Self':
            status_label = QLabel("Myself")
        elif relationship != 'None':
            status_label = QLabel(relationship)
        else:
            status_label = QLabel('')
        status_label.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        name_layout.addWidget(status_label)
        row_layout.addLayout(name_layout)
        row_layout.addStretch()

        if relationship not in ["Friend", "Pending Friend Invitation", "Self"]:
            add_btn = QPushButton("Add")
            add_btn.setFixedSize(60, 28)
            add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            add_btn.setProperty("class", "add")
            add_btn.clicked.connect(lambda checked=False, u=username, b=add_btn, l=status_label: asyncio.create_task(self.sendFriendRequest(u, b, l)))
            row_layout.addWidget(add_btn)
        self.all_users_list.setItemWidget(newUser, row_widget)
        self.currentOnlineUsers[username] = newUser

    @Slot(str)
    def removeOnlineUserFromList(self, username: str):
        """
        Description: Remove current online user from the user online list
        :param username: The username of the online user
        :return:
        """
        if username in self.currentFriends.keys():
            self.updateCurrentFriendList({"name": username, "online": False})
        self.all_users_list.takeItem(self.all_users_list.row(self.currentOnlineUsers[username]))
        self.currentOnlineUsers.pop(username, None)

    @Slot(dict)
    def updateCurrentFriendList(self, friendData: dict) -> None:
        """
        Description: Updates the friend list
        :param friendData: The dictionary data contains {'name': friendUsername, 'online': True/False}
        :return:
        """
        friendItem = QListWidgetItem()
        friendItem.setData(Qt.ItemDataRole.UserRole, friendData)
        if friendData['name'] in self.currentFriends.keys():
            self.friends_list.takeItem(self.friends_list.row(self.currentFriends[friendData["name"]]))
        if friendData["online"]:
            self.friends_list.insertItem(0, friendItem)
        else:
            self.friends_list.addItem(friendItem)
        self.currentFriends[friendData["name"]] = friendItem

    async def sendFriendRequest(self, username: str, button: QPushButton, label: QLabel) -> None:
        """
        Description: Send friend request to another user
        :param username: The username of the recipient
        :param button: The Add button to be removed
        :param label: The relationship to user label to be updated
        :return:
        """
        label.setText("Pending Friend Invitation")
        button.deleteLater()
        clientSignature = await asyncio.to_thread(clientDigitalSignature, username, CLIENT_TEMP_PRIVATE_KEY)
        clientMsg = json.dumps({"Message Code": "#0011", "Client Message": username, "Counter": nextCounter(), "Client Digital Signature": clientSignature})
        sharedSecret, encryptedMessage = await asyncio.to_thread(serverHybridEncryption, clientMsg)
        await sendMessageToServer(f"{sharedSecret}:{encryptedMessage}")

    @asyncSlot()
    async def sendMessageToFriend(self):
        """Securely encrypt and send text message to friend"""
        message = self.message_input.text()
        if not message:
            return
        if self.emptyChat:
            self.chat_history.clear()
            self.emptyChat = False
        recipient = self.chat_header.text().replace("Chatting with ", "")
        date = time.ctime(time.time())
        self.chat_history.append(
            f"""
                <table width="100%" border="0" cellspacing="0" cellpadding="0">
                    <tr>
                        <td width="25%"></td>
                        <td width="75%" align="right">
                            <span style="color: #95a5a6; font-size: 11px;">{date}</span><br>
                            <span style="color: #2980b9; font-weight: bold; font-size: 13px;">You</span><br>
                            <table border="0" cellspacing="0" cellpadding="8" bgcolor="#e1f5fe" align="right">
                                <tr><td style="color: #0277bd;" align="left">{message}</td></tr>
                            </table>
                        </td>
                    </tr>
                </table><br>
            """)
        senderSignature = await asyncio.to_thread(clientDigitalSignature, message,f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSAprivateKey.pem")
        sendMessage = json.dumps({"Message": message, "Sender Signature": senderSignature})
        aesKey, EncryptedMessage = await asyncio.to_thread(aesEncryption, sendMessage)
        keyForSelf = await asyncio.to_thread(RSAencrypt, aesKey, f"{CLIENT_PERMANENT_KEY_FOLDER}/ClientRSApublicKey.pem")
        keyForRecipient = await asyncio.to_thread(RSAencrypt, aesKey,f"{CURRENT_FRIEND_PUBLIC_KEY}PublicKey.pem")
        finalMessage = json.dumps({"To": recipient, "Date": date, "Message": EncryptedMessage, "Key For Self": keyForSelf, "Key For Recipient": keyForRecipient})
        clientSignature = await asyncio.to_thread(clientDigitalSignature, finalMessage, CLIENT_TEMP_PRIVATE_KEY)
        finalMessageToServer = json.dumps({"Message Code": "#0006", "Client Message": finalMessage, "Counter": nextCounter(), "Client Digital Signature": clientSignature})
        sharedSecret, cipherText = await asyncio.to_thread(serverHybridEncryption, finalMessageToServer)
        await sendMessageToServer(f"{sharedSecret}:{cipherText}")
        # Lock UI until receive a confirmation from the server that the message was delivered to the recipient successfully!
        self.unlockGUI(False)
        self.message_input.clear()

    @Slot(bool)
    def unlockGUI(self, unlock: bool) -> None:
        self.notifications_list.setEnabled(unlock)
        self.friends_list.setEnabled(unlock)
        self.all_users_list.setEnabled(unlock)
        self.message_input.setEnabled(unlock)
        self.send_btn.setEnabled(unlock)
        if unlock:
            self.message_input.setFocus()

    def closeEvent(self, event: QCloseEvent):
        """
        Description: Clean up network resources when the GUI is closed.
        """
        if getattr(self, '_is_officially_closing', False):
            event.accept()
            return

        self.selfShutDown = True

        if os.path.exists(f"{CURRENT_FRIEND_PUBLIC_KEY}PublicKey.pem"):
            os.remove(f"{CURRENT_FRIEND_PUBLIC_KEY}PublicKey.pem")
        if os.path.exists(SERVER_PUBLIC_KEY):
            os.remove(SERVER_PUBLIC_KEY)
        if os.path.exists(CLIENT_TEMP_PRIVATE_KEY):
            os.remove(CLIENT_TEMP_PRIVATE_KEY)
        if os.path.exists(CLIENT_TEMP_PUBLIC_KEY):
            os.remove(CLIENT_TEMP_PUBLIC_KEY)
        print("Ephemeral RSA keys have been removed!")

        try:
            if client_writer:
                client_writer.close()
        except Exception:
            pass

        if self.authenticate:
            event.ignore()
            self._is_officially_closing = True
            quit_box = QMessageBox(self)
            quit_box.setWindowTitle("Quit Application")
            quit_box.setText("You have been logged out of your account and disconnect with the server!")
            quit_box.setIcon(QMessageBox.Icon.Information)
            quit_box.finished.connect(self.close)
            quit_box.open()
        else:
            event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    window = MessagingApp()
    window.show()
    loop.create_task(window.connect_to_server())
    with loop:
        loop.run_forever()
