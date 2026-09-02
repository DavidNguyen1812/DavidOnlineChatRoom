# Secure Messaging Application: Architecture & Protocol Specification

A fully asynchronous, end-to-end encrypted (E2EE) desktop chat application built with Python, PySide6, `qasync`, and `pycryptodome`. Designed with a zero-trust architecture, the application utilizes hybrid encryption (AES-256-OCB and RSA-4096), strict digital signature verification (PSS/SHA-256), and ephemeral session keys to guarantee transport-layer forward secrecy and persistent peer-to-peer privacy.

---

## Part 1: Directory & Storage Architecture

### 1. Client-Side Cryptographic Key Storage

| Folder | Key Type | Persistence | Primary Purpose |
| --- | --- | --- | --- |
| **`CurrentFriendPU/`** | Public Key | Ephemeral | E2EE payload encryption and sender signature verification for the active peer. |
| **`ClientTempKey/`** | Key Pair | Ephemeral | Transport-layer hybrid encryption and packet signing with the server. |
| **`ClientPermanentKey/`** | Key Pair | Persistent | Account identity, server registration, and long-term E2EE identity. Losing this causes permanent data loss. |
| **`ServerPU/`** | Public Key | Ephemeral | Server payload encryption and inbound server digital signature verification (SHA-512 runtime verified). |

### 2. Server-Side Asset Directory

| File | Type | Primary Purpose |
| --- | --- | --- |
| **`client.py`** | Source Code | Canonical client distribution. The server hashes this asset to verify connecting clients. |
| **`generateServerRSAkeys.py`** | Utility | Administrative script to provision fresh RSA-4096 key pairs for the server. |

### 3. Server-Side Database Schema (JSON)

| Database File | Primary Purpose | Security Context |
| --- | --- | --- |
| **`accountData.json`** | Identity & Auth | Stores username-salted password hashes, lockout counts, and friend lists. |
| **`chatHistory.json`** | E2EE Messages | Stores AES-256-OCB payloads wrapped in recipient and sender RSA public keys. |
| **`pendingNotifications.json`** | Event Queuing | Caches unread message counts, inbound friend requests, and auth responses. |

### 4. Server-Side Cryptographic Key Storage

| Folder | Key Type | Persistence | Primary Purpose |
| --- | --- | --- | --- |
| **`ClientRegisteredPublicKeys/`** | Public Key | Persistent | Account authentication and E2EE peer-to-key distribution. |
| **`ClientTempPublicKeys/`** | Public Key | Ephemeral | Transport-layer hybrid encryption (AES/RSA) tunneling for active sockets. |
| **`ServerPermanentKeys/`** | Key Pair | Persistent | Server root of trust. If regenerated, the client source hash must be updated. |

---

## Part 2: Communication Protocol & Flow

**Global Transport Standard:** After the initial `#0000` handshake, all messages traverse the network as a hybrid-encrypted string strictly formatted as: `SharedSecret:EncryptedPayload`.

* **SharedSecret:** The AES-256 OCB session key, tag, and nonce encrypted with the recipient's RSA Public Key.
* **EncryptedPayload:** The JSON message encrypted with the AES-256 OCB session key.
* **Global Error Handling:** If the server fails to parse the string, it returns `400 Bad Request`. If the server fails RSA decryption, it returns `500 Server Decryption Error`. If Digital Signatures fail verification, it returns `501 Signature Verification Failure`. The client disconnects immediately on any of these errors.

### Phase 1: Socket Connection & Integrity Verification

**1. Initial Handshake**

* **Client -> Server:** Requests Server Public Key. Message: `{"Message Code": "#0000"}`
* **Server -> Client:** Responds with server public key. Message: `{"Message Code": "#0000", "Status Code": 200, "Server Public Key": "<ServerPU>"}`
* **Client Verification:** Client calculates the SHA-512 hash of the received Server PU. If it does not match the hardcoded checksum, aborts connection to prevent MITM.

**2. Client Source Code Verification (`#0001`)**

* **Client -> Server:** Signs `HashedClientCode:ClientTempPU`.
* Payload: `{"Message Code": "#0001", "Client Message": "<Hash>:<TempPU>", "Client Digital Signature": "<Signature>"}`


* **Server Processing:**
* Extracts and caches the Client Temp PU for the session.
* Verifies signature using the new Temp PU.
* Checks if the client source hash matches the server's authoritative `client.py` hash.


* **Server -> Client (Success):**
* Payload: `{"Message Code": "#0001", "Status Code": 200, "Server Message": "Client Source Code Verification Success"}`


* **Server -> Client (Update Required):**
* Payload: `{"Message Code": "#0001", "Status Code": 202, "Server Message": "<clientSourceBytes>:<hash>"}`


* **Client Processing:** If 200, launch Auth GUI. If 202, prompt user to download the update, verify checksum, save to disk, and exit.

### Phase 2: Authentication & Registration

**1. Login Request (`#0002`)**

* **Client -> Server:** Hashes password (SHA-512) and signs `userName:hashedPassword`.
* Payload: `{"Message Code": "#0002", "Client Message": "<userName>:<hash>", "Client Digital Signature": "<Sig>"}`


* **Server Processing:** Checks user database, validates password hash, and checks brute-force lockout status.
* **Server -> Client:**
* `Status 200`: "Authentication Success!"
* `Status 401`: "Invalid Credential..." or "There is no registered account..." or "Too Many Invalid Log In Attempt..."
* `Status 403`: "Your account is currently locked..."



**2. Permanent Key Exchange / Registration (`#0003`)**

* **Client -> Server (If 200 Login):** Signs hash of permanent PU using Temp PI.
* Payload: `{"Message Code": "#0003", "Client Message": "<PermanentPUHash>", "Client Digital Signature": "<Sig>"}`


* **Client -> Server (If 401 Unregistered & User Clicks Yes):** Signs `userName:hashedPassword:PermanentPU`.
* **Server Processing:**
* If registering (len == 3): Stores credentials and permanent PU. Returns `Status 200 "New Account Registration Successful!"`.
* If logging in (len == 1): Compares hash to stored permanent PU. Returns `Status 200 "Logging Successful!"` or `Status 403 "Verification Error!"`.


* **Client Processing:** Closes auth form, launches main messaging window.

### Phase 3: Session Initialization

**1. Requesting State Data (`#0004`)**

* **Client -> Server:** Requests presence and notifications.
* Payload: `{"Message Code": "#0004", "Client Message": "Tung Tung Tung Sahur Request COU, FL, and PN"}`


* **Server -> Client:** Aggregates Online Users, Friend List, and Pending Notifications.
* Payload: `{"Message Code": "#0004", "Status Code": 200, "Server Message": {"Current Online Users": {...}, "Current Friend List": [...], "Current Pending Notifications": {...}}}`


* **Client Processing:** Populates GUI lists.

### Phase 4: Encrypted Chat Routing

**1. Selecting a Friend (`#0005`)**

* **Client -> Server:** Requests friend data. Payload: `{"Message Code": "#0005", "Client Message": "<friendUsername>"}`
* **Server -> Client:** Retrieves friend's registered PU and the encrypted chat history list.
* Payload: `{"Message Code": "#0005", "Status Code": 200, "Server Message": {"Friend Registered PU": "...", "Encrypted Chat History": [...]}}`


* **Client Processing:** Temporarily stores Friend PU. Decrypts history using Client Permanent Private Key.

**2. Sending a Message (`#0006`)**

* **Client -> Server:**
* Signs raw message with Permanent PI.
* Encrypts `{"Message": msg, "Sender Signature": sig}` with a random AES-256 key.
* Wraps AES key for self (Client Permanent PU) and recipient (Friend Permanent PU).
* Payload: `{"Message Code": "#0006", "Client Message": {"To": "...", "Date": "...", "Message": "<AES_Cipher>", "Key For Self": "...", "Key For Recipient": "..."}}`


* **Server Processing:** Stores the exact payload in `chatHistory.json`.
* If recipient is online: Forwards the E2EE payload directly to them.
* If offline: Increments recipient's unread message count.
* Returns `Status 200 "Message Deliver Success!"` to the sender.



### Phase 5: Real-Time Presence & Notifications

**1. Live Presence Updates (`#0007` & `#0008`)**

* **Server -> Connected Clients (`#0007`):** Broadcasts new connections.
* Payload: `{"Message Code": "#0007", "Server Message": {"New Client Connected": "...", "Relationship": "..."}}`


* **Server -> Connected Clients (`#0008`):** Broadcasts disconnections.
* Payload: `{"Message Code": "#0008", "Server Message": "<clientUserName>"}`



**2. Sending Live Notifications (`#0009`)**

* **Server -> Client:** Pushes active events (messages, requests).
* Payload: `{"Message Code": "#0009", "Server Message": {"Notification Type": "<type>", "From": "<user>"}}`


* **Client Processing:** Updates notification GUI immediately.

**3. Notification ACK / Friend Request Decision (`#0010`)**

* **Client -> Server:** Acknowledges reading a message or answers a friend request.
* Payload: `{"Message Code": "#0010", "Client Message": {"Notification Type": "<type>", "From": "<user>"}}`


* **Server Processing:** Updates `pendingNotifications.json`.

**4. Make Friend Request (`#0011`)**

* **Client -> Server:** Payload: `{"Message Code": "#0011", "Client Message": "<username>"}`
* **Server Processing:** Updates pending requests. If target is online, dispatches a `#0009` live notification to them.