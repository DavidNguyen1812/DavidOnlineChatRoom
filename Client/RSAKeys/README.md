# Client-Side Cryptographic Key Storage

This directory manages the RSA key pairs and public certificates required for identity verification, session security, and end-to-end encryption (E2EE).

---

| Folder                 | Key Type | Persistence | Primary Purpose |
|------------------------| --- | --- | --- |
| **`CurrentFriendPU/`** | Public Key (RSA-4096) | Ephemeral (Session-cached) | E2EE payload encryption and sender signature verification for the active peer. |
| **`Ephemeral/`**       | Key Pair (RSA-4096) | Ephemeral (Per-connection) | Transport-layer hybrid encryption (AES-256-OCB/RSA) and packet signing with the server. |
| **`Permanent/`**       | Key Pair (RSA-4096) | Persistent | Account identity, server registration authentication, and long-term E2EE identity. |
| **`ServerPU/`**        | Public Key (RSA-4096) | Ephemeral (Runtime-verified) | Server payload encryption and inbound server digital signature verification. |

---

**Directory Specifications**

* **`CurrentFriendPU/` (Active Peer Public Key)**
* Dynamically caches the registered RSA public key of the user currently selected in the chat window.
* Used to encrypt outbound AES session keys for the recipient and verify inbound message signatures.
* Overwritten automatically upon switching conversation threads and wiped on application exit.


* **`Ephemeral/` (Session Ephemeral Keys)**
* Generates a unique RSA key pair on each application launch to secure communication across the client-server transport boundary.
* The public key is signed by the ephemeral private key and exchanged during the initial handshake.
* The key pair is deleted and regenerated upon reconnection, enforcing forward secrecy across connection lifecycles.


* **`Permanent/` (Persistent Identity Keys)**
* Stores the long-term RSA key pair assigned by the server after a successful new account registration, used for account log in authentication and peer-to-peer signature authorization.
* **Critical:** The private key in this folder is tied directly to the user's encrypted chat database. Losing this key results in unrecoverable data loss and permanent loss of account access.
* **Server Security Policy:** During the key pair assignment after a succesful new account registration, the server will never store the private key and clear it from the memory after sending the keys securely to the client. It will up to the user to manage the key from there own!


* **`ServerPU/` (Server Public Key Verification)**
* Holds the server's public certificate retrieved during handshake initialization.
* The client validates the received key bytes against a hardcoded SHA-512 fingerprint prior to session establishment.
* Prevents Man-in-the-Middle (MITM) attacks and blocks unauthorized server spoofing or tampered client binaries.
* **Critical:** The client MUST use the correct official client source code with the right server public key.
