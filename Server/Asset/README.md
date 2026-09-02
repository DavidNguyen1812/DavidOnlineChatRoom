# Server-Side Asset Directory

This directory houses the authoritative client distribution files and core cryptographic utilities required to establish secure, verified server infrastructure.

---

| File | Type | Primary Purpose |
| --- | --- | --- |
| **`client.py`** | Source Code | Client distribution and pre-authentication integrity verification. |
| **`generateServerRSAkeys.py`** | Utility Script | Automated generation of server RSA key pairs. |

---

**Directory Specifications**

* **`client.py` (Official Client Application)**
* Serves as the canonical source code for user distribution, containing the embedded SHA-512 fingerprint of the server's public key.
* The server dynamically hashes this local asset to cross-reference against connecting clients during the initial handshake. This guarantees that only untampered, up-to-date clients can proceed to the user authentication phase.


* **`generateServerRSAkeys.py` (Cryptographic Generator)**
* A standalone administrative script executed to provision fresh RSA-4096 key pairs for the server backend environment.