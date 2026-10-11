# Server-Side Database Schema (JSON)

This directory houses the local JSON databases responsible for persisting user credentials, end-to-end encrypted (E2EE) messaging payloads, and asynchronous network notifications.

---

| Database File | Primary Purpose | Security Context |
| --- | --- | --- |
| **`accountData.json`** | Identity & Authentication | Stores salted password hashes and rate-limiting metrics. |
| **`chatHistory.json`** | E2EE Message Storage | Stores zero-knowledge encrypted payloads and RSA-wrapped symmetric keys. |
| **`pendingNotifications.json`** | Event Queuing | Caches delivery states for offline users. |

---

### 1. `accountData.json` (User Profiles & Authentication)

```json
    "JohnDoe": {
        "Password": {
            "salt": "EWDQWBMx10HpiptxmzkqJQ==",
            "hash": "2bf5532d0fe31ea73452b75f1bb2d000f4b7cdcde316b5c11d0948032f5355a0a272c7a3c293e29f28ca79e8e3fcdf5f8b4ef6e62b9032b6d0ede3a11c6002eb",
            "iterations": 600000
        },
        "Last Log In": "Sat Oct 10 22:01:47 2026",
        "Current Lock Out Time": 0,
        "Failed Attempts": 0,
        "Locked Out Record": [],
        "Friends": [
            "DavidNguyen1812",
            "CodyArthur"
        ]
    }

```

* **`Password`**: A SHA-512 hash of the user's password, strictly salted with their unique username to neutralize rainbow table attacks and prevent hash collisions.
* **`Last Log In`**: Timestamp of the most recent successfully authenticated session.
* **`Current Lock Out Time`**: Active lockout duration metric used to mitigate brute-force authentication attempts.
* **`Failed Attempts`**: Persistently keeping track of current failed log in attempts.
* **`Locked Out Record`**: Historical log tracking the timestamps of prior account lockouts.
* **`Friends`**: An array of authorized peer usernames explicitly approved by the user.

### 2. `chatHistory.json` (Encrypted Messaging)

```json
{
    "JaneDoe": {
        "JohnDoe": [
            {
                "To": "JohnDoe",
                "Date": "Mon Jan 3 00:00:00 1900",
                "Message": "R3eUzydqcunmZkR7odEk0E68TRvE675sKMjxPngJOgJfeYc4RpixEF8oT...",
                "Key For Self": "JkUqyhmpO6wA3s3Ej7zRe9/eM7NZa+RXPYTnAOpX58NqMVIQR104MlsUG...",
                "Key For Recipient": "WqyeflzTWGlq0QuEWcrWsD8iY+1g+4UnvLcunCdj9OjcwlHqcFMnTGRLp..."
            }
        ]
    }
 }

```

* **`To` / `Date**`: Routing metadata and chronologic timestamps for UI sorting.
* **`Message`**: The actual message payload, strictly encrypted using a randomly generated AES-256 key in OCB mode. The server cannot read this.
* **`Key For Self`**: The ephemeral AES-256 session key, encrypted using the **sender's** permanent RSA-4096 public key. This ensures the sender can decrypt and view their own chat history.
* **`Key For Recipient`**: The exact same ephemeral AES-256 session key, encrypted using the **recipient's** permanent RSA-4096 public key.

### 3. `pendingNotifications.json` (Asynchronous Events)

```json
{
    "JohnDoe": {
        "Unread Messages": {"JaneDoe": 1},
        "Pending Friend Requests": ["NewUser123"],
        "Friend Request Answers": {"JaneDoe": "accept"}
    }
}

```

* **`Unread Messages`**: A key-value mapping of sender usernames to the exact integer count of unread messages.
* **`Pending Friend Requests`**: A queue of inbound peer connection requests awaiting the user's authorization.
* **`Friend Request Answers`**: State tracking for outbound requests (e.g., `accept` or `reject`), cached here so the requesting user receives the update immediately upon their next login.
