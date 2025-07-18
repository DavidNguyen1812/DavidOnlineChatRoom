# DavidOnlineChatRoom

An online chat room with hybrid encryption on RSA and AES-OCB using pycryptodome, an open source crypto library.
The Server can be hosted on the cloud server like EC2 instances, .etc.

Every message sent between the client and server for authentication purpose are in sha512 hash forms.

Every message exchanged after the client is in the chat session with other clients are encrypted using hybrid encryption RSA and AES-256-OCB mode.

The hashing algorithem shake_128 is used for file integrity check for Server public key verification upon first connection and censored word list or a newly updated of a client script.

Server implemented time out for user used inappropriate language using better_profanity and the censored wordlist. Server also will lock user account with too many failed log in attempts.

**Required Python Dependencies**

pip install pycryptodome schedule dotenv -y

Pycryptodome - The encryption process
Schedule - For checking lock accounts and time out accounts
dotenv - For loading environment variables from .env file

**Before Running the Scripts**

Make sure you configure the appropriate file paths in your env file and change the file name to .env to hide it and enable dotenv to load the environment variables.

Make sure you configure public address of the server correctly.

Do not modify any script file, else you're cooked!
