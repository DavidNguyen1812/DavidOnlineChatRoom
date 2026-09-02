from Crypto.PublicKey import RSA
import pathlib, os, hashlib

root_dir = pathlib.Path(__file__).parent.parent.absolute()
server_private_rsa_key_path = root_dir / 'RSAKeys' / 'ServerPermanentKeys' / 'ServerRSAprivateKey.pem'
server_public_rsa_key_path = root_dir / 'RSAKeys' / 'ServerPermanentKeys' / 'ServerRSApublicKey.pem'
up_to_date_client_script = pathlib.Path(__file__).parent / "client.py"

generateNewKeyPairs = False
if os.path.exists(server_private_rsa_key_path) and os.path.exists(server_public_rsa_key_path):
    userInput = ""
    print(f"There are existing RSA key pairs in {root_dir / 'RSAKeys' / 'ServerPermanentKeys'} folder!")
    while userInput.lower() not in ["y", "n"]:
        userInput = input(f"Do you want generate new RSA key pairs? (y/n): ")
        if userInput == "y":
            generateNewKeyPairs = True
else:
    print(f"RSA key pairs not found, generating new RSA key pairs")
    generateNewKeyPairs = True

if generateNewKeyPairs:
    try:
        key = RSA.generate(4096)
        privateKey = key.export_key()
        publicKey = key.publickey().export_key()
        with open(server_private_rsa_key_path, "wb") as pemfile:
            pemfile.write(privateKey)
        print(f"\nNew server private RSA key created at {server_private_rsa_key_path}")
        with open(server_public_rsa_key_path, "wb") as pemfile:
            pemfile.write(publicKey)
        print(f"\nNew server public RSA key created at {server_public_rsa_key_path}")
        serverPUhash = hashlib.sha512(publicKey).hexdigest()
        print(f"\nThe new server public RSA key SHA-512 hash is:\n{serverPUhash}\nPlease update this hash in the variable SERVERPUBLICKEYHASH in {up_to_date_client_script}")
    except Exception as e:
        print(f"Error creating RSA key pair: {e}")
else:
    print(f"No RSA key pairs were generated!")
