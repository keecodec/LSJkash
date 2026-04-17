"""LSJkash - Client TCP de discussion securise."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, encrypt_message, generate_key, import_key  # noqa: E402
from crypto.caesar import caesar_decrypt, caesar_encrypt  # noqa: E402
from crypto.rsa_oaep import (  # noqa: E402
    encrypt_with_public_key,
    export_public_key,
    generate_key_pair,
    import_public_key,
    sign_message,
)
from crypto.vigenere import vigenere_decrypt, vigenere_encrypt  # noqa: E402

HOST = "127.0.0.1"
PORT = 5000

CIPHER = "none"
CIPHER_KEY = None
RSA_PRIVATE_KEY = None  # Etape 6 : cle privee RSA du client pour signer les messages


def encrypt(message):
    """Chiffre (et signe) un message selon le mode actif."""
    if CIPHER == "caesar":
        return caesar_encrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_encrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return encrypt_message(message, CIPHER_KEY)
    if CIPHER == "rsa":
        # Chiffrement AES-GCM + signature RSA-PSS
        cipher_b64 = encrypt_message(message, CIPHER_KEY)
        sig_b64 = sign_message(RSA_PRIVATE_KEY, cipher_b64.encode())
        return f"{cipher_b64}|{sig_b64}"
    return message


def decrypt(message):
    """Dechiffre un message selon le mode actif."""
    if CIPHER == "caesar":
        return caesar_decrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_decrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return decrypt_message(message, CIPHER_KEY)
    if CIPHER == "rsa":
        # Les messages relaves par le serveur sont juste la partie chiffree (pas de signature)
        return decrypt_message(message.strip(), CIPHER_KEY)
    return message


def receive(sock):
    """Recoit et affiche les messages du serveur."""
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                print("[!] Connexion fermee par le serveur")
                break
            encrypted_msg = data.decode().strip()
            try:
                clear_msg = decrypt(encrypted_msg)
            except ValueError as exc:
                print(f"\n[!] Message recu invalide : {exc}")
                print("> ", end="", flush=True)
                continue
            print(f"\r[chiffre] {encrypted_msg}")
            print(f"[clair]   {clear_msg}")
            print("> ", end="", flush=True)
        except OSError:
            break


def rsa_handshake(sock, server_pubkey_b64: str) -> tuple:
    """Effectue le handshake RSA-OAEP cote client.

    Protocole :
      1. Deja recu : PUBKEY:<server_pubkey_b64>
      2. Generer cle AES-256 + paire RSA propre
      3. Chiffrer la cle AES avec la cle publique du serveur (OAEP)
      4. Envoyer HANDSHAKE:<enc_key_b64>:<own_pubkey_b64>
      5. Attendre OK

    Returns:
        (session_key: bytes, own_private_key)
    """
    server_pub = import_public_key(server_pubkey_b64)

    # Generer la cle de session AES-256 et la paire RSA du client
    session_key = generate_key()
    own_priv, own_pub = generate_key_pair()

    # Chiffrer la cle de session avec la cle publique du serveur
    enc_key_b64 = encrypt_with_public_key(server_pub, session_key)
    own_pub_b64 = export_public_key(own_pub)

    sock.sendall(f"HANDSHAKE:{enc_key_b64}:{own_pub_b64}\n".encode())

    # Attendre la confirmation du serveur
    resp = sock.recv(4096).decode().strip()
    if resp != "OK":
        raise ConnectionError(f"Handshake refuse par le serveur : {resp}")

    return session_key, own_priv


def main():
    global CIPHER, CIPHER_KEY, RSA_PRIVATE_KEY

    username = input("Pseudo: ").strip() or "Anonyme"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"[!] Impossible de se connecter a {HOST}:{PORT}")
            sys.exit(1)

        # Premier paquet : detection du mode
        config_data = sock.recv(4096).decode().strip()

        if config_data.startswith("PUBKEY:"):
            # Mode RSA (Etape 6)
            CIPHER = "rsa"
            server_pubkey_b64 = config_data.split(":", 1)[1]
            print("[*] Mode RSA detecte — handshake OAEP en cours...")
            try:
                CIPHER_KEY, RSA_PRIVATE_KEY = rsa_handshake(sock, server_pubkey_b64)
            except ConnectionError as exc:
                print(f"[!] {exc}")
                sys.exit(1)
            print("[*] Cle de session AES-256 echangee via RSA-OAEP")
            print("[*] Chaque message sera signe avec votre cle RSA privee")

        elif config_data.startswith("CIPHER:"):
            # Modes non-RSA (none, caesar, vigenere, aesgcm)
            parts = config_data.split(":", 2)
            CIPHER = parts[1]
            key_str = parts[2] if len(parts) > 2 else ""
            if CIPHER == "caesar" and key_str:
                CIPHER_KEY = int(key_str)
            elif CIPHER == "vigenere" and key_str:
                CIPHER_KEY = key_str
            elif CIPHER == "aesgcm" and key_str:
                CIPHER_KEY = import_key(key_str)

        else:
            print(f"[!] Reponse serveur inattendue : {config_data}")
            sys.exit(1)

        print(f"[*] Connecte a {HOST}:{PORT} en tant que {username}")
        print(f"[*] Chiffrement: {CIPHER}")
        print("[*] Tapez votre message puis Entree. Ctrl+C pour quitter.\n")

        threading.Thread(target=receive, args=(sock,), daemon=True).start()

        try:
            while True:
                msg = input("> ")
                if msg:
                    payload = f"[{username}] {msg}"
                    encrypted = encrypt(payload)
                    sock.sendall(encrypted.encode())
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Deconnexion")


if __name__ == "__main__":
    main()
