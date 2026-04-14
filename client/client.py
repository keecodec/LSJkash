"""LSJkash - Client TCP de discussion securise."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, encrypt_message, import_key  # noqa: E402
from crypto.caesar import caesar_decrypt, caesar_encrypt  # noqa: E402
from crypto.vigenere import vigenere_decrypt, vigenere_encrypt  # noqa: E402

HOST = "127.0.0.1"
PORT = 5000

CIPHER = "none"
CIPHER_KEY = None


def encrypt(message):
    """Chiffre un message selon le mode actif."""
    if CIPHER == "caesar":
        return caesar_encrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_encrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return encrypt_message(message, CIPHER_KEY)
    return message


def decrypt(message):
    """Dechiffre un message selon le mode actif."""
    if CIPHER == "caesar":
        return caesar_decrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_decrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return decrypt_message(message, CIPHER_KEY)
    return message


def receive(sock):
    """Recoit et affiche les messages du serveur."""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[!] Connexion fermee par le serveur")
                break
            encrypted_msg = data.decode()
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


def main():
    global CIPHER, CIPHER_KEY

    username = input("Pseudo: ").strip() or "Anonyme"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"[!] Impossible de se connecter a {HOST}:{PORT}")
            sys.exit(1)

        # Recoit la config de chiffrement du serveur
        config_data = sock.recv(4096).decode().strip()
        if config_data.startswith("CIPHER:"):
            parts = config_data.split(":", 2)
            CIPHER = parts[1]
            key_str = parts[2] if len(parts) > 2 else ""
            if CIPHER == "caesar" and key_str:
                CIPHER_KEY = int(key_str)
            elif CIPHER == "vigenere" and key_str:
                CIPHER_KEY = key_str
            elif CIPHER == "aesgcm" and key_str:
                CIPHER_KEY = import_key(key_str)
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
