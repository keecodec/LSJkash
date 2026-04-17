"""LSJkash - Serveur TCP de discussion securise."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, encrypt_message, export_key, generate_key  # noqa: E402
from crypto.caesar import caesar_decrypt, caesar_encrypt  # noqa: E402
from crypto.vigenere import vigenere_decrypt, vigenere_encrypt  # noqa: E402

HOST = "0.0.0.0"
PORT = 5000

clients = []
lock = threading.Lock()

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


def broadcast(message_bytes, sender_conn=None):
    """Envoie un message a tous les clients connectes sauf l'expediteur."""
    with lock:
        for client in clients:
            if client != sender_conn:
                try:
                    client.sendall(message_bytes)
                except OSError:
                    clients.remove(client)


def handle_client(conn, addr):
    """Gere la communication avec un client connecte."""
    print(f"[+] {addr} connecte")
    with lock:
        clients.append(conn)

    # Envoie le mode de chiffrement au client
    if CIPHER == "aesgcm":
        key_material = export_key(CIPHER_KEY)
    else:
        key_material = CIPHER_KEY or ""
    config = f"CIPHER:{CIPHER}:{key_material}\n"
    conn.sendall(config.encode())

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            encrypted_msg = data.decode()
            try:
                clear_msg = decrypt(encrypted_msg)
            except ValueError as exc:
                print(f"[!] Message invalide de {addr}: {exc}")
                continue
            print(f"[{addr}] chiffre: {encrypted_msg}")
            print(f"[{addr}] clair:   {clear_msg}")
            broadcast(data, conn)
    except ConnectionResetError:
        pass
    finally:
        with lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[-] {addr} deconnecte")


def main():
    global CIPHER, CIPHER_KEY

    print("=== LSJkash Serveur ===")
    print("1. none (clair)")
    print("2. caesar")
    print("3. vigenere")
    print("4. aesgcm")
    choix = input("Mode de chiffrement [1]: ").strip().lower()
    modes = {"1": "none", "2": "caesar", "3": "vigenere",
             "4": "aesgcm", "none": "none", "caesar": "caesar",
             "vigenere": "vigenere", "aesgcm": "aesgcm",
             "": "none"}
    CIPHER = modes.get(choix, "none")

    if CIPHER == "caesar":
        CIPHER_KEY = int(input("Cle (decalage 1-25): ").strip())
    elif CIPHER == "vigenere":
        CIPHER_KEY = input("Cle (mot): ").strip().upper()
    elif CIPHER == "aesgcm":
        CIPHER_KEY = generate_key()

    print(f"[*] Chiffrement: {CIPHER}")
    if CIPHER == "aesgcm":
        print("[*] Cle AES-256 de session generee et transmise aux clients a la connexion")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        print(f"[*] Serveur en ecoute sur {HOST}:{PORT}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
