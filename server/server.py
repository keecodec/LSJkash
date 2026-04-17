"""LSJkash - Serveur TCP de discussion securise."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, encrypt_message, export_key, generate_key  # noqa: E402
from crypto.caesar import caesar_decrypt, caesar_encrypt  # noqa: E402
from crypto.rsa_oaep import (  # noqa: E402
    decrypt_with_private_key,
    export_public_key,
    generate_key_pair,
    verify_signature,
)
from crypto.vigenere import vigenere_decrypt, vigenere_encrypt  # noqa: E402

HOST = "0.0.0.0"
PORT = 5000

clients = []
lock = threading.Lock()

CIPHER = "none"
CIPHER_KEY = None

# Etape 6 : cles RSA du serveur (generees au demarrage en mode rsa)
SERVER_RSA_PRIVATE_KEY = None
SERVER_RSA_PUBLIC_KEY = None

# Etape 6 : sessions individuelles des clients RSA : conn -> {"session_key": bytes, "pubkey": rsa_pub}
client_sessions = {}


# ============================================================
# Chiffrement / dechiffrement (modes non-RSA)
# ============================================================

def encrypt(message):
    """Chiffre un message selon le mode actif (non-RSA)."""
    if CIPHER == "caesar":
        return caesar_encrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_encrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return encrypt_message(message, CIPHER_KEY)
    return message


def decrypt(message):
    """Dechiffre un message selon le mode actif (non-RSA)."""
    if CIPHER == "caesar":
        return caesar_decrypt(message, CIPHER_KEY)
    if CIPHER == "vigenere":
        return vigenere_decrypt(message, CIPHER_KEY)
    if CIPHER == "aesgcm":
        return decrypt_message(message, CIPHER_KEY)
    return message


# ============================================================
# Broadcast
# ============================================================

def broadcast(message_bytes, sender_conn=None):
    """Envoie un message a tous les clients connectes sauf l'expediteur (modes non-RSA)."""
    with lock:
        for client in list(clients):
            if client != sender_conn:
                try:
                    client.sendall(message_bytes)
                except OSError:
                    clients.remove(client)


def broadcast_rsa(plaintext: str, sender_conn=None):
    """Re-chiffre et diffuse un message pour tous les clients RSA.

    Chaque client ayant sa propre cle de session, le serveur dechiffre
    le message une fois puis le re-chiffre pour chaque destinataire.
    """
    with lock:
        dead = []
        for conn, session in list(client_sessions.items()):
            if conn == sender_conn:
                continue
            try:
                ciphertext = encrypt_message(plaintext, session["session_key"])
                conn.sendall(ciphertext.encode())
            except OSError:
                dead.append(conn)
        for conn in dead:
            client_sessions.pop(conn, None)


# ============================================================
# Gestion des clients — mode RSA (Etape 6)
# ============================================================

def handle_client_rsa(conn, addr):
    """Handshake RSA-OAEP + boucle de messages signes (Etape 6).

    Protocole :
      1. Serveur -> Client : PUBKEY:<rsa_pub_b64>
      2. Client -> Serveur : HANDSHAKE:<enc_aes_key_b64>:<client_pub_b64>
      3. Serveur dechiffre la cle AES, stocke la cle publique du client
      4. Serveur -> Client : OK
      5. Boucle : client envoie <aes_gcm_b64>|<sig_b64>, serveur verifie + relaie
    """
    # Etape 1 : envoyer la cle publique RSA du serveur
    pub_b64 = export_public_key(SERVER_RSA_PUBLIC_KEY)
    conn.sendall(f"PUBKEY:{pub_b64}\n".encode())

    # Etape 2 : recevoir le HANDSHAKE du client
    try:
        raw = conn.recv(4096).decode().strip()
    except OSError:
        conn.close()
        return

    if not raw.startswith("HANDSHAKE:"):
        conn.sendall(b"ERR:Bad handshake\n")
        conn.close()
        return

    parts = raw.split(":", 2)
    if len(parts) != 3:
        conn.sendall(b"ERR:Malformed handshake\n")
        conn.close()
        return

    enc_key_b64 = parts[1]
    client_pub_b64 = parts[2]

    # Etape 3 : dechiffrer la cle de session + importer la cle publique du client
    try:
        from crypto.rsa_oaep import import_public_key
        session_key = decrypt_with_private_key(SERVER_RSA_PRIVATE_KEY, enc_key_b64)
        client_pub = import_public_key(client_pub_b64)
    except Exception as exc:
        print(f"[!] Handshake RSA invalide {addr}: {exc}")
        conn.sendall(b"ERR:Handshake failed\n")
        conn.close()
        return

    with lock:
        client_sessions[conn] = {"session_key": session_key, "pubkey": client_pub}
        clients.append(conn)

    # Etape 4 : confirmer au client
    conn.sendall(b"OK\n")
    print(f"[+] {addr} connecte (RSA, cle de session echangee par OAEP)")

    # Etape 5 : boucle de messages
    try:
        while True:
            data = conn.recv(8192)
            if not data:
                break

            payload = data.decode().strip()

            # Format attendu : <aes_gcm_b64>|<signature_b64>
            if "|" not in payload:
                print(f"[!] {addr} : message sans signature — ignore")
                continue

            cipher_b64, sig_b64 = payload.split("|", 1)

            # Verification de la signature
            sig_valid = verify_signature(client_pub, cipher_b64.encode(), sig_b64)
            if not sig_valid:
                print(f"[!] {addr} : signature INVALIDE — message rejete")
                continue

            # Dechiffrement
            try:
                clear_msg = decrypt_message(cipher_b64, session_key)
            except ValueError as exc:
                print(f"[!] {addr} : dechiffrement invalide : {exc}")
                continue

            print(f"[{addr}] sig=OK | clair: {clear_msg}")
            broadcast_rsa(clear_msg, conn)

    except ConnectionResetError:
        pass
    finally:
        with lock:
            client_sessions.pop(conn, None)
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[-] {addr} deconnecte")


# ============================================================
# Gestion des clients — modes non-RSA
# ============================================================

def handle_client(conn, addr):
    """Gere la communication avec un client connecte."""
    if CIPHER == "rsa":
        handle_client_rsa(conn, addr)
        return

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


# ============================================================
# Point d'entree
# ============================================================

def main():
    global CIPHER, CIPHER_KEY, SERVER_RSA_PRIVATE_KEY, SERVER_RSA_PUBLIC_KEY

    print("=== LSJkash Serveur ===")
    print("1. none (clair)")
    print("2. caesar")
    print("3. vigenere")
    print("4. aesgcm")
    print("5. rsa   (AES-GCM + echange de cle RSA-OAEP + signatures)")
    choix = input("Mode de chiffrement [1]: ").strip().lower()
    modes = {
        "1": "none", "2": "caesar", "3": "vigenere",
        "4": "aesgcm", "5": "rsa",
        "none": "none", "caesar": "caesar", "vigenere": "vigenere",
        "aesgcm": "aesgcm", "rsa": "rsa",
        "": "none",
    }
    CIPHER = modes.get(choix, "none")

    if CIPHER == "caesar":
        CIPHER_KEY = int(input("Cle (decalage 1-25): ").strip())
    elif CIPHER == "vigenere":
        CIPHER_KEY = input("Cle (mot): ").strip().upper()
    elif CIPHER == "aesgcm":
        CIPHER_KEY = generate_key()
    elif CIPHER == "rsa":
        print("[*] Generation de la paire de cles RSA-2048...")
        SERVER_RSA_PRIVATE_KEY, SERVER_RSA_PUBLIC_KEY = generate_key_pair()
        print("[*] Paire RSA generee — cle publique sera envoyee a chaque client")

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
