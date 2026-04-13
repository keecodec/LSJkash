"""LSJkash - Client TCP de discussion securise."""

import socket
import threading
import sys

HOST = "127.0.0.1"
PORT = 5000


def receive(sock):
    """Recoit et affiche les messages du serveur."""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[!] Connexion fermee par le serveur")
                break
            print(f"\r{data.decode()}\n> ", end="", flush=True)
        except OSError:
            break


def main():
    username = input("Pseudo: ").strip()
    if not username:
        username = "Anonyme"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"[!] Impossible de se connecter a {HOST}:{PORT}")
            sys.exit(1)

        print(f"[*] Connecte au serveur {HOST}:{PORT} en tant que {username}")
        print("[*] Tapez votre message puis Entree. Ctrl+C pour quitter.\n")

        threading.Thread(target=receive, args=(sock,), daemon=True).start()

        try:
            while True:
                msg = input("> ")
                if msg:
                    payload = f"[{username}] {msg}"
                    sock.sendall(payload.encode())
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Deconnexion")


if __name__ == "__main__":
    main()
