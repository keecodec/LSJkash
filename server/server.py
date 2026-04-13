"""LSJkash - Serveur TCP de discussion securise."""

import socket
import threading

HOST = "0.0.0.0"
PORT = 5000

clients = []
lock = threading.Lock()


def broadcast(message, sender_conn=None):
    """Envoie un message a tous les clients connectes sauf l'expediteur."""
    with lock:
        for client in clients:
            if client != sender_conn:
                try:
                    client.sendall(message)
                except OSError:
                    clients.remove(client)


def handle_client(conn, addr):
    """Gere la communication avec un client connecte."""
    print(f"[+] {addr} connecte")
    with lock:
        clients.append(conn)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"[{addr}] {data.decode()}")
            broadcast(data, conn)
    except ConnectionResetError:
        pass
    finally:
        with lock:
            clients.remove(conn)
        conn.close()
        print(f"[-] {addr} deconnecte")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        print(f"[*] Serveur en ecoute sur {HOST}:{PORT}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
