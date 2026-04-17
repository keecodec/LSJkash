"""Outil de demo - Dechiffrement d'une capture Wireshark (Etape 6).

Usage :
    python3 tools/decrypt_capture.py

Vous aurez besoin :
  1. La cle de session AES (affichee par le serveur a la connexion)
  2. Le payload chiffre copie depuis Wireshark (la partie avant le | )
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.aes_gcm import decrypt_message, import_key  # noqa: E402


def main():
    print("=== LSJkash - Dechiffrement capture Wireshark ===")
    print()
    print("Etape 1 : Cle de session AES-256")
    print("  (copiez la valeur [DEMO] session_key = ... affichee par le serveur)")
    session_key_b64 = input("  Cle (base64) : ").strip()

    try:
        session_key = import_key(session_key_b64)
    except ValueError as exc:
        print(f"[!] Cle invalide : {exc}")
        sys.exit(1)

    print()
    print("Etape 2 : Payload chiffre depuis Wireshark")
    print("  Dans Wireshark : clic droit sur le paquet TCP -> Follow -> TCP Stream")
    print("  Copiez la partie AVANT le | (le ciphertext AES-GCM en base64)")
    cipher_b64 = input("  Ciphertext (base64) : ").strip()

    # Au cas ou l'utilisateur colle le message complet avec signature
    if "|" in cipher_b64:
        cipher_b64 = cipher_b64.split("|")[0]
        print("  (signature ignoree, seul le ciphertext est utilise)")

    print()
    try:
        plaintext = decrypt_message(cipher_b64, session_key)
        print(f"[OK] Message dechiffre : {plaintext}")
    except ValueError as exc:
        print(f"[!] Dechiffrement echoue : {exc}")
        print("     -> Verifiez que la cle et le ciphertext correspondent au meme client")
        sys.exit(1)


if __name__ == "__main__":
    main()
