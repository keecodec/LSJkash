"""LSJkash - Outil interactif de cryptanalyse."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.caesar import caesar_decrypt  # noqa: E402
from crypto.cryptanalysis import (  # noqa: E402
    caesar_frequency_attack,
    caesar_brute_force,
    break_vigenere,
    kasiski_key_length,
    ic_key_length,
    index_of_coincidence,
)


def crack_caesar(ciphertext):
    """Casse un chiffrement Cesar."""
    print("\n=== Analyse de frequence ===")
    key = caesar_frequency_attack(ciphertext)
    plain = caesar_decrypt(ciphertext, key)
    print(f"Cle trouvee : {key}")
    print(f"Texte clair : {plain}")

    print("\n=== Brute force (top 5) ===")
    for k, txt in caesar_brute_force(ciphertext)[:5]:
        print(f"  cle={k:2d} : {txt[:80]}")


def crack_vigenere(ciphertext):
    """Casse un chiffrement Vigenere."""
    print("\n=== Analyse statistique ===")
    ic = index_of_coincidence(ciphertext)
    print(f"IC du texte : {ic:.4f} (francais=0.074, aleatoire=0.038)")

    k_len = kasiski_key_length(ciphertext)
    print(f"Kasiski     : longueur de cle = {k_len}")

    ic_len = ic_key_length(ciphertext)
    print(f"IC          : longueur de cle = {ic_len}")

    print("\n=== Cassage complet ===")
    key, plain = break_vigenere(ciphertext)
    print(f"Cle trouvee : {key}")
    print(f"Texte clair : {plain}")


def main():
    print("=== LSJkash Cryptanalyse ===")
    print("1. Casser Cesar")
    print("2. Casser Vigenere")
    choix = input("\nChoix [1]: ").strip() or "1"

    print("\nCollez le texte chiffre (une seule ligne) :")
    ciphertext = input("> ").strip()

    if not ciphertext:
        print("[!] Texte vide")
        return

    if choix in ("1", "caesar"):
        crack_caesar(ciphertext)
    elif choix in ("2", "vigenere"):
        crack_vigenere(ciphertext)
    else:
        print("[!] Choix invalide")


if __name__ == "__main__":
    main()
