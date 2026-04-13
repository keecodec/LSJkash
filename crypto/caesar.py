"""Chiffre de Cesar - substitution monoalphabetique."""


def caesar_encrypt(plaintext, key):
    """Chiffre un texte avec le decalage key.

    C(x) = (x + key) mod 26
    Seules les lettres sont decalees, le reste est conserve tel quel.
    """
    result = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + key) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(ciphertext, key):
    """Dechiffre un texte chiffre par Cesar.

    D(x) = (x - key + 26) mod 26
    """
    return caesar_encrypt(ciphertext, -key)
