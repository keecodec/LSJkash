"""Chiffre de Vigenere - substitution polyalphabetique."""


def vigenere_encrypt(plaintext, key):
    """Chiffre un texte avec une cle alphabetique repetee cycliquement.

    Chaque lettre du message est decalee par la lettre correspondante de la cle.
    Les caracteres non-alphabetiques sont conserves sans consommer de cle.
    """
    key = key.upper()
    result = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(ciphertext, key):
    """Dechiffre un texte chiffre par Vigenere."""
    key = key.upper()
    result = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift + 26) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)
