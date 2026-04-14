"""Cryptanalyse de Cesar et Vigenere - Etape 3.

Attaques COA (Ciphertext-Only Attack) :
- Cesar  : analyse de frequence (la lettre la plus frequente = E)
- Vigenere : test de Kasiski + Indice de Coincidence + analyse de frequence par colonne
"""

from math import gcd
from functools import reduce

from crypto.caesar import caesar_decrypt
from crypto.vigenere import vigenere_decrypt

# ------------------------------------------------------------
# Frequences des lettres en francais (source : Becker 2005)
# Ordre alphabetique A..Z
# ------------------------------------------------------------
FREQ_FR = {
    'A': 0.07636, 'B': 0.00901, 'C': 0.03260, 'D': 0.03669,
    'E': 0.14715, 'F': 0.01066, 'G': 0.00866, 'H': 0.00737,
    'I': 0.07529, 'J': 0.00545, 'K': 0.00049, 'L': 0.05456,
    'M': 0.02968, 'N': 0.07095, 'O': 0.05378, 'P': 0.03021,
    'Q': 0.01362, 'R': 0.06553, 'S': 0.07948, 'T': 0.07244,
    'U': 0.06311, 'V': 0.01838, 'W': 0.00049, 'X': 0.00427,
    'Y': 0.00128, 'Z': 0.00326,
}

# Vecteur de frequences ordonne A..Z (pour le calcul du score)
FREQ_FR_VEC = [FREQ_FR[chr(ord('A') + i)] for i in range(26)]


# ============================================================
# Utilitaires generaux
# ============================================================

def _letters_only(text: str) -> str:
    """Retourne uniquement les lettres du texte en majuscules."""
    return ''.join(c.upper() for c in text if c.isalpha())


def _letter_frequencies(text: str) -> list[float]:
    """Calcule les frequences relatives des 26 lettres (A..Z) dans text.

    text doit ne contenir que des lettres majuscules.
    Retourne une liste de 26 flottants, somme = 1.0 (ou 0 si texte vide).
    """
    n = len(text)
    if n == 0:
        return [0.0] * 26
    counts = [text.count(chr(ord('A') + i)) for i in range(26)]
    return [c / n for c in counts]


def _frequency_score(text: str) -> float:
    """Score de ressemblance au francais d'un texte (produit scalaire).

    Plus le score est eleve, plus la distribution ressemble au francais.
    Utilise le produit scalaire entre le vecteur de frequences du texte
    et celui du francais (somme des fi * qi).
    """
    letters = _letters_only(text)
    observed = _letter_frequencies(letters)
    return sum(o * r for o, r in zip(observed, FREQ_FR_VEC))


# ============================================================
# Cesar — Analyse de frequence + Brute-force
# ============================================================

def caesar_frequency_attack(ciphertext: str) -> int:
    """Retrouve la cle de Cesar par analyse de frequence (COA).

    Hypothese : la lettre la plus frequente du chiffre correspond a 'E'.
    Si plusieurs lettres sont a egalite, retourne la cle avec le meilleur
    score de frequence global.

    Returns:
        Cle probable (int entre 0 et 25).
    """
    letters = _letters_only(ciphertext)
    if not letters:
        return 0

    # On choisit la cle qui maximise le score de frequence francais
    best_key, best_score = 0, -1.0
    for key in range(26):
        candidate = caesar_decrypt(letters, key)
        score = _frequency_score(candidate)
        if score > best_score:
            best_score = score
            best_key = key
    return best_key


def caesar_brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """Essaie les 25 cles de Cesar et retourne les candidats tries par score.

    Returns:
        Liste de (cle, texte_dechiffre) classee par score decroissant
        (le plus probable en premier).
    """
    results = []
    for key in range(1, 26):
        candidate = caesar_decrypt(ciphertext, key)
        score = _frequency_score(candidate)
        results.append((key, candidate, score))
    results.sort(key=lambda x: x[2], reverse=True)
    return [(k, txt) for k, txt, _ in results]


# ============================================================
# Indice de Coincidence (IC)
# ============================================================

def index_of_coincidence(text: str) -> float:
    """Calcule l'Indice de Coincidence (IC) d'un texte.

    IC francais typique  : ~0.074
    IC texte aleatoire   : ~0.038  (= 1/26)

    Formule : IC = sum( ni * (ni-1) ) / ( N * (N-1) )
    avec ni = nombre d'occurrences de la lettre i, N = longueur totale.

    Returns:
        Flottant entre 0 et ~0.074 (ou 0 si texte trop court).
    """
    letters = _letters_only(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = [letters.count(chr(ord('A') + i)) for i in range(26)]
    numerator = sum(c * (c - 1) for c in counts)
    denominator = n * (n - 1)
    return numerator / denominator


# ============================================================
# Kasiski — Detection de la longueur de cle Vigenere
# ============================================================

def _pgcd_list(numbers: list[int]) -> int:
    """Calcule le PGCD d'une liste d'entiers."""
    if not numbers:
        return 1
    return reduce(gcd, numbers)


def kasiski_key_length(ciphertext: str, ngram_size: int = 3,
                       min_len: int = 2, max_len: int = 20) -> int:
    """Estime la longueur de cle Vigenere par le test de Kasiski (1863).

    Cherche les n-grammes repetes dans le chiffre.
    Les distances entre repetitions sont des multiples probables de la longueur de cle.
    Le PGCD de toutes ces distances donne la longueur probable.

    Args:
        ciphertext : texte chiffre (lettres uniquement)
        ngram_size : taille des n-grammes a chercher (3 par defaut)
        min_len    : longueur de cle minimale a considerer
        max_len    : longueur de cle maximale a considerer

    Returns:
        Longueur de cle estimee (int), ou 1 si aucune repetition trouvee.
    """
    letters = _letters_only(ciphertext)
    n = len(letters)
    distances = []

    # Trouver toutes les positions de chaque n-gramme
    seen: dict[str, list[int]] = {}
    for i in range(n - ngram_size + 1):
        ngram = letters[i:i + ngram_size]
        if ngram in seen:
            for prev in seen[ngram]:
                dist = i - prev
                if dist > 0:
                    distances.append(dist)
        else:
            seen[ngram] = []
        seen[ngram].append(i)

    if not distances:
        return 1  # Pas assez de repetitions

    # Calculer le PGCD de tous les ecarts
    key_len = _pgcd_list(distances)

    # Si le PGCD est hors de la plage attendue, voter par facteurs
    if key_len < min_len or key_len > max_len:
        # Compter les facteurs dans la plage
        factor_votes: dict[int, int] = {}
        for d in distances:
            for f in range(min_len, min(max_len + 1, d + 1)):
                if d % f == 0:
                    factor_votes[f] = factor_votes.get(f, 0) + 1
        if factor_votes:
            key_len = max(factor_votes, key=factor_votes.get)
        else:
            key_len = min_len

    return key_len


def ic_key_length(ciphertext: str, max_len: int = 20) -> int:
    """Estime la longueur de cle Vigenere par l'Indice de Coincidence.

    Pour chaque longueur L candidate (1..max_len) :
      - Decouper le chiffre en L colonnes
      - Calculer l'IC moyen des colonnes
      - Retenir la premiere longueur qui donne un IC fort (pic).

    Args:
        ciphertext : texte chiffre
        max_len    : longueur maximale a tester

    Returns:
        Longueur de cle estimee (int).
    """
    letters = _letters_only(ciphertext)
    ics = []

    for length in range(1, max_len + 1):
        # Decouper en `length` colonnes
        columns = [''.join(letters[i::length]) for i in range(length)]
        avg_ic = sum(index_of_coincidence(col) for col in columns) / length
        ics.append(avg_ic)

    if not ics:
        return 1

    # On cherche le premier "pic" significatif
    max_ic = max(ics)
    threshold = max(0.060, max_ic * 0.85)

    for i, avg_ic in enumerate(ics):
        if avg_ic >= threshold:
            return i + 1

    return 1


# ============================================================
# Vigenere — Analyse de frequence par colonne
# ============================================================

def vigenere_frequency_attack(ciphertext: str, key_length: int) -> str:
    """Retrouve la cle Vigenere en appliquant l'analyse de frequence colonne par colonne.

    Une fois la longueur de cle connue :
    - Colonne i = tous les caracteres du chiffre aux positions i, i+L, i+2L, ...
    - Chaque colonne est un chiffrement de Cesar independant
    - On recupere chaque lettre de cle avec caesar_frequency_attack()

    Args:
        ciphertext : texte chiffre
        key_length : longueur de cle estimee

    Returns:
        Cle probable (str en majuscules).
    """
    letters = _letters_only(ciphertext)
    key = []
    for i in range(key_length):
        column = letters[i::key_length]
        shift = caesar_frequency_attack(column)
        key.append(chr(ord('A') + shift))
    return ''.join(key)


def break_vigenere(ciphertext: str,
                   max_len: int = 20) -> tuple[str, str]:
    """Casse un chiffrement Vigenere en COA (Kasiski + IC + frequence).

    Algorithme complet :
    1. Estimation longueur cle par Kasiski
    2. Confirmation / affinage par l'IC
    3. Analyse de frequence colonne par colonne
    4. Dechiffrement avec la cle trouvee

    Args:
        ciphertext : texte chiffre (peut contenir des non-lettres)
        max_len    : longueur de cle maximale a tester

    Returns:
        (cle_trouvee, texte_en_clair)
    """
    # Etape 1 : Kasiski
    k_len = kasiski_key_length(ciphertext, max_len=max_len)

    # Etape 2 : IC (prend le dessus si Kasiski echoue)
    ic_len = ic_key_length(ciphertext, max_len=max_len)

    # On teste les deux longueurs et on garde le meilleur score
    candidates = {k_len, ic_len}
    best_key, best_plain, best_score = '', '', -1.0
    for length in candidates:
        if length < 1:
            continue
        key = vigenere_frequency_attack(ciphertext, length)
        plain = vigenere_decrypt(ciphertext, key)
        score = _frequency_score(plain)
        if score > best_score:
            best_score = score
            best_key = key
            best_plain = plain

    return best_key, best_plain
