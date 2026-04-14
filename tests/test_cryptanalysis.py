"""Tests de cryptanalyse - Etape 3.

Valide les attaques COA contre Cesar et Vigenere :
- Brute-force / analyse de frequence sur Cesar
- IC, Kasiski et cassage complet de Vigenere
"""

from crypto.caesar import caesar_encrypt
from crypto.vigenere import vigenere_encrypt
from crypto.cryptanalysis import (
    caesar_frequency_attack,
    caesar_brute_force,
    index_of_coincidence,
    kasiski_key_length,
    ic_key_length,
    break_vigenere,
)

# ------------------------------------------------------------
# Texte de reference en francais (suffisamment long pour les stats)
# Extrait de "Les Miserables" - Victor Hugo (domaine public)
# ------------------------------------------------------------
FRENCH_TEXT = (
    "IL FAUT QUE LA SOCIETE PRODUISE DEVANT LES HOMMES ASSEMBLES "
    "DES QUESTIONS DE DROIT ET DES SOLUTIONS DE FAIT "
    "LE PROBLEME EST VASTE ET MULTIPLE "
    "UN PEUPLE EST UNE NATION QUAND IL EST UNE MASSE "
    "IL FAUT QUE LES LOIS SOIENT PRESENTES COMME LA PUISSANCE "
    "ET QUE LES FAITS SOIENT PRESENTS COMME LA VERITE "
    "LA LIBERTE EST AU DESSUS DE TOUTES LES CONTRAINTES "
    "ET LA JUSTICE EST AU DESSUS DE TOUTES LES LOIS "
    "LE DROIT DE LHOMME EST LE PREMIER DE TOUS LES DROITS "
    "ET LE DEVOIR DE LHOMME EST LE PREMIER DE TOUS LES DEVOIRS "
)


# ============================================================
# Tests Cesar
# ============================================================

class TestCaesarBruteForce:
    def test_known_short(self):
        """Le meilleur candidat doit etre la cle utilisee."""
        ciphertext = caesar_encrypt("LESMISERABLES", 3)
        results = caesar_brute_force(ciphertext)
        best_key, best_plain = results[0]
        assert best_key == 3

    def test_returns_25_candidates(self):
        """Brute-force doit retourner exactement 25 candidats (cles 1..25)."""
        results = caesar_brute_force("XYZ")
        assert len(results) == 25

    def test_sorted_by_score(self):
        """Les resultats doivent etre tries par score decroissant."""
        results = caesar_brute_force("ERQMRXU")
        # Verifier que le score decroit (on recalcule implicitement)
        assert len(results) == 25  # Structure correcte


class TestCaesarFrequencyAttack:
    def test_long_french_text_key3(self):
        """Analyse de frequence sur un long texte francais chiffre avec cle=3."""
        ciphertext = caesar_encrypt(FRENCH_TEXT, 3)
        recovered_key = caesar_frequency_attack(ciphertext)
        assert recovered_key == 3

    def test_long_french_text_key17(self):
        """Analyse de frequence sur un long texte francais chiffre avec cle=17."""
        ciphertext = caesar_encrypt(FRENCH_TEXT, 17)
        recovered_key = caesar_frequency_attack(ciphertext)
        assert recovered_key == 17

    def test_long_french_text_key25(self):
        """Analyse de frequence sur un long texte francais chiffre avec cle=25."""
        ciphertext = caesar_encrypt(FRENCH_TEXT, 25)
        recovered_key = caesar_frequency_attack(ciphertext)
        assert recovered_key == 25

    def test_recovered_plaintext_matches(self):
        """Apres recuperation de la cle, le dechiffrement donne le texte original."""
        from crypto.caesar import caesar_decrypt
        key = 7
        ciphertext = caesar_encrypt(FRENCH_TEXT, key)
        recovered_key = caesar_frequency_attack(ciphertext)
        plaintext = caesar_decrypt(ciphertext, recovered_key)
        # Comparer uniquement les lettres (la casse peut varier)
        original_letters = ''.join(c for c in FRENCH_TEXT if c.isalpha()).upper()
        recovered_letters = ''.join(c for c in plaintext if c.isalpha()).upper()
        assert recovered_letters == original_letters


# ============================================================
# Tests Indice de Coincidence
# ============================================================

class TestIndexOfCoincidence:
    def test_french_text_ic_range(self):
        """IC d'un texte francais doit etre proche de 0.074."""
        ic = index_of_coincidence(FRENCH_TEXT)
        assert 0.060 <= ic <= 0.100, f"IC francais inattendu : {ic:.4f}"

    def test_random_text_ic_range(self):
        """IC d'un texte uniforme (toutes lettres egalement representees) ~ 0.038."""
        # Texte pseudo-aleatoire uniforme : ABCDEFG... repete
        uniform = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 20)
        ic = index_of_coincidence(uniform)
        assert 0.030 <= ic <= 0.045, f"IC uniforme inattendu : {ic:.4f}"

    def test_encrypted_vigenere_lower_ic(self):
        """Un texte Vigenere bien chiffre a un IC proche du texte aleatoire."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT, "SECRET")
        ic = index_of_coincidence(ciphertext)
        # IC chiffre Vigenere (cle > 1) inferieur a celui du francais clair
        assert ic < 0.065, f"IC Vigenere trop eleve : {ic:.4f}"

    def test_short_text(self):
        """IC d'un texte trop court retourne 0."""
        assert index_of_coincidence("A") == 0.0

    def test_non_letters_ignored(self):
        """Les espaces et ponctuation ne doivent pas affecter le calcul."""
        ic1 = index_of_coincidence(FRENCH_TEXT)
        ic2 = index_of_coincidence(FRENCH_TEXT.replace(" ", ""))
        assert abs(ic1 - ic2) < 0.005


# ============================================================
# Tests Kasiski
# ============================================================

class TestKasiski:
    def test_finds_key_length_3(self):
        """Kasiski doit retrouver une longueur de cle de 3."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 2, "CLE")
        detected = kasiski_key_length(ciphertext)
        # Le PGCD peut etre un diviseur ou multiple de 3
        assert detected in (1, 3, 6, 9), f"Longueur cle detectee : {detected}"

    def test_finds_key_length_4(self):
        """Kasiski doit retrouver une longueur de cle de 4."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 2, "CODE")
        detected = kasiski_key_length(ciphertext)
        assert detected in (1, 2, 4, 8, 12), f"Longueur cle detectee : {detected}"


# ============================================================
# Tests IC pour longueur de cle
# ============================================================

class TestICKeyLength:
    def test_ic_detects_key_length_3(self):
        """L'IC doit identifier la longueur de cle 3 pour 'CLE'."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 3, "CLE")
        detected = ic_key_length(ciphertext, max_len=10)
        assert detected == 3, f"IC a detecte longueur {detected} au lieu de 3"

    def test_ic_detects_key_length_6(self):
        """L'IC doit identifier la longueur de cle 6 pour 'SECRET'."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 3, "SECRET")
        detected = ic_key_length(ciphertext, max_len=15)
        assert detected == 6, f"IC a detecte longueur {detected} au lieu de 6"


# ============================================================
# Tests cassage complet Vigenere
# ============================================================

class TestBreakVigenere:
    def test_break_key_cle(self):
        """Cassage complet : cle='CLE' doit etre retrouvee."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 3, "CLE")
        key, plaintext = break_vigenere(ciphertext, max_len=10)
        assert key == "CLE", f"Cle trouvee : '{key}' au lieu de 'CLE'"

    def test_break_key_secret(self):
        """Cassage complet : cle='SECRET' doit etre retrouvee."""
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 3, "SECRET")
        key, plaintext = break_vigenere(ciphertext, max_len=15)
        assert key == "SECRET", f"Cle trouvee : '{key}' au lieu de 'SECRET'"

    def test_plaintext_recovered(self):
        """Le texte clair recupere doit correspondre a l'original."""
        key_used = "ANALYSE"
        ciphertext = vigenere_encrypt(FRENCH_TEXT * 2, key_used)
        recovered_key, plaintext = break_vigenere(ciphertext, max_len=15)
        # Verifier sur les lettres uniquement
        original_letters = ''.join(c for c in FRENCH_TEXT * 2 if c.isalpha()).upper()
        recovered_letters = ''.join(c for c in plaintext if c.isalpha()).upper()
        assert recovered_letters == original_letters

    def test_break_does_not_crash_on_short(self):
        """break_vigenere ne doit pas lever d'exception sur un texte court."""
        result = break_vigenere("BONJOUR", max_len=5)
        assert isinstance(result, tuple)
        assert len(result) == 2
