# Rapport d'audit - Etape 3 : Cryptanalyse

## Objectif

Prouver algorithmiquement les faiblesses des chiffrements implantes a l'etape 2 (Cesar, Vigenere).
Ces attaques sont de type **COA (Ciphertext-Only Attack)** : l'attaquant ne connait que le texte chiffre,
comme dans une capture Wireshark.

---

## Classification des attaques

| Type | Sigle | Hypothese attaquant | Applicable ici |
|------|-------|--------------------|-|
| Ciphertext-Only | **COA** | Uniquement le texte chiffre (capture reseau) | OUI |
| Known-Plaintext | **KPA** | Paires (clair, chiffre) connues | Possible (si trafic connu) |
| Chosen-Plaintext | **CPA** | L'attaquant choisit les textes a chiffrer | Hors scope (pas d'acces au serveur) |

---

## Attaque 1 : Casser Cesar

### Principe — Analyse de frequence

En francais, **E** est la lettre la plus frequente (~14.7 %), suivie de A, S, I, T, N, R.
Dans un texte chiffre par Cesar, la distribution est decalee de k positions.
La lettre la plus frequente du chiffre correspond probablement a **E**.

**Algorithme implementé (`caesar_frequency_attack`)** :  
Pour chaque cle k ∈ {0..25}, dechiffrer et mesurer le score de ressemblance au francais
(produit scalaire avec le vecteur de frequences de reference). La cle avec le score maximal est retenue.

### Resultats

| Texte long (~500 lettres) | Cle utilisee | Cle retrouvee | Temps |
|--------------------------|-------------|--------------|-------|
| Texte "Les Miserables"   | 3           | **3**        | < 1 ms |
| Texte "Les Miserables"   | 17          | **17**       | < 1 ms |
| Texte "Les Miserables"   | 25          | **25**       | < 1 ms |

**Conclusion** : Cesar est casse en **< 1 ms** par simple analyse de frequence.
L'espace des cles est trivialmente petit (25 essais au maximum).

---

## Attaque 2 : Casser Vigenere

### Principe — Kasiski + Indice de Coincidence

Vigenere est une combinaison de n chiffrements Cesar independants (n = longueur de cle).
L'attaque se deroule en 3 etapes :

#### Etape A : Trouver la longueur de cle

**Test de Kasiski (1863)** :
- Chercher les sequences de 3+ lettres qui se repetent dans le chiffre.
- La meme sequence claire chiffree avec le meme alignement de cle produit le meme chiffre.
- Les distances entre repetitions sont des multiples de la longueur de cle.
- **PGCD des distances = longueur de cle probable.**

**Indice de Coincidence (IC)** :
```
IC = Σ ni*(ni-1) / (N*(N-1))
```
- IC texte francais  : ~0.074
- IC texte aleatoire : ~0.038

Pour chaque longueur L candidate, on decoupe le chiffre en L colonnes et on calcule l'IC moyen.
La longueur dont l'IC moyen est le plus proche de 0.074 est retenue.

#### Etape B : Casser chaque colonne

Une fois la longueur L connue, chaque colonne i (positions i, i+L, i+2L, ...) est un chiffrement
de Cesar independant. On applique `caesar_frequency_attack` sur chacune.

#### Etape C : Dechiffrer

La cle reconstruite permet de dechiffrer l'integralite du texte avec `vigenere_decrypt`.

### Resultats

| Texte (~1000 lettres) | Cle utilisee | Longueur detectee | Cle retrouvee | Temps |
|----------------------|-------------|------------------|--------------|-------|
| "Les Miserables" x3  | CLE (3)      | **3**            | **CLE**      | < 50 ms |
| "Les Miserables" x3  | SECRET (6)   | **6**            | **SECRET**   | < 50 ms |
| "Les Miserables" x2  | ANALYSE (7)  | **7**            | **ANALYSE**  | < 50 ms |

**Conclusion** : Vigenere est casse en **< 100 ms** avec un texte suffisamment long.
L'espace des cles de 4 lettres (26^4 = 456 976) est illusoire car l'analyse statistique
ne fait pas de force brute.

---

## Analyse de securite — Triade CIA

| Pilier | Cesar | Vigenere |
|--------|-------|----------|
| **Confidentialite** | ECHOUE — brute-force 25 cles | ECHOUE — Kasiski + IC retrouve la cle |
| **Integrite** | ECHOUE — aucun mecanisme | ECHOUE — aucun mecanisme |
| **Authentification** | ECHOUE — aucun mecanisme | ECHOUE — aucun mecanisme |

---

## Vulnerabilites confirmees

1. **Cesar : espace trivial** — 25 cles, attaque en microsecondes, meme sans analyse de frequence
2. **Vigenere : algorithme du 19e siecle** — Kasiski (1863) rend cet algorithme obsolete
3. **Cle transmise en clair** — visible dans Wireshark (`CIPHER:caesar:3`), Kasiski n'est meme pas necessaire
4. **Aucune integrite** — un attaquant MITM peut modifier les messages sans detection
5. **Aucune authentification** — n'importe qui peut rejoindre le serveur

---

## Transition vers l'etape 4

Ces faiblesses sont structurelles et ne peuvent pas etre corrigees par une meilleure cle.
La solution est de remplacer ces chiffrements par **AES-256-GCM** :

| Critere | Cesar/Vigenere | AES-256-GCM |
|---------|---------------|-------------|
| Espace de cles | 25 / 456 976 | 2^256 (~10^77) |
| Resistance COA | Nulle | Semantiquement sure |
| Integrite | Non | Oui (tag GCM 128 bits) |
| Standard | Non | Oui (NIST FIPS 197 + 800-38D) |

---

## SAST (Bandit) — Rappel

- B104 medium : `bindall_interfaces` (`0.0.0.0`) toujours present dans `server.py`
- Aucune nouvelle vulnerabilite introduite par le module `cryptanalysis.py`
