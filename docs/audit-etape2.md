# Rapport d'audit - Etape 2 : Chiffrement symetrique simple

## Chiffrements implementes

### Cesar
- Substitution monoalphabetique : C(x) = (x + k) mod 26
- Espace des cles : 25 valeurs possibles
- **Cassable par force brute en microsecondes**

### Vigenere
- Substitution polyalphabetique : cle repetee cycliquement
- Espace des cles (4 lettres) : 26^4 = 456 976
- **Cassable par analyse statistique (Kasiski + Indice de Coincidence)**

## Analyse de securite

| Critere | Cesar | Vigenere |
|---------|-------|----------|
| Confidentialite | Faible - 25 essais suffisent | Moyenne - cassable statistiquement |
| Integrite | Non | Non |
| Authentification | Non | Non |
| Resistance brute force | Nulle | Faible |

## Vulnerabilites identifiees

1. **Cesar : espace de cles trivial** - 25 cles possibles, brute force instantane
2. **Vigenere : vulnerable a l'analyse de frequence** - Kasiski (1863) retrouve la longueur de cle, puis chaque sous-texte se casse comme un Cesar
3. **Cle transmise en clair** - Le serveur envoie la config CIPHER:type:key au client en TCP, visible dans Wireshark
4. **Pas d'integrite** - Un attaquant peut modifier le chiffre sans detection
5. **Bandit B104** - Binding sur 0.0.0.0 (toutes interfaces)

## Preuve Wireshark

- Les messages sur le reseau sont chiffres (pas lisibles directement)
- MAIS la cle est visible dans le premier paquet (CIPHER:caesar:3)
- Un attaquant peut donc dechiffrer tous les messages

## SAST (Bandit)

- B104: hardcoded_bind_all_interfaces (MEDIUM) - 0.0.0.0 dans server.py
- Pipeline SAST fonctionnel, rapport genere a chaque push

## Remediations prevues

- Etape 3 : Cryptanalyse - prouver les faiblesses en cassant ces chiffrements
- Etape 4 : AES-GCM - chiffrement authentifie, resistant a la cryptanalyse
- Etape 6 : RSA-OAEP - echange de cle securise
