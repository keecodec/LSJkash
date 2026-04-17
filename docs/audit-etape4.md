# Rapport d'audit - Etape 4 : AES-GCM + Echange de cle

## Objectif

Remplacer Cesar et Vigenere par un chiffrement symetrique moderne, standardise et authentifie.
L'etape 4 introduit **AES-256-GCM** avec :

- confidentialite du contenu
- integrite des messages via le tag GCM
- nonce aleatoire de 96 bits (`os.urandom(12)`) par message
- echange de cle de session entre le serveur et les clients a la connexion

---

## Choix technique

### Algorithme retenu

- **AES-256-GCM**
- Standard NIST
- Mode **AEAD** : confidentialite + integrite

### Format d'un message

- `nonce` : 12 octets aleatoires
- `ciphertext || tag` : resultat de `AESGCM.encrypt(...)`
- transport TCP : `base64(nonce || ciphertext || tag)`

### Echange de cle

- Le serveur genere une **cle AES-256 de session** au demarrage
- La cle est envoyee au client lors du handshake initial
- Encodage de la cle : base64 ASCII

---

## Proprietes de securite obtenues

| Critere | Cesar / Vigenere | AES-256-GCM |
|---------|------------------|-------------|
| Confidentialite | Tres faible | Forte |
| Integrite | Non | Oui |
| Authentification du message | Non | Oui via tag GCM |
| Resistance a la cryptanalyse classique | Nulle / faible | Forte |
| Standard industriel | Non | Oui |

---

## Points critiques verifies

### Nonce unique par message

- nonce genere par `os.urandom(12)`
- un nouveau nonce est cree a chaque chiffrement
- deux messages identiques avec la meme cle produisent donc des chiffrés differents

### Detection de modification

- toute alteration du payload provoque un echec d'authentification
- le message modifie est rejete
- le serveur ne rebroadcast pas un message dont le tag GCM est invalide

---

## Vulnerabilites restantes

1. **Cle de session transmise sans protection**
   - la cle AES est envoyee au client dans le handshake TCP
   - un attaquant sur le reseau peut recuperer cette cle

2. **Pas d'authentification des pairs**
   - le client ne verifie pas qu'il parle au bon serveur
   - le serveur n'authentifie pas les clients

3. **MITM toujours possible**
   - un attaquant peut intercepter la cle de session pendant l'echange initial
   - il peut ensuite dechiffrer, modifier, rechiffrer et relayer le trafic

4. **Binding sur 0.0.0.0**
   - Bandit remonte toujours `B104`
   - acceptable pour un labo local, a encadrer en production

---

## Preuve attendue dans Wireshark

- les messages applicatifs ne sont plus lisibles en clair
- le payload contient un bloc base64 representant `nonce || ciphertext || tag`
- la cle de session reste visible dans le premier paquet de configuration

---

## Conclusion

L'etape 4 corrige les faiblesses cryptographiques de Cesar et Vigenere sur la **confidentialite**
et surtout sur **l'integrite**. En revanche, l'echange de cle reste non securise.

La prochaine etape logique est donc l'**attaque MITM** pour demontrer que :

- un bon chiffrement ne suffit pas
- sans authentification, la securite globale reste cassable
