# Rapport d'audit - Etape 6 : RSA-OAEP + Gestion des identites

## Objectif

Resoudre les deux vulnerabilites structurelles de l'etape 4/5 :

1. **La cle AES transmise en clair** → un attaquant MITM la capture et dechiffre tout
2. **Aucune authentification des participants** → un attaquant peut se faire passer pour n'importe qui

La solution est le **chiffrement hybride RSA + AES** :
- RSA pour l'echange de cle (asymetrique, protege contre l'interception)
- AES-GCM pour les messages (symetrique, rapide)

---

## Protocole implementé (Etape 6 — mode "rsa")

### Handshake

```
Serveur → Client : PUBKEY:<rsa_pub_pem_b64>
Client  → Serveur: HANDSHAKE:<rsa_oaep_enc_aes_key_b64>:<client_rsa_pub_pem_b64>
Serveur → Client : OK
```

1. Le serveur genere une paire RSA-2048 au demarrage et envoie sa cle publique
2. Le client genere une cle AES-256 aleatoire + sa propre paire RSA-2048
3. Le client chiffre la cle AES avec la cle publique du serveur (RSA-OAEP)
4. Le client envoie la cle chiffree + sa propre cle publique RSA
5. Le serveur dechiffre la cle AES avec sa cle privee

### Messages

```
Client → Serveur : <aes_gcm_b64>|<rsa_pss_signature_b64>
Serveur           : verifie signature, dechiffre, re-chiffre pour chaque destinataire
Serveur → Client  : <aes_gcm_b64>   (re-chiffre avec la cle de session du destinataire)
```

---

## Choix cryptographiques

| Element          | Algorithme              | Justification |
|------------------|-------------------------|---------------|
| Cles RSA         | RSA-2048                | Minimum recommande NIST |
| Padding RSA      | OAEP / SHA-256          | Probabiliste, resiste aux attaques CCA |
| Signatures       | PSS / SHA-256           | Resistance aux attaques par extension |
| Messages         | AES-256-GCM             | AEAD : confidentialite + integrite |
| Nonce AES        | os.urandom(12)          | 96 bits, unique par message |

### Pourquoi RSA-OAEP et non RSA nu ?

RSA "textbook" (sans padding) est deterministe : chiffrer deux fois le meme message donne
le meme resultat. Un attaquant peut :
- Detecter les messages identiques
- Lancer des attaques "chosen-ciphertext" (CCA)
- Forger des signatures

OAEP ajoute une composante aleatoire et une structure cryptographique qui rend ces
attaques impossibles.

---

## Correction des vulnerabilites de l'etape 4/5

### Vulnerabilite 1 : Cle AES transmise en clair

**Avant (etape 4) :**
```
CIPHER:aesgcm:BASE64_DE_LA_CLE_EN_CLAIR
```
→ Wireshark capture la cle, l'attaquant dechiffre tout le trafic.

**Apres (etape 6) :**
```
HANDSHAKE:RSA_OAEP_CIPHERTEXT:CLIENT_PUBLIC_KEY
```
→ La cle AES est chiffree avec RSA-OAEP. Sans la cle privee du serveur,
  un attaquant ne peut pas recuperer la cle AES.

### Vulnerabilite 2 : Aucune authentification

**Avant (etape 4/5) :**
- N'importe qui peut envoyer n'importe quel message sous n'importe quel nom
- Un MITM peut injecter des faux messages sans detection

**Apres (etape 6) :**
- Chaque client possede une paire RSA
- Chaque message est signe avec la cle privee du client
- Le serveur verifie la signature avant de relayer
- Un message avec une signature invalide est **rejete**

---

## Analyse de securite — Triade CIA

| Pilier | Etape 4 | Etape 6 |
|--------|---------|---------|
| **Confidentialite** | Oui (AES-GCM) mais cle volable | Oui (AES-GCM + cle protegee RSA) |
| **Integrite** | Oui (tag GCM) | Oui (tag GCM + signature RSA-PSS) |
| **Authentification** | Non | Oui (signature RSA-PSS par message) |

---

## Ce que l'attaquant MITM peut encore faire

| Attaque | Statut | Explication |
|---------|--------|-------------|
| Intercepter la cle AES | **IMPOSSIBLE** | Chiffree RSA-OAEP, dechiffrable seulement avec la cle privee du serveur |
| Dechiffrer les messages | **IMPOSSIBLE** | Sans la cle AES, le payload AES-GCM est opaque |
| Injecter un faux message | **IMPOSSIBLE** | Signature RSA-PSS invalide → message rejete par le serveur |
| Usurper l'identite d'un client | **IMPOSSIBLE** | Necessite la cle privee RSA du client |
| Intercepter la cle publique du serveur | Possible | Sans PKI (certificats), le client ne peut pas verifier l'authenticite de la cle publique |

### Vulnerabilite residuelle : absence de PKI

L'etape 6 ne protege pas contre un MITM **actif au moment du premier echange** :
l'attaquant peut substituer SA propre cle publique RSA a celle du serveur.
La solution industrielle est une PKI (certificates X.509, autorites de certification).
Cela depasse le scope de ce projet.

---

## Vulnerabilites Bandit

| Code | Niveau | Description | Statut |
|------|--------|-------------|--------|
| B104 | MEDIUM | `bind("0.0.0.0")` dans `server.py` | Accepte (labo local) |

Aucune alerte introduite par `rsa_oaep.py` ou les modifications du serveur/client.

---

## Comparatif des etapes

| Critere | Etape 1 (clair) | Etape 2 (César) | Etape 4 (AES) | Etape 6 (RSA+AES) |
|---------|-----------------|-----------------|---------------|-------------------|
| Confidentialite | Non | Tres faible | Forte | Forte |
| Integrite | Non | Non | Oui | Oui |
| Authentification | Non | Non | Non | Oui |
| Echange de cle securise | N/A | N/A | Non | Oui |
| Resistance MITM | Non | Non | Non | Oui (partiel) |
