# Rapport d'audit - Etape 5 : Attaque Man-in-the-Middle (MITM)

## Objectif

Demontrer que le chiffrement AES-GCM (etape 4) ne suffit pas sans authentification.
Un attaquant positionne entre le client et le serveur intercepte la cle AES
et obtient un acces complet aux communications.

## Vulnerabilite exploitee

La cle AES-256 est transmise en clair via TCP lors du handshake :
```
CIPHER:aesgcm:<cle_base64>
```
Aucune authentification des participants (pas de certificat, pas de signature).

## Architecture de l'attaque

```
Client (port 5001) <---> MITM Proxy <---> Serveur (port 5000)
```

Le proxy MITM :
1. Ecoute sur le port 5001
2. A chaque connexion client, ouvre un tunnel vers le vrai serveur (port 5000)
3. Intercepte le paquet `CIPHER:aesgcm:<key>` -> vole la cle AES-256
4. Relaye tout le trafic en le dechiffrant au passage

## Capacites de l'attaquant

| Capacite | Statut | Description |
|----------|--------|-------------|
| Lecture des messages | OUI | Dechiffrement en temps reel avec la cle volee |
| Modification de messages | OUI | Dechiffre, modifie, re-chiffre avec la meme cle |
| Injection de messages | OUI | Forge des messages avec pseudo usurpe |
| Replay attack | OUI | Rejoue des messages captures precedemment |
| Vol de la cle AES | OUI | Cle en clair dans le handshake TCP |

## Resultats des tests

| Test | Resultat |
|------|----------|
| Interception cle AES-256 | Cle volee au premier paquet |
| Dechiffrement C->S | Messages lisibles en clair |
| Dechiffrement S->C | Messages lisibles en clair |
| Injection faux message | Recu par le vrai client comme message legitime |
| Usurpation de pseudo | Le client ne peut pas distinguer un vrai message d'un faux |

## Chiffrement vs Authentification

| | Chiffrement | Authentification |
|---|---|---|
| **Fonction** | Confidentialite - personne ne peut LIRE | Authenticite - on sait QUI a envoye |
| **AES-GCM seul** | OUI | NON |
| **Avec RSA (etape 6)** | OUI | OUI |

**Conclusion** : Le chiffrement protege contre l'ecoute passive, mais pas contre un attaquant actif.
Sans authentification, l'attaquant s'interpose et negocie des cles separees avec chaque partie.

## Remediations (Etape 6)

- **RSA-OAEP** : le client chiffre la cle AES avec la cle publique du serveur
- **Signatures numeriques** : chaque message est signe avec la cle privee de l'emetteur
- **Echange de cle authentifie** : la cle publique est verifiee avant l'echange
- Meme si l'attaquant intercepte le traffic, il ne peut pas dechiffrer la cle AES
  car il n'a pas la cle privee RSA correspondante
