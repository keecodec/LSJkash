# Rapport d'audit - Etape 1 : Communication TCP en clair

## Architecture

- Serveur TCP multi-thread sur port 5000
- Broadcast des messages a tous les clients connectes
- Protocole : TCP (fiabilite de livraison, ordre garanti)

## Analyse de securite - Triade CIA

| Pilier | Statut | Constat |
|--------|--------|---------|
| Confidentialite | ECHOUE | Messages visibles en clair dans Wireshark (Follow TCP Stream) |
| Integrite | ECHOUE | Aucun mecanisme de verification, un attaquant peut modifier les paquets |
| Disponibilite | ECHOUE | Aucune protection contre le flooding ou la deconnexion forcee |

## Vulnerabilites identifiees

1. **Ecoute passive (sniffing)** - Tout utilisateur sur le meme reseau peut lire les messages avec Wireshark
2. **Injection de messages** - Rien n'empeche un attaquant d'envoyer des messages au serveur en se faisant passer pour un autre
3. **Pas d'authentification** - N'importe qui peut se connecter au serveur
4. **Binding sur 0.0.0.0** (Bandit B104) - Le serveur ecoute sur toutes les interfaces

## Preuve Wireshark

- Filtre utilise : `tcp.port == 5000`
- Capture sur interface loopback (tcpdump -i lo)
- Follow TCP Stream : messages lisibles en clair

## Remediations prevues

- Etape 2 : Chiffrement symetrique (Cesar, Vigenere) - protection basique
- Etape 4 : AES-GCM - chiffrement authentifie (confidentialite + integrite)
- Etape 6 : RSA-OAEP - authentification des participants
