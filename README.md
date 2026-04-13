# LSJkash - Serveur de Communication Chiffre

Serveur de discussion securise en Python avec chiffrement progressif (clair -> Cesar -> Vigenere -> AES-GCM -> RSA-OAEP -> Post-Quantique), dans un environnement DevSecOps complet.

## Equipe et Roles

| Role | Membre | Responsabilites |
|------|--------|-----------------|
| Lead Developer | _A remplir_ | Architecture technique, revues de code, approbation des merge requests |
| Security Officer | _A remplir_ | Configuration scanners CI/CD (Bandit, Safety), rapports d'audit, documentation vulnerabilites |
| Ops | _A remplir_ | Deploiement Docker, docker-compose, maintenance infrastructure, documentation exploitation |
| Project Manager | _A remplir_ | Suivi planning, gestion issues Gitea, point de contact intervenant, compte-rendu checkpoints |

## Structure du projet

```
LSJkash/
├── server/            # Code du serveur TCP
├── client/            # Code du client TCP
├── docs/              # Rapports d'audit et documentation
├── .gitea/workflows/  # Pipelines CI/CD
├── docker-compose.yml # Infrastructure Gitea + Act Runner
├── requirements.txt   # Dependances Python
└── README.md
```

## Prerequis

- Docker + Docker Compose
- Python 3.12+
- Wireshark (pour les captures reseau)

## Lancement de l'infrastructure

```bash
# 1. Demarrer Gitea + Act Runner
docker compose up -d

# 2. Acceder a Gitea
# http://localhost:3000
# Creer un compte admin lors du premier acces

# 3. Enregistrer le runner
# Administration > Runners > Creer un token
# Copier le token dans la variable RUNNER_TOKEN
RUNNER_TOKEN=<votre_token> docker compose up -d act-runner
```

## Lancement du serveur de discussion

```bash
# Installer les dependances
pip install -r requirements.txt

# Lancer le serveur
python server/server.py

# Lancer un client (dans un autre terminal)
python client/client.py
```

## Etapes du projet

- [x] Etape 0 : Infrastructure DevSecOps (Gitea + Docker + CI/CD)
- [ ] Etape 1 : Communication TCP en clair
- [ ] Etape 2 : Chiffrement Cesar + Vigenere
- [ ] Etape 3 : Cryptanalyse
- [ ] Etape 4 : AES-GCM + echange de cle
- [ ] Etape 5 : Attaque MITM
- [ ] Etape 6 : RSA-OAEP + signatures numeriques
- [ ] Etape 7 : Automatisation CI/CD complete
- [ ] Bonus  : Chiffrement post-quantique (ML-KEM / Kyber)
