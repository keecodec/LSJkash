"""RSA-OAEP + Signatures numeriques - Etape 6.

Chiffrement hybride RSA + AES :
  1. Le serveur genere une paire RSA-2048 et partage sa cle publique (PEM)
  2. Le client genere une cle AES-256 aleatoire + sa propre paire RSA
  3. Le client chiffre la cle AES avec la cle publique RSA du serveur (OAEP)
  4. Le serveur dechiffre avec sa cle privee -> obtient la cle de session
  5. Les messages utilisent AES-GCM avec cette cle + signatures PSS

Regles :
  - Toujours RSA-OAEP, jamais RSA nu (textbook RSA est vulnerable)
  - Signatures : PSS avec SHA-256 (resistance aux attaques par extension)
  - Cle RSA : 2048 bits minimum
"""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_key_pair():
    """Genere une paire de cles RSA-2048.

    Returns:
        (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def export_public_key(public_key) -> str:
    """Serialise une cle publique RSA en PEM encode base64 ASCII (pour envoi TCP)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("ascii")


def import_public_key(encoded: str):
    """Deserialise une cle publique RSA depuis PEM encode base64 ASCII."""
    pem = base64.b64decode(encoded.encode("ascii"))
    return serialization.load_pem_public_key(pem)


def encrypt_with_public_key(public_key, plaintext: bytes) -> str:
    """Chiffre des donnees avec la cle publique RSA (RSA-OAEP / SHA-256).

    Utilise pour chiffrer la cle de session AES (32 octets) cote client.
    Retourne le ciphertext encode en base64 ASCII.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_with_private_key(private_key, encoded: str) -> bytes:
    """Dechiffre un ciphertext RSA-OAEP avec la cle privee.

    Utilise cote serveur pour recuperer la cle de session AES.
    """
    ciphertext = base64.b64decode(encoded.encode("ascii"))
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_message(private_key, message: bytes) -> str:
    """Signe un message avec la cle privee RSA (RSA-PSS / SHA-256).

    Permet au destinataire de verifier l'identite de l'emetteur.
    Retourne la signature encodee en base64 ASCII.
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_signature(public_key, message: bytes, signature_b64: str) -> bool:
    """Verifie une signature RSA-PSS avec la cle publique de l'emetteur.

    Returns:
        True si la signature est valide, False sinon.
    """
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"))
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, Exception):
        return False
