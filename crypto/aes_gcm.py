"""AES-GCM helpers - Etape 4."""

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def _validate_key(key: bytes) -> None:
    """Valide qu'une cle AES-256 a bien 32 octets."""
    if len(key) != KEY_SIZE:
        raise ValueError("La cle AES-GCM doit contenir 32 octets.")


def generate_key() -> bytes:
    """Genere une cle AES-256 aleatoire."""
    return AESGCM.generate_key(bit_length=256)


def export_key(key: bytes) -> str:
    """Encode une cle AES-256 en base64 ASCII pour l'echange TCP."""
    _validate_key(key)
    return base64.b64encode(key).decode("ascii")


def import_key(encoded_key: str) -> bytes:
    """Decode une cle AES-256 recue en base64 ASCII."""
    try:
        key = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("Cle AES-GCM invalide.") from exc
    _validate_key(key)
    return key


def encrypt_message(plaintext: str, key: bytes) -> str:
    """Chiffre un message UTF-8 avec AES-256-GCM.

    Format retourne : base64(nonce || ciphertext || tag)
    """
    _validate_key(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_message(payload: str, key: bytes) -> str:
    """Dechiffre un payload base64(nonce || ciphertext || tag)."""
    _validate_key(key)
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("Payload AES-GCM invalide.") from exc

    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Payload AES-GCM trop court.")

    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Authentification AES-GCM invalide.") from exc
    return plaintext.decode("utf-8")
