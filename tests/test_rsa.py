"""Tests pour RSA-OAEP et signatures numeriques - Etape 6."""

import pytest
from crypto.aes_gcm import generate_key
from crypto.rsa_oaep import (
    decrypt_with_private_key,
    encrypt_with_public_key,
    export_public_key,
    generate_key_pair,
    import_public_key,
    sign_message,
    verify_signature,
)


class TestRSAKeyGeneration:
    def test_generate_key_pair_returns_two_objects(self):
        priv, pub = generate_key_pair()
        assert priv is not None
        assert pub is not None

    def test_public_key_differs_from_private(self):
        priv, pub = generate_key_pair()
        assert priv is not pub

    def test_two_key_pairs_are_different(self):
        _, pub1 = generate_key_pair()
        _, pub2 = generate_key_pair()
        assert export_public_key(pub1) != export_public_key(pub2)


class TestPublicKeySerialisation:
    def test_export_import_roundtrip(self):
        _, pub = generate_key_pair()
        encoded = export_public_key(pub)
        recovered = import_public_key(encoded)
        assert export_public_key(recovered) == encoded

    def test_export_is_ascii_string(self):
        _, pub = generate_key_pair()
        encoded = export_public_key(pub)
        assert isinstance(encoded, str)
        encoded.encode("ascii")  # ne doit pas lever

    def test_import_invalid_raises(self):
        with pytest.raises(Exception):
            import_public_key("ceci_nest_pas_une_cle")


class TestRSAOAEP:
    def test_encrypt_decrypt_roundtrip(self):
        priv, pub = generate_key_pair()
        plaintext = b"cle AES super secrete de 32 o!!!"
        encrypted = encrypt_with_public_key(pub, plaintext)
        decrypted = decrypt_with_private_key(priv, encrypted)
        assert decrypted == plaintext

    def test_encrypt_aes_key_roundtrip(self):
        """Cas reel : chiffrer une cle AES-256 de 32 octets."""
        priv, pub = generate_key_pair()
        aes_key = generate_key()
        assert len(aes_key) == 32
        enc = encrypt_with_public_key(pub, aes_key)
        dec = decrypt_with_private_key(priv, enc)
        assert dec == aes_key

    def test_wrong_private_key_raises(self):
        priv1, pub1 = generate_key_pair()
        priv2, _ = generate_key_pair()
        encrypted = encrypt_with_public_key(pub1, b"secret")
        with pytest.raises(Exception):
            decrypt_with_private_key(priv2, encrypted)

    def test_encrypt_produces_base64(self):
        _, pub = generate_key_pair()
        enc = encrypt_with_public_key(pub, b"test")
        assert isinstance(enc, str)
        import base64
        base64.b64decode(enc)  # ne doit pas lever

    def test_same_plaintext_different_ciphertexts(self):
        """OAEP est probabiliste : deux chiffrements du meme texte different."""
        _, pub = generate_key_pair()
        plaintext = b"meme texte"
        enc1 = encrypt_with_public_key(pub, plaintext)
        enc2 = encrypt_with_public_key(pub, plaintext)
        assert enc1 != enc2


class TestRSASignatures:
    def test_sign_verify_valid(self):
        priv, pub = generate_key_pair()
        message = b"message authentique"
        sig = sign_message(priv, message)
        assert verify_signature(pub, message, sig) is True

    def test_wrong_public_key_fails(self):
        priv, _ = generate_key_pair()
        _, pub2 = generate_key_pair()
        message = b"message authentique"
        sig = sign_message(priv, message)
        assert verify_signature(pub2, message, sig) is False

    def test_altered_message_fails(self):
        priv, pub = generate_key_pair()
        message = b"message original"
        sig = sign_message(priv, message)
        assert verify_signature(pub, b"message modifie", sig) is False

    def test_altered_signature_fails(self):
        priv, pub = generate_key_pair()
        message = b"message"
        sig = sign_message(priv, message)
        bad_sig = sig[:-4] + "AAAA"
        assert verify_signature(pub, message, bad_sig) is False

    def test_sign_returns_base64(self):
        priv, _ = generate_key_pair()
        sig = sign_message(priv, b"test")
        assert isinstance(sig, str)
        import base64
        base64.b64decode(sig)  # ne doit pas lever

    def test_empty_message(self):
        priv, pub = generate_key_pair()
        sig = sign_message(priv, b"")
        assert verify_signature(pub, b"", sig) is True


class TestFullHandshakeSimulation:
    def test_full_key_exchange(self):
        """Simule l'echange complet : serveur genere RSA, client envoie cle AES chiffree."""
        # Serveur genere sa paire RSA
        server_priv, server_pub = generate_key_pair()

        # Client : genere sa cle AES de session
        session_key = generate_key()

        # Client : chiffre la cle AES avec la cle publique du serveur
        enc_session_key = encrypt_with_public_key(server_pub, session_key)

        # Serveur : dechiffre la cle de session
        recovered_key = decrypt_with_private_key(server_priv, enc_session_key)

        assert recovered_key == session_key

    def test_signed_message_workflow(self):
        """Simule l'envoi d'un message signe et sa verification."""
        from crypto.aes_gcm import decrypt_message, encrypt_message

        # Client genere sa paire RSA
        client_priv, client_pub = generate_key_pair()

        # Cle de session partagee (obtenue via OAEP)
        session_key = generate_key()

        # Client : chiffre + signe un message
        plaintext = "Bonjour depuis le client"
        cipher_b64 = encrypt_message(plaintext, session_key)
        sig_b64 = sign_message(client_priv, cipher_b64.encode())

        # Serveur : verifie la signature
        assert verify_signature(client_pub, cipher_b64.encode(), sig_b64) is True

        # Serveur : dechiffre
        recovered = decrypt_message(cipher_b64, session_key)
        assert recovered == plaintext

    def test_mitm_cannot_decrypt_session_key(self):
        """Un attaquant MITM sans la cle privee du serveur ne peut pas recuperer la cle AES."""
        server_priv, server_pub = generate_key_pair()
        attacker_priv, _ = generate_key_pair()

        session_key = generate_key()
        enc_session_key = encrypt_with_public_key(server_pub, session_key)

        # L'attaquant tente de dechiffrer avec SA propre cle privee
        with pytest.raises(Exception):
            decrypt_with_private_key(attacker_priv, enc_session_key)
