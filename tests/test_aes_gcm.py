"""Tests AES-GCM - Etape 4."""

import base64

import pytest

from crypto.aes_gcm import (
    KEY_SIZE,
    decrypt_message,
    encrypt_message,
    export_key,
    generate_key,
    import_key,
)


class TestAESGCM:
    def test_generate_key_length(self):
        key = generate_key()
        assert isinstance(key, bytes)
        assert len(key) == KEY_SIZE

    def test_roundtrip(self):
        key = generate_key()
        plaintext = "Bonjour LSJkash"
        payload = encrypt_message(plaintext, key)
        assert decrypt_message(payload, key) == plaintext

    def test_same_message_twice_gives_different_ciphertexts(self):
        key = generate_key()
        plaintext = "message identique"
        payload1 = encrypt_message(plaintext, key)
        payload2 = encrypt_message(plaintext, key)
        assert payload1 != payload2
        assert decrypt_message(payload1, key) == plaintext
        assert decrypt_message(payload2, key) == plaintext

    def test_tampering_is_detected(self):
        key = generate_key()
        payload = encrypt_message("integrite", key)
        raw = bytearray(base64.b64decode(payload.encode("ascii")))
        raw[-1] ^= 0x01
        forged = base64.b64encode(bytes(raw)).decode("ascii")

        with pytest.raises(ValueError, match="Authentification AES-GCM invalide"):
            decrypt_message(forged, key)

    def test_key_exchange_roundtrip(self):
        key = generate_key()
        exported = export_key(key)
        imported = import_key(exported)
        assert imported == key

    def test_invalid_key_size_is_rejected(self):
        with pytest.raises(ValueError, match="32 octets"):
            export_key(b"trop-court")

    def test_invalid_payload_is_rejected(self):
        key = generate_key()
        with pytest.raises(ValueError):
            decrypt_message("not-base64", key)
