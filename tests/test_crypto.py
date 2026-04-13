"""Tests pour les chiffrements Cesar et Vigenere."""

from crypto.caesar import caesar_encrypt, caesar_decrypt
from crypto.vigenere import vigenere_encrypt, vigenere_decrypt


class TestCaesar:
    def test_encrypt_basic(self):
        assert caesar_encrypt("BONJOUR", 3) == "ERQMRXU"

    def test_decrypt_basic(self):
        assert caesar_decrypt("ERQMRXU", 3) == "BONJOUR"

    def test_roundtrip(self):
        for k in range(1, 26):
            assert caesar_decrypt(caesar_encrypt("Hello World!", k), k) == "Hello World!"

    def test_non_alpha_preserved(self):
        assert caesar_encrypt("Hello, World! 123", 5) == "Mjqqt, Btwqi! 123"

    def test_key_zero(self):
        assert caesar_encrypt("ABC", 0) == "ABC"

    def test_wrap_around(self):
        assert caesar_encrypt("XYZ", 3) == "ABC"


class TestVigenere:
    def test_encrypt_basic(self):
        enc = vigenere_encrypt("BONJOUR", "CLE")
        assert vigenere_decrypt(enc, "CLE") == "BONJOUR"

    def test_roundtrip(self):
        msg = "Hello World!"
        for key in ["SECRET", "A", "ABCDEFG"]:
            assert vigenere_decrypt(vigenere_encrypt(msg, key), key) == msg

    def test_non_alpha_preserved(self):
        enc = vigenere_encrypt("Test 123!", "KEY")
        dec = vigenere_decrypt(enc, "KEY")
        assert dec == "Test 123!"

    def test_key_a_is_identity(self):
        assert vigenere_encrypt("HELLO", "A") == "HELLO"

    def test_case_preserved(self):
        enc = vigenere_encrypt("aBcDeF", "KEY")
        dec = vigenere_decrypt(enc, "KEY")
        assert dec == "aBcDeF"
