
import unittest

from ciphers import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
    rail_fence_encrypt,
    rail_fence_decrypt,
    columnar_encrypt,
    columnar_decrypt,
    substitution_encrypt,
    substitution_decrypt,
    playfair_encrypt,
    playfair_decrypt,
    hill_encrypt,
    hill_decrypt,
)


class TestClassicalCiphers(unittest.TestCase):

    def test_caesar(self):
        text = "HELLO WORLD"
        encrypted = caesar_encrypt(text, 3)

        self.assertEqual(encrypted, "KHOOR ZRUOG")
        self.assertEqual(caesar_decrypt(encrypted, 3), text)

    def test_vigenere(self):
        text = "ATTACKATDAWN"
        encrypted = vigenere_encrypt(text, "LEMON")

        self.assertEqual(encrypted, "LXFOPVEFRNHR")
        self.assertEqual(vigenere_decrypt(encrypted, "LEMON"), text)

    def test_rail_fence(self):
        text = "WEAREDISCOVERED"
        encrypted = rail_fence_encrypt(text, 3)

        self.assertEqual(rail_fence_decrypt(encrypted, 3), text)

    def test_columnar(self):
        text = "WEAREDISCOVERED"
        encrypted = columnar_encrypt(text, "ZEBRA")

        self.assertEqual(columnar_decrypt(encrypted, "ZEBRA"), text)

    def test_substitution(self):
        text = "HELLO WORLD"
        key = "QWERTYUIOPASDFGHJKLZXCVBNM"

        encrypted = substitution_encrypt(text, key)

        self.assertEqual(
            substitution_decrypt(encrypted, key),
            text
        )

    def test_substitution_invalid_key(self):
        with self.assertRaises(ValueError):
            substitution_encrypt("HELLO", "ABC")

    def test_playfair(self):
        # Playfair combines I and J and may insert filler X.
        text = "HIDETHEGOLD"
        key = "MONARCHY"

        encrypted = playfair_encrypt(text, key)
        decrypted = playfair_decrypt(encrypted, key)

        self.assertEqual(encrypted, "BFCKPDFIMPBZ")
        self.assertEqual(decrypted, "HIDETHEGOLD")

    def test_playfair_repeated_letters(self):
        text = "BALLOON"
        key = "MONARCHY"

        encrypted = playfair_encrypt(text, key)
        decrypted = playfair_decrypt(encrypted, key)

        # Filler letters may remain after decryption.
        self.assertTrue(decrypted.startswith("BALXLOON"))

    def test_hill(self):
        text = "HELP"
        key = "3,3,2,5"

        encrypted = hill_encrypt(text, key)

        self.assertEqual(
            hill_decrypt(encrypted, key),
            text
        )

    def test_hill_padding(self):
        text = "CAT"
        key = "3,3,2,5"

        encrypted = hill_encrypt(text, key)
        decrypted = hill_decrypt(encrypted, key)

        self.assertEqual(decrypted, "CATX")

    def test_hill_invalid_key(self):
        with self.assertRaises(ValueError):
            hill_encrypt("HELLO", "2,4,2,4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
