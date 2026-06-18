import unittest
import string
from generator import generate_password, generate_passphrase, AMBIGUOUS_CHARS, SYMBOLS

class TestGenerator(unittest.TestCase):
    def test_generate_password_defaults(self):
        """Test password generation with default settings."""
        password = generate_password()
        self.assertEqual(len(password), 16)
        
        # Verify it has at least one of each class
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in SYMBOLS for c in password))

    def test_generate_password_length(self):
        """Test custom length limits and values."""
        for length in [4, 8, 20, 100]:
            password = generate_password(length=length)
            self.assertEqual(len(password), length)

    def test_generate_password_invalid_lengths(self):
        """Test that invalid lengths raise errors."""
        with self.assertRaises(ValueError):
            generate_password(length=3)
        with self.assertRaises(ValueError):
            # Length less than enabled character pools (4 pools)
            generate_password(length=3, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)

    def test_generate_password_no_pools(self):
        """Test that enabling no pools raises a ValueError."""
        with self.assertRaises(ValueError):
            generate_password(use_upper=False, use_lower=False, use_digits=False, use_symbols=False)

    def test_generate_password_specific_pools(self):
        """Test generation using only subset of pools."""
        password = generate_password(length=10, use_upper=False, use_lower=True, use_digits=False, use_symbols=False)
        self.assertEqual(len(password), 10)
        self.assertTrue(password.islower())
        self.assertTrue(password.isalpha())

        password_digits = generate_password(length=10, use_upper=False, use_lower=False, use_digits=True, use_symbols=False)
        self.assertTrue(password_digits.isdigit())

    def test_generate_password_exclude_ambiguous(self):
        """Test exclusion of ambiguous characters."""
        # Run multiple times to verify statistical occurrence doesn't sneak ambiguous chars in
        for _ in range(50):
            password = generate_password(
                length=30,
                exclude_ambiguous=True,
            )
            for char in AMBIGUOUS_CHARS:
                self.assertNotIn(char, password)

    def test_generate_passphrase_defaults(self):
        """Test passphrase generation defaults."""
        passphrase = generate_passphrase()
        words = passphrase.split("-")
        self.assertEqual(len(words), 4)
        for w in words:
            self.assertTrue(len(w) > 0)

    def test_generate_passphrase_custom(self):
        """Test passphrase generation with custom word count and separator."""
        custom_words = ["apple", "banana", "cherry", "date", "elderberry"]
        passphrase = generate_passphrase(num_words=3, separator="*", word_list=custom_words)
        words = passphrase.split("*")
        self.assertEqual(len(words), 3)
        for w in words:
            self.assertIn(w, custom_words)

    def test_generate_passphrase_invalid_words(self):
        """Test passphrase raises error when less than 3 words are requested."""
        with self.assertRaises(ValueError):
            generate_passphrase(num_words=2)

if __name__ == "__main__":
    unittest.main()
