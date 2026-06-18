import unittest
from strength import check_strength, estimate_entropy, has_sequential_chars, has_repeated_chars

class TestStrength(unittest.TestCase):
    def test_estimate_entropy(self):
        """Test entropy estimation ranges."""
        self.assertEqual(estimate_entropy(""), 0.0)
        self.assertEqual(estimate_entropy("a"), 4.700439718141092) # 1 * log2(26)
        
        # Test character classes pool size combination
        # lowercase only: 26 pool
        entropy_low = estimate_entropy("abcdef")
        # lowercase + uppercase: 52 pool
        entropy_mix = estimate_entropy("abcDEF")
        self.assertGreater(entropy_mix, entropy_low)

    def test_has_sequential_chars(self):
        """Test detection of sequential character runs."""
        self.assertTrue(has_sequential_chars("abc"))
        self.assertTrue(has_sequential_chars("123"))
        self.assertTrue(has_sequential_chars("XYZ"))
        self.assertTrue(has_sequential_chars("aBC")) # case-insensitive
        
        self.assertFalse(has_sequential_chars("axc"))
        self.assertFalse(has_sequential_chars("135"))

    def test_has_repeated_chars(self):
        """Test detection of repeated character runs."""
        self.assertTrue(has_repeated_chars("aaa"))
        self.assertTrue(has_repeated_chars("111"))
        self.assertTrue(has_repeated_chars("abc111xyz"))
        
        self.assertFalse(has_repeated_chars("aab"))
        self.assertFalse(has_repeated_chars("121"))

    def test_check_strength_empty(self):
        """Test check_strength with empty input."""
        res = check_strength("")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["label"], "Very Weak")
        self.assertIn("Password is empty.", res["feedback"])

    def test_check_strength_very_weak(self):
        """Test common or too short passwords."""
        # Common password
        res = check_strength("password")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["label"], "Very Weak")
        self.assertIn("This is a commonly used password — easily guessable.", res["feedback"])

        # Too short password
        res = check_strength("abc")
        self.assertEqual(res["score"], 0)
        self.assertIn("Too short — use at least 12 characters.", res["feedback"])

    def test_check_strength_feedback_requirements(self):
        """Test missing character class feedback prompts."""
        # Missing numbers and symbols, but long enough
        res = check_strength("abcdefghijkl")
        self.assertIn("Add numbers.", res["feedback"])
        self.assertIn("Add symbols.", res["feedback"])
        self.assertIn("Add uppercase letters.", res["feedback"])

    def test_check_strength_excellent(self):
        """Test a strong, robust password."""
        # 16-char mix of uppercase, lowercase, numbers, and symbols with no sequences or repetitions
        res = check_strength("P@ssw0rd12984Xv!")
        self.assertGreaterEqual(res["score"], 5)
        # Note: Depending on score logic, it might have "Strong password — no issues detected." or similar feedback
        self.assertTrue(any("Strong" in label or "Excellent" in label or "Very Strong" in label for label in [res["label"]]))

if __name__ == "__main__":
    unittest.main()
