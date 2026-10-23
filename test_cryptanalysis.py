
import unittest

from cryptanalysis import (
    caesar_brute_force,
    frequency_analysis,
    index_of_coincidence,
)


class TestCryptanalysis(unittest.TestCase):

    def test_caesar_brute_force(self):
        results = caesar_brute_force("KHOOR")

        self.assertEqual(len(results), 26)
        self.assertEqual(results[3]["plaintext"], "HELLO")

    def test_frequency_analysis(self):
        results = frequency_analysis("AABBC")

        counts = {
            item["letter"]: item["count"]
            for item in results
        }

        self.assertEqual(counts["A"], 2)
        self.assertEqual(counts["B"], 2)
        self.assertEqual(counts["C"], 1)

    def test_frequency_percentages(self):
        results = frequency_analysis("AABC")

        percentages = {
            item["letter"]: item["percentage"]
            for item in results
        }

        self.assertEqual(percentages["A"], 50.0)
        self.assertEqual(percentages["B"], 25.0)
        self.assertEqual(percentages["C"], 25.0)

    def test_index_of_coincidence(self):
        # Four identical letters give IC = 1.
        self.assertAlmostEqual(index_of_coincidence("AAAA"), 1.0)

    def test_short_text_ic(self):
        self.assertEqual(index_of_coincidence("A"), 0.0)


if __name__ == "__main__":
    unittest.main()
