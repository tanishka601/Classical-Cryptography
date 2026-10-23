
from collections import Counter
import string
import re

from ciphers import caesar_decrypt

ALPHABET = string.ascii_uppercase


def caesar_brute_force(ciphertext):
    """Return all 26 possible Caesar decryptions."""
    results = []

    for shift in range(26):
        plaintext = caesar_decrypt(ciphertext, shift)
        results.append({
            "shift": shift,
            "plaintext": plaintext
        })

    return results


def frequency_analysis(text):
    """Count English letters and calculate their percentages."""
    letters = [
        char.upper()
        for char in text
        if char.upper() in ALPHABET
    ]

    counts = Counter(letters)
    total = len(letters)

    results = []

    for letter in ALPHABET:
        count = counts.get(letter, 0)
        percentage = (count / total * 100) if total else 0

        results.append({
            "letter": letter,
            "count": count,
            "percentage": round(percentage, 2)
        })

    return results


def index_of_coincidence(text):
    """Calculate the index of coincidence for alphabetic text."""
    letters = [
        char.upper()
        for char in text
        if char.upper() in ALPHABET
    ]

    n = len(letters)

    if n < 2:
        return 0.0

    counts = Counter(letters)

    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return numerator / denominator

def vigenere_key_length_analysis(ciphertext, max_key_length=16):
    """
    Estimate possible Vigenere key lengths using average
    Index of Coincidence (IC).

    Higher average IC values can indicate a more likely key length.
    """
    letters = [
        char.upper()
        for char in ciphertext
        if char.upper() in ALPHABET
    ]

    results = []

    if len(letters) < 2:
        return results

    max_key_length = min(max(1, max_key_length), len(letters) // 2)

    for key_length in range(1, max_key_length + 1):
        groups = [
            letters[i::key_length]
            for i in range(key_length)
        ]

        valid_ics = [
            index_of_coincidence("".join(group))
            for group in groups
            if len(group) >= 2
        ]

        average_ic = (
            sum(valid_ics) / len(valid_ics)
            if valid_ics else 0.0
        )

        results.append({
            "key_length": key_length,
            "average_ic": round(average_ic, 4)
        })

    # Rank the most promising lengths first.
    results.sort(key=lambda item: item["average_ic"], reverse=True)

    return results

# =====================================================
# PLAYFAIR KEY-SEARCH ATTACK
# =====================================================

def _playfair_english_score(text):
    """Give candidate plaintexts a simple English-likeness score."""
    text = "".join(
        char for char in text.upper()
        if char in ALPHABET
    )

    if not text:
        return float("-inf")

    # Common English letter pairs and patterns.
    common_patterns = [
        "TH", "HE", "IN", "ER", "AN", "RE", "ON",
        "AT", "EN", "ND", "TI", "ES", "OR", "TE",
        "OF", "ED", "IS", "IT", "AL", "AR", "ST",
        "TO", "NT", "NG", "SE", "HA", "AS", "OU",
        "EA", "HI", "VE", "CO", "ME", "DE", "HI"
    ]

    score = sum(text.count(pair) for pair in common_patterns)

    common_trigrams = [
        "THE", "AND", "ING", "HER", "ERE", "ENT",
        "THA", "NTH", "WAS", "ETH", "FOR", "DTH"
    ]

    score += 3 * sum(
        text.count(pattern) for pattern in common_trigrams
    )

    common_words = [
        "THE", "AND", "THAT", "HAVE", "FOR", "NOT",
        "WITH", "YOU", "THIS", "FROM", "ARE", "WAS",
        "BEFORE", "AFTER", "HELLO", "WORLD"
    ]

    score += 5 * sum(
        len(re.findall(rf"(?<![A-Z]){word}(?![A-Z])", text))
        for word in common_words
    )

    # Penalize uncommon Playfair letter combinations slightly.
    score -= 2 * text.count("Q")

    return score


def playfair_key_search(ciphertext, candidate_keys):
    """
    Try candidate Playfair keywords and rank decrypted results.

    candidate_keys: list of possible keywords.
    Requires playfair_decrypt from ciphers.py.
    """
    from ciphers import playfair_decrypt

    results = []
    seen_keys = set()

    for key in candidate_keys:
        key = key.strip()

        if not key:
            continue

        normalized_key = "".join(
            char for char in key.upper()
            if char in ALPHABET
        ).replace("J", "I")

        if not normalized_key or normalized_key in seen_keys:
            continue

        seen_keys.add(normalized_key)

        try:
            plaintext = playfair_decrypt(ciphertext, key)
            score = _playfair_english_score(plaintext)

            results.append({
                "candidate_key": key,
                "score": score,
                "plaintext": plaintext
            })

        except Exception as error:
            results.append({
                "candidate_key": key,
                "score": float("-inf"),
                "plaintext": f"Decryption error: {error}"
            })

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return results

# =====================================================
# HILL CIPHER KNOWN-PLAINTEXT ANALYSIS (2x2)
# =====================================================

def hill_cipher_analysis(plaintext, ciphertext):
    """
    Recover a 2x2 Hill cipher key from known plaintext
    and matching ciphertext.

    Uses the convention:
        C = K * P (mod 26)

    Letters are mapped A=0, B=1, ..., Z=25.
    The plaintext matrix must be invertible modulo 26.
    """

    def clean_text(text):
        return "".join(
            char.upper()
            for char in text
            if char.isascii() and char.isalpha()
        )

    def mod_inverse(value, modulus=26):
        value %= modulus

        for candidate in range(1, modulus):
            if (value * candidate) % modulus == 1:
                return candidate

        return None

    plaintext = clean_text(plaintext)
    ciphertext = clean_text(ciphertext)

    if len(plaintext) != len(ciphertext):
        return {
            "success": False,
            "message": "Plaintext and ciphertext lengths must match."
        }

    if len(plaintext) < 4 or len(plaintext) % 2 != 0:
        return {
            "success": False,
            "message": (
                "Provide at least four matching letters, "
                "with an even number of letters."
            )
        }

    # Use the first two plaintext blocks to form P.
    p0 = ord(plaintext[0]) - ord("A")
    p1 = ord(plaintext[1]) - ord("A")
    p2 = ord(plaintext[2]) - ord("A")
    p3 = ord(plaintext[3]) - ord("A")

    c0 = ord(ciphertext[0]) - ord("A")
    c1 = ord(ciphertext[1]) - ord("A")
    c2 = ord(ciphertext[2]) - ord("A")
    c3 = ord(ciphertext[3]) - ord("A")

    # Matrix columns are plaintext/ciphertext blocks.
    p_matrix = [[p0, p2], [p1, p3]]
    c_matrix = [[c0, c2], [c1, c3]]

    determinant = (
        p_matrix[0][0] * p_matrix[1][1]
        - p_matrix[0][1] * p_matrix[1][0]
    ) % 26

    inverse_det = mod_inverse(determinant)

    if inverse_det is None:
        return {
            "success": False,
            "message": (
                "The first two plaintext blocks do not form an "
                "invertible matrix modulo 26. Try different known "
                "plaintext/ciphertext pairs."
            )
        }

    # Inverse of a 2x2 matrix modulo 26.
    p_inverse = [
        [
            (p_matrix[1][1] * inverse_det) % 26,
            (-p_matrix[0][1] * inverse_det) % 26
        ],
        [
            (-p_matrix[1][0] * inverse_det) % 26,
            (p_matrix[0][0] * inverse_det) % 26
        ]
    ]

    # K = C * inverse(P) (mod 26)
    key = [
        [
            sum(
                c_matrix[i][k] * p_inverse[k][j]
                for k in range(2)
            ) % 26
            for j in range(2)
        ]
        for i in range(2)
    ]

    # Validate the recovered key against all supplied letters.
    for i in range(0, len(plaintext), 2):
        p_block = [
            ord(plaintext[i]) - ord("A"),
            ord(plaintext[i + 1]) - ord("A")
        ]

        c_block = [
            ord(ciphertext[i]) - ord("A"),
            ord(ciphertext[i + 1]) - ord("A")
        ]

        calculated = [
            (key[row][0] * p_block[0]
             + key[row][1] * p_block[1]) % 26
            for row in range(2)
        ]

        if calculated != c_block:
            return {
                "success": False,
                "message": (
                    "No single 2x2 Hill key derived from the first "
                    "two blocks matches all supplied pairs. Check "
                    "the inputs, padding, and cipher convention."
                )
            }

    key_letters = [
        "".join(chr(value + ord("A")) for value in row)
        for row in key
    ]

    return {
        "success": True,
        "key_matrix": key,
        "key_letters": key_letters,
        "determinant": determinant,
        "message": "Hill cipher key recovered and validated."
    }


