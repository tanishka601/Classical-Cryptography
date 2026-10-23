
import string
import math

ALPHABET = string.ascii_uppercase


# ==================================================
# 1. CAESAR CIPHER
# ==================================================

def caesar_encrypt(text, shift):
    result = ""

    for char in text:
        if char.isascii() and char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char

    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ==================================================
# 2. VIGENERE CIPHER
# ==================================================

def vigenere_encrypt(text, key):
    key = key.upper()

    if not key or any(c not in ALPHABET for c in key):
        raise ValueError("Key must contain English letters only.")

    result = ""
    j = 0

    for char in text:
        if char.isascii() and char.isalpha():
            shift = ord(key[j % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            j += 1
        else:
            result += char

    return result


def vigenere_decrypt(text, key):
    key = key.upper()

    if not key or any(c not in ALPHABET for c in key):
        raise ValueError("Key must contain English letters only.")

    result = ""
    j = 0

    for char in text:
        if char.isascii() and char.isalpha():
            shift = ord(key[j % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            j += 1
        else:
            result += char

    return result


# ==================================================
# 3. RAIL FENCE CIPHER
# ==================================================

def rail_fence_encrypt(text, rails):
    if rails < 1:
        raise ValueError("Rails must be at least 1.")

    if rails == 1 or rails >= len(text):
        return text

    rows = [''] * rails
    rail = 0
    direction = 1

    for char in text:
        rows[rail] += char

        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1

        rail += direction

    return ''.join(rows)


def rail_fence_decrypt(ciphertext, rails):
    if rails < 1:
        raise ValueError("Rails must be at least 1.")

    if rails == 1 or rails >= len(ciphertext):
        return ciphertext

    pattern = []
    rail = 0
    direction = 1

    for _ in ciphertext:
        pattern.append(rail)

        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1

        rail += direction

    counts = [pattern.count(r) for r in range(rails)]
    rows = []
    index = 0

    for count in counts:
        rows.append(list(ciphertext[index:index + count]))
        index += count

    positions = [0] * rails
    result = []

    for r in pattern:
        result.append(rows[r][positions[r]])
        positions[r] += 1

    return ''.join(result)


# ==================================================
# 4. COLUMNAR TRANSPOSITION CIPHER
# ==================================================

def columnar_encrypt(text, key):
    key = str(key)

    if not key or not key.isascii() or not key.isalnum():
        raise ValueError("Key must contain letters or digits only.")

    columns = len(key)
    order = sorted(range(columns), key=lambda i: (key[i], i))

    return ''.join(
        text[i]
        for col in order
        for i in range(col, len(text), columns)
    )


def columnar_decrypt(ciphertext, key):
    key = str(key)

    if not key or not key.isascii() or not key.isalnum():
        raise ValueError("Key must contain letters or digits only.")

    if not ciphertext:
        return ""

    columns = len(key)
    length = len(ciphertext)
    rows = (length + columns - 1) // columns
    remainder = length % columns

    column_lengths = [
        rows if remainder == 0 or col < remainder else rows - 1
        for col in range(columns)
    ]

    order = sorted(range(columns), key=lambda i: (key[i], i))
    column_data = [''] * columns
    index = 0

    for col in order:
        count = column_lengths[col]
        column_data[col] = ciphertext[index:index + count]
        index += count

    result = []

    for row in range(rows):
        for col in range(columns):
            if row < len(column_data[col]):
                result.append(column_data[col][row])

    return ''.join(result)


# ==================================================
# 5. MONOALPHABETIC SUBSTITUTION CIPHER
# ==================================================

def _validate_substitution_key(key):
    key = key.upper()

    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError(
            "Key must contain all 26 English letters exactly once."
        )

    return key


def substitution_encrypt(text, key):
    key = _validate_substitution_key(key)
    result = ""

    for char in text:
        if char.isascii() and char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            index = ord(char.upper()) - ord('A')
            mapped = key[index]
            result += mapped if char.isupper() else mapped.lower()
        else:
            result += char

    return result


def substitution_decrypt(text, key):
    key = _validate_substitution_key(key)
    inverse = {key[i]: ALPHABET[i] for i in range(26)}
    result = ""

    for char in text:
        if char.isascii() and char.isalpha():
            mapped = inverse[char.upper()]
            result += mapped if char.isupper() else mapped.lower()
        else:
            result += char

    return result


# ==================================================
# 6. PLAYFAIR CIPHER
# ==================================================


def _playfair_matrix(key):
    """Create a 5x5 Playfair matrix using the key."""
    key = ''.join(c for c in key.upper() if c in ALPHABET)
    key = key.replace('J', 'I')

    sequence = []
    for char in key + ALPHABET:
        if char != 'J' and char not in sequence:
            sequence.append(char)

    return [sequence[i:i + 5] for i in range(0, 25, 5)]


def _playfair_prepare(text):
    """Clean plaintext and split it into pairs, inserting filler letters."""
    text = ''.join(
        c for c in text.upper() if c in ALPHABET
    ).replace('J', 'I')

    pairs = []
    i = 0

    while i < len(text):
        first = text[i]

        if i + 1 >= len(text):
            second = 'X' if first != 'X' else 'Q'
            i += 1
        elif text[i + 1] == first:
            second = 'X' if first != 'X' else 'Q'
            i += 1
        else:
            second = text[i + 1]
            i += 2

        pairs.append(first + second)

    return pairs


def _playfair_transform_pair(pair, matrix, decrypt=False):
    """Encrypt or decrypt one pair using Playfair rules."""
    positions = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    a, b = pair
    r1, c1 = positions[a]
    r2, c2 = positions[b]

    step = -1 if decrypt else 1

    # Same row: move right for encryption, left for decryption.
    if r1 == r2:
        return (
            matrix[r1][(c1 + step) % 5]
            + matrix[r2][(c2 + step) % 5]
        )

    # Same column: move down for encryption, up for decryption.
    if c1 == c2:
        return (
            matrix[(r1 + step) % 5][c1]
            + matrix[(r2 + step) % 5][c2]
        )

    # Rectangle: exchange the columns.
    return matrix[r1][c2] + matrix[r2][c1]


def playfair_encrypt(text, key):
    """Encrypt plaintext using the Playfair cipher."""
    if not key or not any(c.isascii() and c.isalpha() for c in key):
        raise ValueError("Playfair key must contain English letters.")

    matrix = _playfair_matrix(key)
    pairs = _playfair_prepare(text)

    return ''.join(
        _playfair_transform_pair(pair, matrix)
        for pair in pairs
    )



def playfair_decrypt(ciphertext, key):
    """Decrypt Playfair ciphertext and remove a trailing padding X when applicable."""
    if not key or not any(c.isascii() and c.isalpha() for c in key):
        raise ValueError("Playfair key must contain English letters.")

    text = ''.join(
        c for c in ciphertext.upper() if c in ALPHABET
    ).replace('J', 'I')

    if len(text) % 2 != 0:
        raise ValueError("Playfair ciphertext must have an even length.")

    matrix = _playfair_matrix(key)

    decrypted = ''.join(
        _playfair_transform_pair(
            text[i:i + 2], matrix, decrypt=True
        )
        for i in range(0, len(text), 2)
    )

    # Remove the final X only when it was added to pad odd-length plaintext.
    if decrypted.endswith('X'):
        decrypted = decrypted[:-1]

    return decrypted




# ==================================================
# 7. HILL CIPHER (2 x 2 MATRIX)
# ==================================================

def _validate_hill_key(key):
    try:
        values = [int(x.strip()) for x in key.split(',')]
    except (ValueError, AttributeError):
        raise ValueError("Enter four integers, e.g. 3,3,2,5.")

    if len(values) != 4:
        raise ValueError("Hill key must contain exactly four integers.")

    a, b, c, d = values
    determinant = (a * d - b * c) % 26

    if math.gcd(determinant, 26) != 1:
        raise ValueError(
            "Key matrix is not invertible modulo 26. "
            "Choose a key with gcd(det, 26) = 1."
        )

    return a % 26, b % 26, c % 26, d % 26


def _hill_inverse_key(key):
    a, b, c, d = key
    determinant = (a * d - b * c) % 26
    inverse_det = pow(determinant, -1, 26)

    return (
        (d * inverse_det) % 26,
        (-b * inverse_det) % 26,
        (-c * inverse_det) % 26,
        (a * inverse_det) % 26
    )


def hill_encrypt(text, key):
    a, b, c, d = _validate_hill_key(key)

    # This implementation processes English letters only.
    cleaned = ''.join(
        ch for ch in text.upper() if ch in ALPHABET
    )

    if len(cleaned) % 2:
        cleaned += 'X'

    result = []

    for i in range(0, len(cleaned), 2):
        x = ord(cleaned[i]) - ord('A')
        y = ord(cleaned[i + 1]) - ord('A')

        first = (a * x + b * y) % 26
        second = (c * x + d * y) % 26

        result.append(chr(first + ord('A')))
        result.append(chr(second + ord('A')))

    return ''.join(result)


def hill_decrypt(ciphertext, key):
    inverse_key = _hill_inverse_key(_validate_hill_key(key))
    a, b, c, d = inverse_key

    cleaned = ''.join(
        ch for ch in ciphertext.upper() if ch in ALPHABET
    )

    if len(cleaned) % 2:
        raise ValueError("Hill ciphertext must have an even number of letters.")

    result = []

    for i in range(0, len(cleaned), 2):
        x = ord(cleaned[i]) - ord('A')
        y = ord(cleaned[i + 1]) - ord('A')

        first = (a * x + b * y) % 26
        second = (c * x + d * y) % 26

        result.append(chr(first + ord('A')))
        result.append(chr(second + ord('A')))

    return ''.join(result)
