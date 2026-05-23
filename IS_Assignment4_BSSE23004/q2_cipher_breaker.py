"""
=============================================================================
Question 2: Caesar / Vigenere Cipher Breaker using Frequency Analysis
=============================================================================
This module provides:
  - Caesar cipher  : encrypt, decrypt, auto-break
  - Vigenere cipher: encrypt, decrypt, auto-break

Breaking strategy:
  Caesar   -> Brute-force all 26 shifts; score each candidate against
              English letter frequency distribution using Chi-squared stat.

  Vigenere -> (1) Estimate key length via Index of Coincidence (IoC).
              (2) Treat each column of letters at distance=key_length as an
                  independent Caesar cipher and break each column.
=============================================================================
"""

import string


# ---------------------------------------------------------------------------
# English letter frequencies (A-Z) – standard reference values
# ---------------------------------------------------------------------------
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
    'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
    'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
    'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074,
}

ALPHABET = string.ascii_uppercase


# ===========================================================================
# CAESAR CIPHER
# ===========================================================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt plaintext with a Caesar cipher using the given shift (0-25)."""
    result = []
    for ch in plaintext.upper():
        if ch in ALPHABET:
            result.append(ALPHABET[(ALPHABET.index(ch) + shift) % 26])
        else:
            result.append(ch)
    return ''.join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt Caesar ciphertext by reversing the shift."""
    return caesar_encrypt(ciphertext, -shift % 26)


def chi_squared(text: str) -> float:
    """
    Chi-squared statistic between observed letter frequencies in `text`
    and expected English frequencies.  Lower = more English-like.
    """
    text = text.upper()
    total = sum(1 for c in text if c in ALPHABET)
    if total == 0:
        return float('inf')
    score = 0.0
    for letter in ALPHABET:
        observed = text.count(letter)
        expected = ENGLISH_FREQ[letter] * total
        score += (observed - expected) ** 2 / expected
    return score


def caesar_break(ciphertext: str) -> dict:
    """
    Automatically recover the Caesar key and plaintext via frequency analysis.
    Returns a dict with keys: shift, plaintext, score.
    """
    best = None
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        score     = chi_squared(candidate)
        if best is None or score < best['score']:
            best = {'shift': shift, 'plaintext': candidate, 'score': score}
    return best


# ===========================================================================
# VIGENERE CIPHER
# ===========================================================================

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext with Vigenere cipher using the given key string."""
    key    = key.upper()
    result = []
    ki     = 0
    for ch in plaintext.upper():
        if ch in ALPHABET:
            shift = ALPHABET.index(key[ki % len(key)])
            result.append(ALPHABET[(ALPHABET.index(ch) + shift) % 26])
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenere ciphertext using the known key."""
    key    = key.upper()
    result = []
    ki     = 0
    for ch in ciphertext.upper():
        if ch in ALPHABET:
            shift = ALPHABET.index(key[ki % len(key)])
            result.append(ALPHABET[(ALPHABET.index(ch) - shift) % 26])
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def index_of_coincidence(text: str) -> float:
    """
    Compute the Index of Coincidence (IoC) for the given text.
    IoC for English  ~0.067
    IoC for random   ~0.038
    """
    text  = ''.join(c for c in text.upper() if c in ALPHABET)
    n     = len(text)
    if n < 2:
        return 0.0
    freq_sum = sum(text.count(c) * (text.count(c) - 1) for c in ALPHABET)
    return freq_sum / (n * (n - 1))


def estimate_key_length(ciphertext: str, max_len: int = 20) -> int:
    """
    Estimate Vigenere key length by finding the period whose column IoC
    is closest to the English IoC of 0.067.
    """
    letters = ''.join(c for c in ciphertext.upper() if c in ALPHABET)
    TARGET_IOC = 0.067
    best_len   = 1
    best_diff  = float('inf')

    for klen in range(1, max_len + 1):
        avg_ioc = 0.0
        for col in range(klen):
            column  = letters[col::klen]
            avg_ioc += index_of_coincidence(column)
        avg_ioc /= klen
        diff = abs(avg_ioc - TARGET_IOC)
        if diff < best_diff:
            best_diff = diff
            best_len  = klen

    return best_len


def vigenere_break(ciphertext: str, max_key_len: int = 20) -> dict:
    """
    Automatically break a Vigenere-encrypted ciphertext.
    Returns a dict with keys: key_length, key, plaintext.
    """
    letters  = ''.join(c for c in ciphertext.upper() if c in ALPHABET)
    key_len  = estimate_key_length(ciphertext, max_key_len)
    key_chars = []

    for col in range(key_len):
        column = letters[col::key_len]
        result = caesar_break(column)
        key_chars.append(ALPHABET[result['shift']])

    recovered_key = ''.join(key_chars)
    plaintext     = vigenere_decrypt(ciphertext, recovered_key)

    return {
        'key_length': key_len,
        'key'       : recovered_key,
        'plaintext' : plaintext,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_separator(title: str = ""):
    width = 72
    if title:
        side = (width - len(title) - 2) // 2
        print("-" * side + f" {title} " + "-" * (width - side - len(title) - 2))
    else:
        print("-" * width)


def truncate(text: str, n: int = 80) -> str:
    return text[:n] + ("..." if len(text) > n else "")


# ===========================================================================
# TESTS – Five Ciphertexts
# ===========================================================================

if __name__ == "__main__":

    print("=" * 72)
    print("   Caesar / Vigenere Cipher Breaker – Frequency Analysis Demo")
    print("=" * 72)
    print()

    # -----------------------------------------------------------------------
    # Caesar tests (3 ciphertexts)
    # -----------------------------------------------------------------------
    print_separator("CAESAR CIPHER TESTS")
    print()

    caesar_tests = [
        # (label, original_plaintext, shift)
        ("C-Test 1", "ATTACKATDAWN", 13),
        ("C-Test 2", "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG", 7),
        ("C-Test 3",
         "INFORMATION SECURITY IS THE PRACTICE OF PROTECTING DATA "
         "FROM UNAUTHORIZED ACCESS", 19),
    ]

    for label, plaintext, shift in caesar_tests:
        ct     = caesar_encrypt(plaintext, shift)
        result = caesar_break(ct)

        print(f"  [{label}]")
        print(f"  Original shift   : {shift}")
        print(f"  Plaintext        : {truncate(plaintext)}")
        print(f"  Ciphertext       : {truncate(ct)}")
        print(f"  Recovered shift  : {result['shift']}")
        print(f"  Recovered text   : {truncate(result['plaintext'])}")
        ok = result['shift'] == shift
        print(f"  Status           : {'CORRECT' if ok else 'WRONG'}")
        print()

    # -----------------------------------------------------------------------
    # Vigenere tests (2 ciphertexts)
    # -----------------------------------------------------------------------
    print_separator("VIGENERE CIPHER TESTS")
    print()

    vigenere_tests = [
        ("V-Test 4",
         "CRYPTOGRAPHY IS THE ART OF WRITING AND SOLVING CODES "
         "AND CIPHERS USED TO PROTECT INFORMATION",
         "KEY"),
        ("V-Test 5",
         "FREQUENCY ANALYSIS IS A POWERFUL TECHNIQUE USED TO BREAK "
         "CLASSICAL CIPHERS BY STUDYING HOW OFTEN LETTERS APPEAR IN "
         "THE CIPHERTEXT AND COMPARING THEM TO KNOWN LANGUAGE PATTERNS",
         "SPHINX"),
    ]

    for label, plaintext, key in vigenere_tests:
        ct     = vigenere_encrypt(plaintext, key)
        result = vigenere_break(ct)

        print(f"  [{label}]")
        print(f"  Original key     : {key}  (length {len(key)})")
        print(f"  Plaintext        : {truncate(plaintext)}")
        print(f"  Ciphertext       : {truncate(ct)}")
        print(f"  Estimated keylen : {result['key_length']}")
        print(f"  Recovered key    : {result['key']}")
        print(f"  Recovered text   : {truncate(result['plaintext'])}")
        ok = result['key'].upper() == key.upper()
        print(f"  Status           : {'CORRECT' if ok else 'PARTIAL (longer text improves accuracy)'}")
        print()

    # -----------------------------------------------------------------------
    # Explanation
    # -----------------------------------------------------------------------
    print_separator("How Frequency Analysis Works")
    print("""
  In natural English, every letter appears with a characteristic frequency.
  'E' is the most common (~12.7%), followed by T, A, O, I, N.  Rare letters
  include Q, Z, X.  Classical ciphers preserve this frequency distribution:

  Caesar Cipher:
    Every plaintext letter is shifted by a fixed amount.  The ciphertext
    letter frequencies are just the English frequencies rotated by the shift.
    Breaking it: try all 26 possible shifts; for each candidate decryption,
    compute the Chi-squared statistic against expected English frequencies.
    The shift with the lowest Chi-squared score is the correct key.

  Vigenere Cipher:
    Uses a repeating keyword, so each plaintext letter is shifted by the
    corresponding key letter.  This partially flattens frequencies.
    Breaking it:
      Step 1 – Find key length: compute the Index of Coincidence (IoC) for
               substrings extracted at every period p = 1,2,...,20.  When p
               matches the true key length, each column is a mono-alphabetic
               substitution and its IoC approaches 0.067 (English).
      Step 2 – Break each column: once the key length is known, every p-th
               letter forms an independent Caesar-encrypted stream; apply
               Chi-squared frequency analysis to each column to recover the
               corresponding key letter.

  Why it works:
    Both ciphers are substitution ciphers that preserve the statistical
    structure of the plaintext language.  They provide no true confusion or
    diffusion, so statistical patterns leak through the ciphertext, making
    them trivially breakable with enough ciphertext.
    """)
    print("=" * 72)
