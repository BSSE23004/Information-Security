"""
Q4: Caesar Cipher Cryptanalysis - Brute Force Attack
Ciphertext: "AOL FODPSX ZLZL PZ HUK WLYP."
Goal: Find the key and recover the original plaintext.
"""

COMMON_WORDS = {"THE", "AND", "IS", "ARE", "FOR", "TO", "OF", "IN", "A",
                "WITH", "THAT", "THIS", "HAVE", "FROM", "OR", "WAS", "AT",
                "BE", "BY", "AN", "IT", "NOT", "BUT", "WHAT", "ALL"}

def caesar_decrypt(text, key):
    result = ""
    for char in text.upper():
        if char.isalpha():
            result += chr((ord(char) - ord('A') - key) % 26 + ord('A'))
        else:
            result += char
    return result

def score_plaintext(text):
    """Score how English-like a text is by counting common words."""
    words  = text.split()
    score  = sum(1 for w in words if w.upper() in COMMON_WORDS)
    return score

ciphertext = "AOL FODPSX ZLZL PZ HUK WLYP."

print("=" * 65)
print("         Q4: CAESAR CIPHER CRYPTANALYSIS")
print("=" * 65)
print(f"\n  Ciphertext : {ciphertext}\n")
print("  Brute-Force: Trying all 26 possible keys")
print("  " + "-" * 60)
print(f"  {'Key':<6} {'Score':<8} {'Decrypted Text'}")
print("  " + "-" * 60)

best_key   = 0
best_score = -1
best_text  = ""

for key in range(26):
    decrypted = caesar_decrypt(ciphertext, key)
    score     = score_plaintext(decrypted)
    marker    = " <-- BEST MATCH" if score > best_score else ""

    if score > best_score:
        if best_score >= 0:
            # Reprint previous best without marker (just show all)
            pass
        best_score = score
        best_key   = key
        best_text  = decrypted

    print(f"  {key:<6} {score:<8} {decrypted}")

print("\n" + "=" * 65)
print("  RESULT:")
print("=" * 65)
print(f"\n  Ciphertext       : {ciphertext}")
print(f"  Encryption Key   : {best_key}")
print(f"  Recovered Text   : {best_text}")
print(f"\n  Explanation:")
print(f"    Key = {best_key} means each letter was shifted forward by {best_key} positions.")
print(f"    To decrypt, we shift each letter BACK by {best_key} positions.")
print(f"    Verification: 'AOL' -> shift back {best_key} -> '{caesar_decrypt('AOL', best_key)}'")
print(f"                  'HUK' -> shift back {best_key} -> '{caesar_decrypt('HUK', best_key)}'")
print(f"                  'PZ'  -> shift back {best_key} -> '{caesar_decrypt('PZ', best_key)}'")
