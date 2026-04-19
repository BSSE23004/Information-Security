"""
Q1: Caesar Cipher - Encryption and Decryption
Key = 7
Plaintext: MODERN NETWORKS REQUIRE STRONG SECURITY MECHANISMS TO PROTECT DATA.
"""

def caesar_encrypt(text, key):
    result = ""
    for char in text.upper():
        if char.isalpha():
            encrypted_char = chr((ord(char) - ord('A') + key) % 26 + ord('A'))
            result += encrypted_char
        else:
            result += char
    return result

def caesar_decrypt(text, key):
    result = ""
    for char in text.upper():
        if char.isalpha():
            decrypted_char = chr((ord(char) - ord('A') - key) % 26 + ord('A'))
            result += decrypted_char
        else:
            result += char
    return result

def show_substitution_table(key):
    print("\nSubstitution Table (first 10 letters):")
    print("Plain : " + " ".join(chr(ord('A') + i) for i in range(10)))
    print("Cipher: " + " ".join(chr((i + key) % 26 + ord('A')) for i in range(10)))

# ─── Main ────────────────────────────────────────────────
plaintext = "MODERN NETWORKS REQUIRE STRONG SECURITY MECHANISMS TO PROTECT DATA."
key = 7

print("=" * 65)
print("         Q1: CAESAR CIPHER (Key = 7)")
print("=" * 65)

ciphertext = caesar_encrypt(plaintext, key)
decrypted  = caesar_decrypt(ciphertext, key)

print(f"\n  Plaintext  : {plaintext}")
print(f"  Key        : {key}")
print(f"\n  Ciphertext : {ciphertext}")
print(f"\n  Decrypted  : {decrypted}")

# Verify
match = plaintext.upper() == decrypted
print(f"\n  Verification: Decrypted == Original Plaintext? --> {match}")

show_substitution_table(key)

print("\n" + "=" * 65)
print("  Step-by-step (first word 'MODERN'):")
print("=" * 65)
for ch in "MODERN":
    enc = chr((ord(ch) - ord('A') + key) % 26 + ord('A'))
    print(f"  {ch}({ord(ch)-ord('A'):2d}) + {key} = {ord(ch)-ord('A')+key:2d} mod 26 = "
          f"{(ord(ch)-ord('A')+key)%26:2d} -> {enc}")
