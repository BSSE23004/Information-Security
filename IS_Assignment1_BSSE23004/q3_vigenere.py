"""
Q3: Vigenère Cipher - Encrypt your full name using keyword "KALI"
INSTRUCTIONS: Replace the value of `plaintext` below with your actual full name.
              Example: plaintext = "IBRAHIM Sattar"
"""

def vigenere_encrypt(text, key):
    result   = ""
    key      = key.upper()
    key_idx  = 0
    for char in text.upper():
        if char.isalpha():
            shift   = ord(key[key_idx % len(key)]) - ord('A')
            enc     = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result += enc
            key_idx += 1
        else:
            result += char   # preserve spaces
    return result

def vigenere_decrypt(text, key):
    result   = ""
    key      = key.upper()
    key_idx  = 0
    for char in text.upper():
        if char.isalpha():
            shift   = ord(key[key_idx % len(key)]) - ord('A')
            dec     = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            result += dec
            key_idx += 1
        else:
            result += char
    return result

plaintext = "IBRAHIM SATTAR"   

key = "KALI"

print("=" * 65)
print("         Q3: VIGENÈRE CIPHER (Keyword: KALI)")
print("=" * 65)

ciphertext = vigenere_encrypt(plaintext, key)
decrypted  = vigenere_decrypt(ciphertext, key)

print(f"\n  Plaintext  : {plaintext.upper()}")
print(f"  Key        : {key}")
print(f"\n  Ciphertext : {ciphertext}")
print(f"\n  Decrypted  : {decrypted}")
print(f"\n  Verification: Decrypted == Original? --> {plaintext.upper() == decrypted}")

print("\n" + "=" * 65)
print("  Step-by-step encryption table:")
print("=" * 65)
print(f"  {'Char':<6} {'Key':<6} {'PlainIdx':<10} {'KeyShift':<10} {'CipherIdx':<12} {'Cipher'}")
print("  " + "-" * 55)

key_idx = 0
for i, char in enumerate(plaintext.upper()):
    if char.isalpha():
        k      = key[key_idx % len(key)]
        p_idx  = ord(char) - ord('A')
        k_idx  = ord(k) - ord('A')
        c_idx  = (p_idx + k_idx) % 26
        c_char = chr(c_idx + ord('A'))
        print(f"  {char:<6} {k:<6} {p_idx:<10} {k_idx:<10} {c_idx:<12} {c_char}")
        key_idx += 1
    else:
        print(f"  {char:<6} {'--':<6} {'--':<10} {'--':<10} {'--':<12} {char}")
