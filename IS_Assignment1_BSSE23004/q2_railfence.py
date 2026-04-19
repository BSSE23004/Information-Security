"""
Q2: Rail Fence Cipher - Encryption with 4 rails
Plaintext: PENETRATION TESTING IS IMPORTANT FOR COMPUTER SECURITY.
"""

def rail_fence_encrypt(text, rails):
    clean = ''.join(c for c in text.upper() if c.isalpha())

    fence = [''] * rails
    rail = 0
    direction = 1

    for char in clean:
        fence[rail] += char
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    return ''.join(fence)

def rail_fence_decrypt(ciphertext, rails):
    n = len(ciphertext)
    pattern = []
    rail = 0
    direction = 1

    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    counts = [pattern.count(r) for r in range(rails)]
    fence = []
    idx = 0
    for count in counts:
        fence.append(list(ciphertext[idx:idx + count]))
        idx += count

    result = ''
    rail_idx = [0] * rails
    for r in pattern:
        result += fence[r][rail_idx[r]]
        rail_idx[r] += 1
    return result

def show_fence(text, rails):
    clean = ''.join(c for c in text.upper() if c.isalpha())
    grid = [['.' for _ in range(len(clean))] for _ in range(rails)]
    rail = 0
    direction = 1

    for i, char in enumerate(clean):
        grid[rail][i] = char
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    print("\nFence Diagram:")
    for r in range(rails):
        print(f"  Rail {r}: {''.join(grid[r])}")

# ─── Main ────────────────────────────────────────────────
plaintext = "PENETRATION TESTING IS IMPORTANT FOR COMPUTER SECURITY."
rails = 4

print("=" * 65)
print("         Q2: RAIL FENCE CIPHER (4 Rails)")
print("=" * 65)

clean = ''.join(c for c in plaintext.upper() if c.isalpha())
print(f"\n  Original Plaintext : {plaintext}")
print(f"  Cleaned Plaintext  : {clean}")
print(f"  Number of Rails    : {rails}")
print(f"  Total Characters   : {len(clean)}")

show_fence(plaintext, rails)

ciphertext = rail_fence_encrypt(plaintext, rails)
decrypted  = rail_fence_decrypt(ciphertext, rails)

print(f"\n  Ciphertext : {ciphertext}")
print(f"  Decrypted  : {decrypted}")

match = clean == decrypted
print(f"\n  Verification: Decrypted == Original? --> {match}")

print("\n" + "=" * 65)
print("  Rail contents (before concatenation):")
print("=" * 65)
fence_parts = [''] * rails
rail = 0
direction = 1
for char in clean:
    fence_parts[rail] += char
    if rail == 0:
        direction = 1
    elif rail == rails - 1:
        direction = -1
    rail += direction
for r in range(rails):
    print(f"  Rail {r}: {fence_parts[r]}")
print(f"\n  Final Ciphertext (concatenated): {ciphertext}")
