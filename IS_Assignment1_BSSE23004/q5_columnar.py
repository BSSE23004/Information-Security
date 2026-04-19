"""
Q5: Columnar Transposition Cipher
Keyword  : KEY
Plaintext: NETWORK SECURITY REQUIRES MONITORING AND RESPONSE.
"""

def columnar_encrypt(text, key):
    clean    = ''.join(c for c in text.upper() if c.isalpha())
    num_cols = len(key)
    num_rows = -(-len(clean) // num_cols)          # ceiling division
    padded   = clean.ljust(num_rows * num_cols, 'X')

    # Build grid
    grid = [list(padded[i * num_cols:(i + 1) * num_cols]) for i in range(num_rows)]

    # Determine column reading order (alphabetical sort of key)
    key_upper = key.upper()
    order     = sorted(range(len(key_upper)), key=lambda x: key_upper[x])

    ciphertext = ''
    for col in order:
        for row in grid:
            ciphertext += row[col]

    return ciphertext, grid, order, padded, num_cols, num_rows

def columnar_decrypt(ciphertext, key, original_len):
    num_cols = len(key)
    num_rows = -(-original_len // num_cols)
    key_upper = key.upper()
    order     = sorted(range(len(key_upper)), key=lambda x: key_upper[x])

    # Split ciphertext back into columns
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx  = 0
    for col in order:
        for row in range(num_rows):
            grid[row][col] = ciphertext[idx]
            idx += 1

    plaintext = ''.join(''.join(row) for row in grid)
    return plaintext[:original_len]

# ─── Main ────────────────────────────────────────────────
plaintext = "NETWORK SECURITY REQUIRES MONITORING AND RESPONSE."
key       = "KEY"

clean = ''.join(c for c in plaintext.upper() if c.isalpha())

print("=" * 65)
print("         Q5: COLUMNAR TRANSPOSITION CIPHER (Key: KEY)")
print("=" * 65)
print(f"\n  Plaintext  : {plaintext}")
print(f"  Key        : {key}")
print(f"  Cleaned    : {clean} ({len(clean)} chars)")

ciphertext, grid, order, padded, num_cols, num_rows = columnar_encrypt(plaintext, key)

# Determine column ranks for display
key_upper = key.upper()
ranks     = [0] * len(key)
for rank, col_idx in enumerate(order):
    ranks[col_idx] = rank + 1   # 1-indexed rank

print("\n" + "=" * 65)
print("  Grid Layout (padded with X where needed):")
print("=" * 65)
print(f"\n  Keyword   :  {'    '.join(list(key_upper))}")
print(f"  Col Order :  {'    '.join(str(r) for r in ranks)}   (1=read first, 2=second, ...)\n")

for r in range(num_rows):
    row_str = '    '.join(list(padded[r * num_cols:(r + 1) * num_cols]))
    print(f"  Row {r + 1:<4}  :  {row_str}")

print("\n" + "=" * 65)
print("  Columns read in alphabetical key order:")
print("=" * 65)
for rank, col_idx in enumerate(order):
    col_data = ''.join(grid[r][col_idx] for r in range(num_rows))
    print(f"  Step {rank + 1} -> Column '{key_upper[col_idx]}' (index {col_idx + 1}): {col_data}")

print("\n" + "=" * 65)
print(f"\n  Ciphertext : {ciphertext}")

# Decrypt to verify
decrypted = columnar_decrypt(ciphertext, key, len(clean))
print(f"  Decrypted  : {decrypted}")
print(f"\n  Verification: Decrypted == Original? --> {clean == decrypted}")
