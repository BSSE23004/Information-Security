"""
=============================================================================
Question 1: SPHINX Cipher – A Custom Symmetric Encryption Algorithm
=============================================================================
Algorithm Name  : SPHINX (Substitution-Permutation eXtended Hybrid In-Nibble Cipher)
Block size      : 8 bytes  (64 bits)
Key size        : 8–32 bytes (64–256 bits)
Rounds          : 4

Per-round structure (encrypt):
  1. XOR state with round subkey          (key mixing / confusion)
  2. Key-derived S-box substitution       (non-linear substitution)
  3. Nibble rotation (swap hi/lo nibbles) (intra-byte diffusion)
  4. Key-derived byte permutation         (transposition / diffusion)
Final key whitening (XOR with round-key 0) after all rounds.

Decryption is the exact reverse of each step, applied in reverse round order.

Key schedule: 4 distinct 8-byte subkeys derived from the master key using
a simple multiplicative mixing rule (no external libraries).

S-box: built by seeding a multiplicative LCG with the key hash, then
Fisher-Yates shuffling [0..255] – making the S-box unique per key.

Padding: PKCS#7.
=============================================================================
"""


# ---------------------------------------------------------------------------
# SPHINX Cipher Implementation
# ---------------------------------------------------------------------------

class SPHINXCipher:
    BLOCK_SIZE = 8   # 64-bit block
    NUM_ROUNDS = 4

    def __init__(self, key: bytes):
        if len(key) < 8:
            raise ValueError("Key must be at least 8 bytes (64 bits).")
        self.key = key
        self.round_keys  = self._derive_round_keys()
        self.sbox        = self._build_sbox()
        self.inv_sbox    = self._build_inv_sbox()
        self.perm        = self._build_permutation()
        self.inv_perm    = self._build_inv_permutation()

    # ------------------------------------------------------------------ #
    # Key schedule                                                         #
    # ------------------------------------------------------------------ #
    def _derive_round_keys(self):
        """Produce NUM_ROUNDS distinct 8-byte subkeys from the master key."""
        key   = list(self.key)
        n     = len(key)
        rkeys = []
        for r in range(self.NUM_ROUNDS):
            rk = []
            for i in range(self.BLOCK_SIZE):
                # Three independent taps from the key, mixed with round constants
                a = key[(i * 5  + r * 3)  % n]
                b = key[(i * 11 + r * 7)  % n]
                c = (r * 17 + i * 31 + 0xA5) & 0xFF
                rk.append(a ^ b ^ c)
            rkeys.append(bytes(rk))
        return rkeys

    # ------------------------------------------------------------------ #
    # S-box (key-dependent)                                                #
    # ------------------------------------------------------------------ #
    def _build_sbox(self):
        """Key-dependent S-box via LCG-seeded Fisher-Yates shuffle."""
        table = list(range(256))
        # Fold key into a 32-bit seed
        seed = 0xDEADBEEF
        for b in self.key:
            seed = ((seed ^ b) * 1664525 + 1013904223) & 0xFFFFFFFF
        # Fisher-Yates
        for i in range(255, 0, -1):
            seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
            j = seed % (i + 1)
            table[i], table[j] = table[j], table[i]
        return table

    def _build_inv_sbox(self):
        inv = [0] * 256
        for i, v in enumerate(self.sbox):
            inv[v] = i
        return inv

    # ------------------------------------------------------------------ #
    # Byte permutation (key-dependent)                                     #
    # ------------------------------------------------------------------ #
    def _build_permutation(self):
        """Key-dependent transposition table for the 8-byte block."""
        positions = list(range(self.BLOCK_SIZE))
        seed = 0xCAFEBABE
        for b in self.key:
            seed = ((seed ^ b) * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        for i in range(self.BLOCK_SIZE - 1, 0, -1):
            seed = (seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
            j = seed % (i + 1)
            positions[i], positions[j] = positions[j], positions[i]
        return positions

    def _build_inv_permutation(self):
        inv = [0] * self.BLOCK_SIZE
        for i, p in enumerate(self.perm):
            inv[p] = i
        return inv

    # ------------------------------------------------------------------ #
    # Primitive operations                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def _substitute(block: bytes, box: list) -> bytes:
        return bytes(box[b] for b in block)

    @staticmethod
    def _rotate_nibbles(block: bytes) -> bytes:
        """Swap high and low nibbles of every byte (self-inverse)."""
        return bytes(((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in block)

    def _permute(self, block: bytes, perm: list) -> bytes:
        result = bytearray(self.BLOCK_SIZE)
        for i, p in enumerate(perm):
            result[p] = block[i]
        return bytes(result)

    # ------------------------------------------------------------------ #
    # Block-level encrypt / decrypt                                        #
    # ------------------------------------------------------------------ #
    def _encrypt_block(self, block: bytes) -> bytes:
        state = block
        for r in range(self.NUM_ROUNDS):
            state = self._xor_bytes(state, self.round_keys[r])  # 1. Key mixing
            state = self._substitute(state, self.sbox)          # 2. Substitution
            state = self._rotate_nibbles(state)                 # 3. Nibble rotation
            state = self._permute(state, self.perm)             # 4. Transposition
        # Final key whitening
        state = self._xor_bytes(state, self.round_keys[0])
        return state

    def _decrypt_block(self, block: bytes) -> bytes:
        state = block
        # Undo final whitening
        state = self._xor_bytes(state, self.round_keys[0])
        for r in range(self.NUM_ROUNDS - 1, -1, -1):
            state = self._permute(state, self.inv_perm)         # 4. Inverse transposition
            state = self._rotate_nibbles(state)                 # 3. Nibble rotation (self-inverse)
            state = self._substitute(state, self.inv_sbox)     # 2. Inverse substitution
            state = self._xor_bytes(state, self.round_keys[r]) # 1. Key mixing (XOR is self-inverse)
        return state

    # ------------------------------------------------------------------ #
    # Padding (PKCS#7)                                                     #
    # ------------------------------------------------------------------ #
    def _pad(self, data: bytes) -> bytes:
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.BLOCK_SIZE:
            raise ValueError("Invalid padding detected during decryption.")
        return data[:-pad_len]

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self._pad(plaintext)
        ct = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            ct += self._encrypt_block(padded[i:i + self.BLOCK_SIZE])
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of block size.")
        pt = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            pt += self._decrypt_block(ciphertext[i:i + self.BLOCK_SIZE])
        return self._unpad(pt)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def print_separator(title: str = ""):
    width = 70
    if title:
        side = (width - len(title) - 2) // 2
        print("-" * side + f" {title} " + "-" * (width - side - len(title) - 2))
    else:
        print("-" * width)


def run_test(label: str, key: bytes, plaintext: str):
    print_separator(label)
    print(f"  Key (hex)       : {bytes_to_hex(key)}")
    print(f"  Key (length)    : {len(key)*8} bits")
    print(f"  Plaintext       : {plaintext!r}")

    cipher  = SPHINXCipher(key)
    pt_bytes = plaintext.encode('utf-8')

    ciphertext = cipher.encrypt(pt_bytes)
    decrypted  = cipher.decrypt(ciphertext)

    print(f"  Ciphertext (hex): {bytes_to_hex(ciphertext)}")
    print(f"  Decrypted       : {decrypted.decode('utf-8')!r}")
    assert decrypted == pt_bytes, "DECRYPTION MISMATCH – test FAILED"
    print(f"  Verification    : PASSED  (decrypted == original plaintext)")
    print()


# ---------------------------------------------------------------------------
# Main – Three Test Vectors
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("   SPHINX Cipher – Custom Symmetric Encryption Algorithm Demo")
    print("=" * 70)
    print()

    # ------------------------------------------------------------------
    # Test 1: Short message, 64-bit key (minimum)
    # ------------------------------------------------------------------
    run_test(
        label     = "Test 1: Short message / 64-bit key",
        key       = b"SecureK1",                          # 8 bytes = 64 bits
        plaintext = "Hello!"
    )

    # ------------------------------------------------------------------
    # Test 2: Medium message, 128-bit key
    # ------------------------------------------------------------------
    run_test(
        label     = "Test 2: Medium message / 128-bit key",
        key       = b"MySecretKey12345",                  # 16 bytes = 128 bits
        plaintext = "Information Security Assignment"
    )

    # ------------------------------------------------------------------
    # Test 3: Long message, 256-bit key
    # ------------------------------------------------------------------
    run_test(
        label     = "Test 3: Long message / 256-bit key",
        key       = b"SuperStrongKey!!SuperStrongKey!!",  # 32 bytes = 256 bits
        plaintext = "The quick brown fox jumps over the lazy dog. 1234567890!@#$"
    )

    # ------------------------------------------------------------------
    # Bonus: Avalanche effect demonstration (1-bit key difference)
    # ------------------------------------------------------------------
    print_separator("Bonus: Avalanche Effect")
    key1 = b"TestKey1"
    key2 = b"TestKey2"   # Only last byte differs
    msg  = b"SameMsg!"

    c1 = SPHINXCipher(key1).encrypt(msg)
    c2 = SPHINXCipher(key2).encrypt(msg)

    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(c1, c2))
    total_bits = len(c1) * 8

    print(f"  Plaintext               : {msg}")
    print(f"  Key 1                   : {key1}")
    print(f"  Key 2                   : {key2}  (1 byte changed)")
    print(f"  Ciphertext 1 (hex)      : {bytes_to_hex(c1)}")
    print(f"  Ciphertext 2 (hex)      : {bytes_to_hex(c2)}")
    print(f"  Different bits          : {diff_bits} / {total_bits}  "
          f"({100*diff_bits/total_bits:.1f}%)")
    print()

    # ------------------------------------------------------------------
    # Algorithm summary
    # ------------------------------------------------------------------
    print_separator("Algorithm Summary")
    print("""
  SPHINX Cipher Design
  --------------------
  Block Size   : 64 bits (8 bytes)
  Key Size     : 64–256 bits (8–32 bytes)
  Rounds       : 4
  Padding      : PKCS#7

  Per-round steps:
    1. XOR with round subkey        -> confusion (key mixing)
    2. Key-derived S-box lookup     -> non-linear substitution
    3. Nibble rotation (hi <-> lo)  -> intra-byte diffusion
    4. Key-derived byte permutation -> transposition / diffusion

  Key Schedule : 4 subkeys derived from master key using multiplicative
                 mixing across three key-byte taps + round constants.

  S-box        : Unique per key; built by seeding an LCG with the key
                 hash, then Fisher-Yates shuffling [0..255].

  Permutation  : Unique per key; built similarly with a 64-bit LCG seed.

  Known Weakness
  --------------
  The 4-round SPHINX cipher is vulnerable to differential and linear
  cryptanalysis with moderate effort because its diffusion layer (a
  single byte permutation over 8 bytes) provides insufficient avalanche
  after fewer than 4 rounds. An attacker with chosen-plaintext access
  could exploit the limited diffusion to recover subkeys incrementally.

  Possible Improvements
  ---------------------
  1. Increase rounds to 8–12 and widen the block to 128 bits.
  2. Replace nibble rotation with an MDS-matrix MixBytes step (as in AES
     MixColumns) for stronger inter-byte diffusion.
  3. Use a proven key schedule (e.g., AES key expansion) instead of the
     simple multiplicative mixing used here.
    """)
    print("=" * 70)
