"""
CA Keystream Generator - Standalone Module
Rule 90 Cellular Automaton for encryption
Can be imported by other modules
"""


def rule90_step(state: bytearray) -> bytearray:
    """Rule 90 cellular automaton step"""
    n = len(state)
    new_state = bytearray(n)
    for i in range(n):
        left = state[(i - 1) % n]
        right = state[(i + 1) % n]
        new_state[i] = left ^ right
    return new_state


def ca_keystream(seed_bytes: bytes, length_bytes: int) -> bytes:
    """Generate keystream from seed using Rule 90 CA"""
    if not seed_bytes or length_bytes == 0:
        return b''

    state = bytearray(seed_bytes)
    keystream = bytearray()

    while len(keystream) < length_bytes:
        middle_byte = state[len(state) // 2]
        keystream.append(middle_byte)
        state = rule90_step(state)

    return bytes(keystream[:length_bytes])


def ca_encode_message(msg_bytes: bytes, seed: bytes) -> bytes:
    """Encrypt message bytes using CA keystream"""
    if not msg_bytes:
        return b''

    ks = ca_keystream(seed, len(msg_bytes))

    # XOR encryption (byte by byte)
    encrypted = bytes(a ^ b for a, b in zip(msg_bytes, ks))
    return encrypted


def ca_decode_message(enc_bytes: bytes, seed: bytes) -> bytes:
    """Decrypt message bytes using CA keystream"""
    if not enc_bytes:
        return b''

    ks = ca_keystream(seed, len(enc_bytes))

    # XOR decryption (same as encryption)
    decrypted = bytes(a ^ b for a, b in zip(enc_bytes, ks))
    return decrypted


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == '__main__':
    # Example 1: Generate keystream
    seed = b"\x12\x34\x56\x78"
    ks = ca_keystream(seed, 32)
    print(f"Keystream (32 bytes): {ks.hex()}")

    # Example 2: Encrypt message
    msg = b"Hello World"
    encrypted = ca_encode_message(msg, seed)
    print(f"Original:  {msg}")
    print(f"Encrypted: {encrypted.hex()}")

    # Example 3: Decrypt message
    decrypted = ca_decode_message(encrypted, seed)
    print(f"Decrypted: {decrypted}")

    # Verify
    assert msg == decrypted, "Encryption/Decryption mismatch!"
    print("✓ Encryption/Decryption verified!")
