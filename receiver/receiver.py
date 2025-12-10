"""
STAR-C2 FIXED RECEIVER
✓ Uses CA decryption
✓ Reassembles chunks correctly
✓ No numpy dependency
✓ Decompresses messages
"""

import struct
import sys
import random
import time
import logging
import gzip
from typing import Optional, Dict, Any
from scapy.all import IP, ICMP, Raw, sniff, conf
from websocket import send

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

    state = bytearray(seed_bytes)
    keystream = bytearray()

    while len(keystream) < length_bytes:
        middle_byte = state[len(state) // 2]
        keystream.append(middle_byte)
        state = rule90_step(state)

    return bytes(keystream[:length_bytes])


def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    """Decrypt message using CA keystream"""
    if not enc_bytes:
        return ''

    ks = ca_keystream(seed, len(enc_bytes))
    decrypted = bytes(a ^ b for a, b in zip(enc_bytes, ks))
    return decrypted.decode('utf-8', errors='ignore')


# ============================================================================
# CONSTANTS
# ============================================================================

SYNC = b"STR1"
SATID = b"GXY"
FRAME_ID = 0xA1
SEED = b"\x12\x34\x56\x78"

# Message Types
MSG_TYPE_REQUEST = 1
MSG_TYPE_REPLY = 0
MSG_TYPE_CHUNK = 2


# ============================================================================
# RECEIVER CLASS
# ============================================================================

class OptimizedChunkedReceiver:
    """Receives ICMP packets, decrypts, decompresses, and reassembles messages"""

    def __init__(self, listen_ip: str = '0.0.0.0', timeout: int = 300):
        self.listen_ip = listen_ip
        self.timeout = timeout

        # Store reassembly state
        self.sessions = {}  # {session_id: {seq_num: chunk_data}}
        self.complete_messages = {}  # {session_id: encrypted_data}

        logger.info(f"[+] Receiver initialized")
        logger.info(f"    Listen IP: {listen_ip}")
        logger.info(f"    Timeout: {timeout}s")

    def packet_callback(self, packet):
        """Called for each ICMP packet received"""

        try:
            if not (IP in packet and ICMP in packet):
                return

            icmp = packet[ICMP]

            # Only process Echo Requests (type 8)
            if icmp.type != 8:
                return

            # Extract data
            if not (Raw in packet):
                return

            payload = packet[Raw].load
            src_ip = packet[IP].src
            session_id = icmp.id
            seq_num = icmp.seq

            logger.info(f"\n[*] Received ICMP packet")
            logger.info(f"    Source: {src_ip}")
            logger.info(f"    Session: {session_id}, Seq: {seq_num}")
            logger.info(f"    Payload size: {len(payload)} bytes")
            logger.info(f"    Payload (hex): {payload.hex()}")

            # Store chunk
            if session_id not in self.sessions:
                self.sessions[session_id] = {}
                logger.info(f"[+] New session: {session_id}")

            self.sessions[session_id][seq_num] = payload

            logger.info(f"[✓] Chunk stored (total chunks in session: {len(self.sessions[session_id])})")

            # Try to reassemble and decrypt
            self.try_reassemble(session_id)

            # Send ICMP Echo Reply
            reply = IP(dst=src_ip) / ICMP(type=0, code=0, id=session_id, seq=seq_num) / \
                    Raw(load=b'ACK')
            send(reply, verbose=False)
            logger.info(f"[✓] Sent ICMP Echo Reply to {src_ip}")

        except Exception as e:
            logger.error(f"[!] Error processing packet: {e}")

    def try_reassemble(self, session_id: int):
        """Try to reassemble and decrypt message from collected chunks"""

        if session_id not in self.sessions:
            return

        chunks = self.sessions[session_id]

        # Check if we have sequential chunks
        seq_nums = sorted(chunks.keys())

        # If we don't have chunk 0, can't decrypt yet
        if 0 not in seq_nums:
            return

        # Check for missing gaps
        for i in range(max(seq_nums) + 1):
            if i not in chunks:
                return  # Still missing chunks

        # All chunks present - reassemble
        logger.info(f"\n[*] Reassembling message from {len(chunks)} chunks...")

        encrypted_data = b''
        for i in range(len(chunks)):
            encrypted_data += chunks[i]

        logger.info(f"[✓] Reassembled: {len(encrypted_data)} bytes (hex: {encrypted_data.hex()[:64]}...)")

        # Decrypt using CA keystream
        logger.info(f"[*] Decrypting with CA keystream (seed: {SEED.hex()})...")
        decrypted = ca_keystream(SEED, len(encrypted_data))

        message_data = bytes(a ^ b for a, b in zip(encrypted_data, decrypted))
        logger.info(f"[✓] Decrypted: {len(message_data)} bytes")

        # Decompress
        try:
            decompressed = gzip.decompress(message_data)
            message = decompressed.decode('utf-8')
            logger.info(f"[✓] Decompressed: {len(decompressed)} bytes")
            logger.info(f"[✓] MESSAGE: {message}\n")

            self.complete_messages[session_id] = message

        except Exception as e:
            logger.error(f"[!] Decompression failed: {e}")
            logger.info(f"[*] Raw decrypted data: {message_data}")

    def listen(self):
        """Start listening for ICMP packets"""
        logger.info(f"\n[*] Listening for ICMP packets (timeout: {self.timeout}s)...\n")

        try:
            sniff(
                prn=self.packet_callback,
                filter="icmp",
                timeout=self.timeout,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("\n[!] Receiver stopped")
        except Exception as e:
            logger.error(f"[!] Error: {e}")

    def get_messages(self):
        """Get all complete messages"""
        return self.complete_messages


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    listen_ip = sys.argv if len(sys.argv) > 1 else '0.0.0.0'
    timeout = int(sys.argv) if len(sys.argv) > 2 else 300

    receiver = OptimizedChunkedReceiver(listen_ip, timeout)
    receiver.listen()
