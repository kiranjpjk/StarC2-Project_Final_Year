"""
Live Packet Sniffer for ICMP packets
Uses scapy to capture network traffic
"""

import threading
import time
from collections import deque
from scapy.all import sniff, IP, ICMP

class LivePacketSniffer:
    """Captures ICMP packets in real-time"""

    def __init__(self, max_packets=1000):
        self.packets = deque(maxlen=max_packets)
        self.running = False
        self.thread = None
        self.packet_count = 0

    def packet_callback(self, packet):
        """Called when a packet is captured"""
        if IP in packet and ICMP in packet:
            try:
                pkt_info = {
                    'timestamp': time.time(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'ttl': packet[IP].ttl,
                    'icmp_type': packet[ICMP].type,
                    'icmp_code': packet[ICMP].code,
                    'payload_size': len(packet[ICMP].payload),
                    'raw_payload': bytes(packet[ICMP].payload)[:100]  # First 100 bytes
                }
                self.packets.append(pkt_info)
                self.packet_count += 1
            except Exception as e:
                print(f"Error processing packet: {e}")

    def start(self):
        """Start packet capture in background thread"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.thread.start()
        print("[+] Packet sniffer started")

    def _sniff_packets(self):
        """Background thread: sniff ICMP packets"""
        try:
            sniff(
                prn=self.packet_callback,
                filter="icmp",
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[!] Sniffer error: {e}")
            self.running = False

    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[+] Packet sniffer stopped")

    def get_packets(self):
        """Get all captured packets"""
        return list(self.packets)

    def get_recent_packets(self, count=10):
        """Get last N packets"""
        recent = list(self.packets)[-count:]
        return recent

    def clear_packets(self):
        """Clear packet buffer"""
        self.packets.clear()
        self.packet_count = 0

    def get_stats(self):
        """Get sniffer statistics"""
        return {
            'total_packets': self.packet_count,
            'buffered_packets': len(self.packets),
            'running': self.running
        }
