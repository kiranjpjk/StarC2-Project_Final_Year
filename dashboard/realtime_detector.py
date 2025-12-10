"""
Real-time ICMP Covert Channel Detector
Uses statistical analysis to detect suspicious ICMP traffic
"""

import time
import math
import statistics
from collections import Counter, deque

class RealtimeDetector:
    """Detects ICMP covert channels in real-time"""

    def __init__(self, max_history=500):
        self.detections = deque(maxlen=max_history)
        self.history = deque(maxlen=max_history)
        self.detection_count = 0
        self.total_packets = 0

    # ============================================================
    # DETECTION TECHNIQUES
    # ============================================================

    def entropy_analysis(self, payload: bytes) -> float:
        """Calculate Shannon entropy (bits/byte)"""
        if not payload or len(payload) == 0:
            return 0.0

        byte_counts = Counter(payload)
        entropy = 0.0

        for count in byte_counts.values():
            p = count / len(payload)
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def distribution_analysis(self, payload: bytes) -> float:
        """Analyze byte distribution uniformity"""
        if not payload or len(payload) < 2:
            return 0.0

        byte_counts = Counter(payload)
        frequencies = list(byte_counts.values())

        mean_freq = statistics.mean(frequencies)
        if mean_freq == 0:
            return 0.0

        variance = statistics.variance(frequencies) if len(frequencies) > 1 else 0
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_freq

        return min(cv / 2.0, 1.0)

    def ttl_anomaly(self, ttl: int) -> float:
        """Detect unusual TTL values"""
        normal_ttls = [32, 64, 128, 255]
        return 0.7 if ttl not in normal_ttls else 0.1

    def size_consistency(self, payload: bytes) -> float:
        """Check for consistent payload sizes"""
        size = len(payload)

        # Covert channels often use regular sizes (multiples of 8, 16)
        if size % 8 == 0 or size % 16 == 0:
            return 0.3

        return 0.1

    def timing_analysis(self, current_time: float) -> float:
        """Detect regular timing patterns"""
        if len(self.history) < 2:
            return 0.0

        recent_times = [h['timestamp'] for h in list(self.history)[-5:]]

        if len(recent_times) < 2:
            return 0.0

        # Calculate inter-packet delays
        delays = []
        for i in range(len(recent_times) - 1):
            delay = recent_times[i+1] - recent_times[i]
            if delay > 0:
                delays.append(delay)

        if not delays or len(delays) < 2:
            return 0.0

        # Low variance in delays = higher score
        delay_variance = statistics.variance(delays)
        mean_delay = statistics.mean(delays)

        if mean_delay == 0:
            return 0.0

        cv = math.sqrt(delay_variance) / mean_delay
        timing_score = max(0, 1.0 - cv)

        return min(timing_score, 1.0)

    # ============================================================
    # MAIN DETECTION METHOD
    # ============================================================

    def analyze_packet(self, packet_data: dict) -> dict:
        """Analyze a single packet for covert channel indicators"""
        self.total_packets += 1

        try:
            payload = packet_data.get('raw_payload', b'')
            ttl = packet_data.get('ttl', 64)
            timestamp = packet_data.get('timestamp', time.time())

            # Store in history
            self.history.append({
                'timestamp': timestamp,
                'src_ip': packet_data.get('src_ip'),
                'payload_size': packet_data.get('payload_size', 0),
                'ttl': ttl
            })

            # Calculate scores for each technique
            entropy_score = self.entropy_analysis(payload) / 8.0  # Normalize to [0, 1]
            distribution_score = self.distribution_analysis(payload)
            ttl_score = self.ttl_anomaly(ttl)
            size_score = self.size_consistency(payload)
            timing_score = self.timing_analysis(timestamp)

            # Combine scores (weighted average)
            scores = [
                entropy_score * 0.25,
                distribution_score * 0.20,
                ttl_score * 0.15,
                size_score * 0.20,
                timing_score * 0.20
            ]

            confidence = sum(scores)
            confidence = min(max(confidence, 0.0), 1.0)  # Clamp to [0, 1]

            # Determine if suspicious
            is_suspicious = confidence > 0.6

            detection = {
                'timestamp': timestamp,
                'src_ip': packet_data.get('src_ip'),
                'dst_ip': packet_data.get('dst_ip'),
                'payload_size': packet_data.get('payload_size', 0),
                'confidence': round(confidence, 3),
                'is_suspicious': is_suspicious,
                'scores': {
                    'entropy': round(entropy_score, 3),
                    'distribution': round(distribution_score, 3),
                    'ttl': round(ttl_score, 3),
                    'size': round(size_score, 3),
                    'timing': round(timing_score, 3)
                }
            }

            # Store detection
            self.detections.append(detection)

            if is_suspicious:
                self.detection_count += 1

            return detection

        except Exception as e:
            print(f"[!] Detection error: {e}")
            return {
                'error': str(e),
                'confidence': 0.0,
                'is_suspicious': False
            }

    # ============================================================
    # REPORTING METHODS
    # ============================================================

    def get_detections(self, suspicious_only=False):
        """Get detection results"""
        detections = list(self.detections)

        if suspicious_only:
            detections = [d for d in detections if d.get('is_suspicious', False)]

        return detections

    def get_recent_detections(self, count=10, suspicious_only=False):
        """Get last N detections"""
        detections = list(self.detections)[-count:]

        if suspicious_only:
            detections = [d for d in detections if d.get('is_suspicious', False)]

        return detections

    def get_stats(self):
        """Get detector statistics"""
        avg_confidence = 0.0

        if self.detections:
            confidences = [d.get('confidence', 0) for d in self.detections]
            avg_confidence = statistics.mean(confidences)

        return {
            'total_packets': self.total_packets,
            'detections': self.detection_count,
            'suspicious_percentage': (self.detection_count / max(self.total_packets, 1)) * 100,
            'average_confidence': round(avg_confidence, 3),
            'buffered_detections': len(self.detections)
        }

    def clear_detections(self):
        """Clear detection history"""
        self.detections.clear()
        self.history.clear()
        self.detection_count = 0
        self.total_packets = 0

    def get_summary(self):
        """Get summary of all detections"""
        stats = self.get_stats()
        recent = self.get_recent_detections(5, suspicious_only=True)

        return {
            'stats': stats,
            'recent_suspicious': recent
        }
