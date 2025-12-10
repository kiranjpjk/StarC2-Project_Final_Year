#!/usr/bin/env python3
"""
ADVANCED ICMP C2 DETECTOR - Non-ML Approach
Uses behavioral analysis, statistics, and heuristics
NO MACHINE LEARNING - Pure expert analysis
"""

import math
import time
import statistics
from collections import Counter, defaultdict
from typing import Dict, List, Tuple


# ============================================================================
# CORE ANALYSIS TECHNIQUES
# ============================================================================

class EntropyAnalyzer:
    """Calculate and analyze payload entropy"""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Shannon entropy of data"""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        entropy = 0.0

        for count in byte_counts.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def analyze_packets(packets: List[Dict], threshold: float = 6.0) -> List[Dict]:
        """Detect high-entropy (encrypted) payloads"""
        alerts = []

        for pkt in packets:
            if 'payload' not in pkt or not pkt['payload']:
                continue

            entropy = EntropyAnalyzer.calculate_entropy(pkt['payload'])

            if entropy > threshold:
                alerts.append({
                    'type': 'ENTROPY_ANOMALY',
                    'severity': 'HIGH',
                    'src_ip': pkt['src_ip'],
                    'entropy': f"{entropy:.2f}",
                    'threshold': threshold,
                    'message': f'Encrypted payload from {pkt["src_ip"]}: entropy={entropy:.2f}'
                })

        return alerts


# ============================================================================

class AutocorrelationAnalyzer:
    """Detect random vs sequential patterns"""

    @staticmethod
    def calculate_autocorrelation(values: list, lag: int = 1) -> float:
        """Calculate autocorrelation at specific lag"""
        if len(values) < lag + 1:
            return 0.0

        mean = sum(values) / len(values)
        c0 = sum((x - mean) ** 2 for x in values) / len(values)

        if c0 == 0:
            return 0.0

        c_lag = sum(
            (values[i] - mean) * (values[i + lag] - mean)
            for i in range(len(values) - lag)
        ) / len(values)

        return c_lag / c0

    @staticmethod
    def analyze_packets(packets: List[Dict], window: int = 20) -> List[Dict]:
        """Detect random sequence numbers (C2 signature)"""
        alerts = []
        source_sequences = defaultdict(list)

        for pkt in packets:
            source_sequences[pkt['src_ip']].append(pkt['icmp_seq'])

        for src_ip, sequences in source_sequences.items():
            if len(sequences) >= window:
                recent = sequences[-window:]
                autocorr = AutocorrelationAnalyzer.calculate_autocorrelation(recent)

                # C2 has low autocorrelation (random)
                if autocorr < 0.2:
                    alerts.append({
                        'type': 'SEQUENCE_RANDOMNESS',
                        'severity': 'MEDIUM',
                        'src_ip': src_ip,
                        'autocorrelation': f"{autocorr:.3f}",
                        'message': f'Random sequences from {src_ip}: autocorr={autocorr:.3f}'
                    })

        return alerts


# ============================================================================

class TemporalAnalyzer:
    """Analyze inter-arrival times and patterns"""

    @staticmethod
    def detect_anomalies(packets: List[Dict]) -> List[Dict]:
        """Detect unusual timing patterns"""
        alerts = []
        source_timestamps = defaultdict(list)

        for pkt in packets:
            source_timestamps[pkt['src_ip']].append(pkt['timestamp'])

        for src_ip, timestamps in source_timestamps.items():
            if len(timestamps) >= 10:
                recent = sorted(timestamps[-10:])
                gaps = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]

                if gaps:
                    avg_gap = sum(gaps) / len(gaps)

                    # Check for suspiciously fast rate
                    if avg_gap < 0.1:
                        alerts.append({
                            'type': 'TEMPORAL_FAST',
                            'severity': 'MEDIUM',
                            'src_ip': src_ip,
                            'avg_gap': f"{avg_gap:.3f}s",
                            'message': f'Suspiciously fast ICMP from {src_ip}: {avg_gap:.3f}s'
                        })

                    # Check for high variance (Type 3 pattern)
                    variance = sum((x - avg_gap) ** 2 for x in gaps) / len(gaps)
                    std_dev = variance ** 0.5
                    cv = (std_dev / avg_gap) if avg_gap > 0 else 0

                    if cv > 1.5:
                        alerts.append({
                            'type': 'TEMPORAL_VARIANCE',
                            'severity': 'MEDIUM',
                            'src_ip': src_ip,
                            'cv': f"{cv:.2f}",
                            'message': f'Irregular timing from {src_ip}: CV={cv:.2f}'
                        })

        return alerts


# ============================================================================

class DistributionAnalyzer:
    """Analyze packet size distributions"""

    @staticmethod
    def calculate_stats(values: list) -> dict:
        """Calculate distribution statistics"""
        if not values:
            return {}

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        cv = (std_dev / mean) if mean > 0 else 0

        return {
            'mean': mean,
            'std_dev': std_dev,
            'cv': cv,
            'min': min(values),
            'max': max(values),
        }

    @staticmethod
    def detect_anomalies(packets: List[Dict], variance_threshold: float = 0.30) -> List[Dict]:
        """Detect abnormal size distributions"""
        alerts = []
        source_sizes = defaultdict(list)

        for pkt in packets:
            source_sizes[pkt['src_ip']].append(pkt['payload_size'])

        for src_ip, sizes in source_sizes.items():
            if len(sizes) >= 15:
                stats = DistributionAnalyzer.calculate_stats(sizes[-20:])

                # High variance = C2
                if stats['cv'] > variance_threshold:
                    alerts.append({
                        'type': 'SIZE_VARIANCE',
                        'severity': 'HIGH',
                        'src_ip': src_ip,
                        'cv': f"{stats['cv']:.2%}",
                        'mean': f"{stats['mean']:.0f}",
                        'range': f"{stats['max'] - stats['min']}",
                        'message': f'Variable sizes from {src_ip}: CV={stats["cv"]:.1%}'
                    })

        return alerts


# ============================================================================

class TTLAnalyzer:
    """TTL-based fingerprinting and deviation detection"""

    @staticmethod
    def build_fingerprint(packets: List[Dict]) -> dict:
        """Build TTL baseline for each source"""
        ttl_profiles = defaultdict(list)

        for pkt in packets:
            ttl_profiles[pkt['src_ip']].append(pkt['ttl'])

        fingerprints = {}
        for src_ip, ttls in ttl_profiles.items():
            if len(ttls) >= 5:
                ttl_counts = Counter(ttls)
                primary_ttl = ttl_counts.most_common(1)[0][0]
                primary_ratio = ttl_counts[primary_ttl] / len(ttls)

                fingerprints[src_ip] = {
                    'primary_ttl': primary_ttl,
                    'primary_ratio': primary_ratio,
                    'all_ttls': set(ttls)
                }

        return fingerprints

    @staticmethod
    def detect_deviations(packets: List[Dict], fingerprints: dict) -> List[Dict]:
        """Detect TTL deviations from baseline"""
        alerts = []

        for pkt in packets:
            src_ip = pkt['src_ip']
            ttl = pkt['ttl']

            if src_ip in fingerprints:
                fp = fingerprints[src_ip]
                expected = fp['primary_ttl']

                if abs(ttl - expected) > 2:
                    alerts.append({
                        'type': 'TTL_DEVIATION',
                        'severity': 'MEDIUM',
                        'src_ip': src_ip,
                        'expected': expected,
                        'actual': ttl,
                        'message': f'TTL deviation from {src_ip}: expected {expected}, got {ttl}'
                    })

        return alerts


# ============================================================================

class StateAnalyzer:
    """ICMP state machine analysis"""

    def __init__(self):
        self.source_states = defaultdict(lambda: {
            'last_type': None,
            'type_counts': Counter(),
            'timestamps': [],
            'transitions': []
        })

    def track_packet(self, src: str, icmp_type: int, timestamp: float) -> List[Dict]:
        """Track packet and return alerts"""
        alerts = []
        state = self.source_states[src]

        # Update state
        state['type_counts'][icmp_type] += 1
        state['timestamps'].append(timestamp)
        state['last_type'] = icmp_type

        # Check patterns
        alerts.extend(self._check_type3_spam(src, state, timestamp))
        alerts.extend(self._check_type8_rapid(src, state, timestamp))

        return alerts

    def _check_type3_spam(self, src: str, state: dict, timestamp: float) -> List[Dict]:
        """Detect rapid Type 3 traffic"""
        alerts = []

        # Count Type 3 in last 60 seconds
        recent_type3 = sum(1 for t in state['timestamps']
                           if timestamp - t < 60 and state['type_counts'][3] > 0)

        if recent_type3 > 5:
            alerts.append({
                'type': 'TYPE3_SPAM',
                'severity': 'HIGH',
                'src_ip': src,
                'count': recent_type3,
                'message': f'Rapid Type 3 from {src}: {recent_type3} packets/min'
            })

        return alerts

    def _check_type8_rapid(self, src: str, state: dict, timestamp: float) -> List[Dict]:
        """Detect rapid Type 8 traffic"""
        alerts = []

        # Count Type 8 in last 10 seconds
        recent_type8 = sum(1 for t in state['timestamps']
                           if timestamp - t < 10)

        if recent_type8 > 10:
            alerts.append({
                'type': 'TYPE8_RAPID',
                'severity': 'MEDIUM',
                'src_ip': src,
                'count': recent_type8,
                'message': f'Rapid Type 8 from {src}: {recent_type8} packets in 10s'
            })

        return alerts


# ============================================================================

class AdvancedDetector:
    """
    Complete expert-level ICMP C2 detector
    Uses behavioral analysis, statistics, heuristics
    NO MACHINE LEARNING
    """

    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()
        self.autocorr_analyzer = AutocorrelationAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.distribution_analyzer = DistributionAnalyzer()
        self.ttl_analyzer = TTLAnalyzer()
        self.state_analyzer = StateAnalyzer()

    def detect(self, packets: List[Dict]) -> List[Dict]:
        """Run all detection techniques"""
        all_alerts = []

        # Technique 1: Entropy
        all_alerts.extend(
            self.entropy_analyzer.analyze_packets(packets, threshold=6.0)
        )

        # Technique 2: Autocorrelation
        all_alerts.extend(
            self.autocorr_analyzer.analyze_packets(packets)
        )

        # Technique 3: Temporal
        all_alerts.extend(
            self.temporal_analyzer.detect_anomalies(packets)
        )

        # Technique 4: Distribution
        all_alerts.extend(
            self.distribution_analyzer.detect_anomalies(packets)
        )

        # Technique 5: TTL
        ttl_fps = self.ttl_analyzer.build_fingerprint(packets)
        all_alerts.extend(
            self.ttl_analyzer.detect_deviations(packets, ttl_fps)
        )

        # Technique 6: State Machine
        for pkt in packets:
            state_alerts = self.state_analyzer.track_packet(
                pkt['src_ip'],
                pkt['icmp_type'],
                pkt['timestamp']
            )
            all_alerts.extend(state_alerts)

        # Score and return
        return self._score_results(all_alerts)

    def _score_results(self, alerts: List[Dict]) -> List[Dict]:
        """Score each source by alert count"""
        source_scores = defaultdict(lambda: {
            'score': 0,
            'alerts': [],
            'techniques': set()
        })

        for alert in alerts:
            src = alert['src_ip']

            # Score by severity
            if alert['severity'] == 'CRITICAL':
                source_scores[src]['score'] += 10
            elif alert['severity'] == 'HIGH':
                source_scores[src]['score'] += 5
            else:
                source_scores[src]['score'] += 2

            source_scores[src]['alerts'].append(alert)
            source_scores[src]['techniques'].add(alert['type'])

        # Format results
        results = []
        for src_ip, data in source_scores.items():
            technique_count = len(data['techniques'])

            # Confidence based on multiple techniques
            if technique_count >= 4:
                confidence = 'VERY_HIGH'
            elif technique_count >= 2:
                confidence = 'HIGH'
            else:
                confidence = 'MEDIUM'

            results.append({
                'src_ip': src_ip,
                'risk_score': min(data['score'], 100),
                'techniques_detected': technique_count,
                'confidence': confidence,
                'verdict': 'C2_DETECTED' if data['score'] >= 10 else 'SUSPICIOUS',
                'alerts': data['alerts']
            })

        return sorted(results, key=lambda x: x['risk_score'], reverse=True)


# ============================================================================

def main():
    """Demo the detector"""
    print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║ ADVANCED ICMP C2 DETECTOR - NO ML ║
║ Expert-Level Behavioral Analysis ║
╚═══════════════════════════════════════════════════════════════════╝

[+] 7 Advanced Detection Techniques:
    1. Entropy Analysis (detects encryption)
    2. Autocorrelation (detects randomness)
    3. Temporal Analysis (detects timing patterns)
    4. Distribution Analysis (detects variance)
    5. TTL Fingerprinting (detects spoofing)
    6. State Machine (detects violations)
    7. Behavioral Heuristics

[!] Demo mode - simulating attack packets
""")

    detector = AdvancedDetector()

    # Simulate Type 3 C2 attack
    print("\n[*] Simulating Type 3 C2 attack...")
    attack_packets = []
    for i in range(30):
        attack_packets.append({
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'icmp_type': 3,
            'icmp_code': 0,
            'icmp_seq': 1000 + i * 100,  # Random-like
            'ttl': 62 + (i % 3),  # Variable TTL
            'payload_size': 64 + (i % 5) * 20,  # Variable size
            'payload': bytes([i % 256] * (64 + (i % 5) * 20)),  # High entropy
            'timestamp': time.time() + i * 0.2
        })

    # Run detection
    results = detector.detect(attack_packets)

    # Print results
    print("\n[DETECTION RESULTS]")
    print("=" * 70)

    for result in results:
        print(f"\nSource IP: {result['src_ip']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Techniques Detected: {result['techniques_detected']}/7")
        print(f"Confidence: {result['confidence']}")
        print(f"Verdict: {result['verdict']}")
        print(f"\nAlerts ({len(result['alerts'])} total):")

        for alert in result['alerts'][:5]:  # Show first 5
            print(f"  [{alert['severity']:8s}] {alert['type']:20s} - {alert['message']}")

        if len(result['alerts']) > 5:
            print(f"  ... and {len(result['alerts']) - 5} more alerts")


if __name__ == "__main__":
    main()
