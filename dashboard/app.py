"""
Flask Dashboard for ICMP Covert Channel Detection
"""

import os
import json
from flask import Flask, render_template, jsonify

from dashboard.packet_sniffer import LivePacketSniffer
from dashboard.realtime_detector import RealtimeDetector

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

packet_sniffer = None
detector = None

@app.route('/')
def index():
    return render_template('detection_dashboard.html')

@app.route('/api/start', methods=['POST'])
def start_detection():
    global packet_sniffer, detector
    try:
        packet_sniffer = LivePacketSniffer()
        detector = RealtimeDetector()
        packet_sniffer.start()
        return jsonify({'status': 'success', 'message': 'Detection started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_detection():
    global packet_sniffer
    try:
        if packet_sniffer:
            packet_sniffer.stop()
        return jsonify({'status': 'success', 'message': 'Detection stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
