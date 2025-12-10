"""
Main entry point for ICMP Covert Channel Detection System
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

def main():
    parser = argparse.ArgumentParser(description='ICMP Covert Channel Detection')
    parser.add_argument('mode', choices=['sender', 'receiver', 'dashboard'])
    parser.add_argument('--src', help='Source IP (for sender)')
    parser.add_argument('--dst', help='Destination IP (for sender)')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--port', type=int, default=5000)

    args = parser.parse_args()

    if args.mode == 'sender':
        if not args.src or not args.dst:
            print("Sender requires --src and --dst")
            sys.exit(1)
        from sender.star_c2_final_optimized import OptimizedChunkedSender
        sender = OptimizedChunkedSender(args.src, args.dst)
        print(f"[+] Sending to {args.dst}")
        try:
            while True:
                msg = input(">>> ")
                if msg.lower() == 'exit':
                    break
                sender.send_optimized(msg)
        except KeyboardInterrupt:
            print("\n[!] Stopped")

    elif args.mode == 'receiver':
        from receiver.receiver import OptimizedChunkedReceiver
        receiver = OptimizedChunkedReceiver('0.0.0.0', timeout=args.timeout)
        receiver.listen()

    elif args.mode == 'dashboard':
        from dashboard.app import app
        print(f"\n[+] Dashboard running at http://localhost:{args.port}")
        app.run(debug=True, port=args.port, host='0.0.0.0')

if __name__ == '__main__':
    main()
