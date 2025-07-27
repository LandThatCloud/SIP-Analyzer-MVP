# SIP/SDP Log Analyzer with Anomaly Detection (PCAP-based)
# Author: Ram Bharadwaj | Mitel Networks QA
# Description: MVP version - parses SIP messages from .pcap, detects flow anomalies.

import pyshark
import re
from collections import defaultdict
from datetime import datetime

# Define thresholds (in seconds)
INVITE_OK_THRESHOLD = 5.0

# Store call data
calls = defaultdict(lambda: {
    'messages': [],
    'timestamps': {},
    'codecs': [],
    'src_ips': set(),
    'dst_ips': set()
})

def parse_sip_packets(pcap_file):
    print(f"[*] Parsing SIP packets from {pcap_file}...")
    cap = pyshark.FileCapture(pcap_file, display_filter='sip')
    for pkt in cap:
        try:
            call_id = pkt.sip.get_field_by_showname("Call-ID") or "unknown"
            msg = pkt.sip.request_line or pkt.sip.status_line or ""
            ts = pkt.sniff_time

            calls[call_id]['messages'].append(msg)
            calls[call_id]['timestamps'][msg] = ts
            calls[call_id]['src_ips'].add(pkt.ip.src)
            calls[call_id]['dst_ips'].add(pkt.ip.dst)

            # Extract codec from SDP if present
            if hasattr(pkt, 'sdp'):
                sdp_raw = pkt.sdp.get_raw_value()
                codecs = re.findall(r"a=rtpmap:\d+ ([^/]+)", sdp_raw)
                calls[call_id]['codecs'].extend(codecs)

        except AttributeError:
            continue
    cap.close()
    return calls

def analyze_call_flow():
    for call_id, data in calls.items():
        print(f"\n📞 Call-ID: {call_id}")
        msgs = data['messages']
        ts_map = data['timestamps']
        codecs = list(set(data['codecs']))

        def get_time_diff(msg1, msg2):
            if msg1 in ts_map and msg2 in ts_map:
                return (ts_map[msg2] - ts_map[msg1]).total_seconds()
            return None

        print("Messages:")
        for m in msgs:
            print(f"  - {m}")

        if any("INVITE" in m for m in msgs) and any("200 OK" in m for m in msgs):
            delay = get_time_diff([m for m in msgs if "INVITE" in m][0], [m for m in msgs if "200 OK" in m][0])
            if delay and delay > INVITE_OK_THRESHOLD:
                print(f"⚠️ Delay between INVITE and 200 OK: {delay:.2f}s (threshold: {INVITE_OK_THRESHOLD}s)")
            else:
                print(f"✅ INVITE → 200 OK delay acceptable: {delay:.2f}s")

        if "ACK" not in "".join(msgs):
            print("❌ Missing ACK message")
        if "BYE" not in "".join(msgs):
            print("⚠️ BYE message not observed")

        print(f"Codecs negotiated: {codecs}")
        print(f"Media IPs involved: {data['src_ips']} → {data['dst_ips']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python sip_analyzer.py <path_to_pcap>")
    else:
        parse_sip_packets(sys.argv[1])
        analyze_call_flow()
