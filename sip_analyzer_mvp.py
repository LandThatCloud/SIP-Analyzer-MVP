import streamlit as st
import pyshark
import pandas as pd
from collections import defaultdict

# Helper: Analyze SIP + RTP
def analyze_pcap(file):
    cap = pyshark.FileCapture(file, display_filter='sip || rtp')
    calls = defaultdict(lambda: {"messages": [], "rtp": [], "media_ips": set(), "codecs": set()})
    report_rows = []

    for pkt in cap:
        if 'sip' in pkt:
            call_id = pkt.sip.get('Call-ID', 'Unknown')
            msg = pkt.sip.get('Request-Line', '') or pkt.sip.get('Status-Line', '')
            calls[call_id]["messages"].append(msg)
            if hasattr(pkt.sip, 'media_ip'):
                calls[call_id]["media_ips"].add(pkt.sip.media_ip)
            if hasattr(pkt.sip, 'rtp_payload_type'):
                calls[call_id]["codecs"].add(pkt.sip.rtp_payload_type)

        elif 'rtp' in pkt:
            ssrc = pkt.rtp.get('ssrc', 'Unknown')
            jitter = float(pkt.rtp.get('jitter', 0.0))
            calls[ssrc]["rtp"].append(jitter)

    for call_id, info in calls.items():
        missing_ack = not any("ACK" in msg for msg in info["messages"])
        missing_bye = not any("BYE" in msg for msg in info["messages"])
        avg_jitter = round(sum(info["rtp"]) / len(info["rtp"]), 2) if info["rtp"] else None
        one_way = len(info["media_ips"]) < 2

        report_rows.append({
            "Call ID": call_id,
            "Messages": ', '.join(info["messages"][:3]),
            "Missing ACK": missing_ack,
            "Missing BYE": missing_bye,
            "One-Way Audio": one_way,
            "Avg RTP Jitter": avg_jitter,
            "Codecs": ', '.join(info["codecs"]),
            "Media IPs": ' → '.join(info["media_ips"]),
        })

    return pd.DataFrame(report_rows)


# Streamlit UI
st.title("📞 SIP & RTP Analyzer (MBG/MiVB PCAP Inspector)")
uploaded_file = st.file_uploader("Upload a .pcap or .pcapng file", type=['pcap', 'pcapng'])

if uploaded_file is not None:
    with st.spinner("Analyzing PCAP..."):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_file_path = tmp_file.name

        df = analyze_pcap(tmp_file_path)


    st.success("Analysis complete! 📊")
    st.dataframe(df)

    csv = df.to_csv(index=False)
    html = df.to_html(index=False)

    st.download_button("Download CSV", csv, "sip_rtp_report.csv", "text/csv")
    st.download_button("Download HTML", html, "sip_rtp_report.html", "text/html")