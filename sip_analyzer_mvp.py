import streamlit as st
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import tempfile
import statistics

# Helper: Analyze SIP + RTP
def analyze_pcap(file):
    calls = defaultdict(lambda: {
        "messages": [],
        "rtp_jitter": [],
        "rtp_seq": [],
        "media_ips": set(),
        "codecs": set()
    })
    report_rows = []

    cap = pyshark.FileCapture(file, display_filter='sip || rtp', keep_packets=False)
    try:
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
                seq = int(pkt.rtp.get('seq', 0))
                calls[ssrc]["rtp_jitter"].append(jitter)
                calls[ssrc]["rtp_seq"].append(seq)
    finally:
        cap.close()

    for call_id, info in calls.items():
        if call_id == 'Unknown':
            continue

        missing_ack = not any("ACK" in msg for msg in info["messages"])
        missing_bye = not any("BYE" in msg for msg in info["messages"])
        one_way = len(info["media_ips"]) < 2
        jitter_list = info["rtp_jitter"]
        seqs = sorted(info["rtp_seq"])
        rtp_packets = len(seqs)
        packet_loss = sum((seqs[i+1] - seqs[i] - 1 for i in range(len(seqs)-1))) if len(seqs) > 1 else 0

        avg_jitter = round(statistics.mean(jitter_list), 2) if jitter_list else None
        max_jitter = round(max(jitter_list), 2) if jitter_list else None
        std_jitter = round(statistics.stdev(jitter_list), 2) if len(jitter_list) > 1 else None

        report_rows.append({
            "Call ID": call_id,
            "Messages": ', '.join(info["messages"][:3]),
            "Missing ACK": missing_ack,
            "Missing BYE": missing_bye,
            "One-Way Audio": one_way,
            "RTP Packets": rtp_packets,
            "Packet Loss": packet_loss,
            "Avg Jitter": avg_jitter,
            "Max Jitter": max_jitter,
            "Std Dev Jitter": std_jitter,
            "Codecs": ', '.join(info["codecs"]),
            "Media IPs": ' → '.join(info["media_ips"]),
        })

    return pd.DataFrame(report_rows), calls

# Streamlit UI
st.title("📞 SIP & RTP Analyzer (MBG/MiVB PCAP Inspector)")
uploaded_file = st.file_uploader("Upload a .pcap or .pcapng file", type=['pcap', 'pcapng'])

if uploaded_file is not None:
    with st.spinner("Analyzing PCAP..."):
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_file_path = tmp_file.name

        df, calls = analyze_pcap(tmp_file_path)

    st.success("Analysis complete! 📊")
    st.dataframe(df)

    csv = df.to_csv(index=False)
    html = df.to_html(index=False)

    st.download_button("Download CSV", csv, "sip_rtp_report.csv", "text/csv")
    st.download_button("Download HTML", html, "sip_rtp_report.html", "text/html")

    # Call-ID selection and deep-dive
    if not df.empty:
        call_ids = df["Call ID"].tolist()
        selected_call = st.selectbox("🔍 Select a Call-ID to view full SIP flow", call_ids)

        if selected_call:
            st.markdown(f"### 📞 Call Flow for `{selected_call}`")
            call_row = df.set_index("Call ID").loc[selected_call]

            st.markdown(f"**Codecs:** {call_row['Codecs']}")
            st.markdown(f"**Media IPs:** {call_row['Media IPs']}")
            st.markdown(f"**RTP Packets:** {call_row['RTP Packets']}")
            st.markdown(f"**Packet Loss:** {call_row['Packet Loss']}")
            st.markdown(f"**Avg Jitter:** {call_row['Avg Jitter']}")
            st.markdown(f"**Max Jitter:** {call_row['Max Jitter']}")
            st.markdown(f"**Std Dev Jitter:** {call_row['Std Dev Jitter']}")

            # Show SIP message flow
            sip_msgs = []
            cap = pyshark.FileCapture(tmp_file_path, display_filter='sip', keep_packets=False)
            try:
                for pkt in cap:
                    if 'sip' in pkt and pkt.sip.get('Call-ID', '') == selected_call:
                        line = pkt.sip.get('Request-Line', '') or pkt.sip.get('Status-Line', '')
                        time = pkt.sniff_time.strftime("%H:%M:%S")
                        sip_msgs.append(f"[{time}] {line}")
            finally:
                cap.close()

            st.markdown("### 📜 SIP Message Flow")
            for msg in sip_msgs:
                st.text(msg)
