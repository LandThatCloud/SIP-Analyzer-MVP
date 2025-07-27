# SIP & RTP Analyzer (MBG/MiVB PCAP Inspector)

A Streamlit web app for intelligent inspection of SIP signaling and RTP media streams from .pcap/.pcapng files — purpose-built to aid QA teams and developers working with Mitel Border Gateway (MBG) and MiVoice Business (MiVB) systems.

It automates call flow inspection, flags missing SIP messages, detects one-way audio, and computes RTP jitter stats, offering a fast and user-friendly way to investigate call quality.

---

## Features

✅ SIP Message Extraction – INVITE, TRYING, RINGING, OK, ACK, BYE, CANCEL, OPTIONS, etc.

✅ Missing SIP Detection – Flags missing ACK/BYE for each call.

✅ RTP Analysis – Per-stream jitter, packet count, codec used, one-way audio flags.

✅ Call Summary Table – Call-ID, From/To URIs, IPs, codecs, and media path.

✅ One-Way Audio Detection – Highlights calls where only one RTP stream is present.

✅ Jitter Stats – Min/Max/Mean jitter per stream (ms).

✅ Interactive Web UI – Upload .pcap files, view tabular data instantly.

✅ Download Reports – Export full analysis as .csv and .html.

---

## Getting Started

### Prerequisites

- Python 3.8+
- Wireshark/Tshark installed on your system (required by pyshark).  
  - **Windows:** [Download Wireshark](https://www.wireshark.org/download.html)  
  - **Linux:** `sudo apt-get install tshark` (Debian/Ubuntu) or equivalent  
  - **Mac:** `brew install wireshark`

### Install Python dependencies

```bash
pip install streamlit pyshark pandas
```

### Running the app

```bash
streamlit run sip_analyzer_mvp.py
```

Replace `sip_analyzer_mvp.py` with the filename of your script.

---

## Usage

* Upload a SIP/RTP .pcap file from MBG or MiVB call captures.
* The app will:
  * Parse and extract SIP messages.
  * Correlate RTP streams using SSRC and IP/port pairs.
  * Compute jitter and detect one-way audio.
* Review SIP call summary table:
* Flags missing messages (ACK, BYE)
* Shows RTP stream directions and codec info
* Download CSV or HTML reports for sharing or offline analysis.
---

## Limitations and Notes

* SIP ↔ RTP mapping is based on media IPs and SSRC, not SDP correlation (future enhancement).
* Large .pcap files (>100MB) may slow down analysis depending on system memory and CPU.
* Currently does not compute packet loss (planned).
* Performance may vary depending on your Tshark version and setup.

---

## Contributing

Contributions and suggestions are welcome! Feel free to open issues or submit pull requests.

---

## License

MIT License © 2025 Ram Ramaiyah

---

## Acknowledgements

- [Pyshark](https://github.com/KimiNewt/pyshark) for packet parsing  
- [Streamlit](https://streamlit.io/) for easy web app UI  
- Wireshark community for packet capture tools
