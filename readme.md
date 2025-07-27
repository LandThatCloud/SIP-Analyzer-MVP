# SIP & RTP Analyzer (MBG/MiVB PCAP Inspector)

A Streamlit web app to analyze SIP signaling and RTP streams from PCAP or PCAPNG files.  
Designed for troubleshooting VoIP calls by extracting call details, checking SIP message completeness, detecting one-way audio issues, and calculating RTP jitter.

---

## Features

- Parses SIP and RTP packets using [pyshark](https://github.com/KimiNewt/pyshark).
- Extracts SIP call messages (INVITE, ACK, BYE, etc.) and highlights missing important messages.
- Analyzes RTP streams for jitter and potential one-way audio conditions.
- Summarizes call info including Call-ID, media IP addresses, codecs used, and RTP quality metrics.
- Interactive Streamlit UI for uploading PCAP files and viewing detailed reports.
- Downloadable reports in CSV and HTML formats for offline analysis.

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
