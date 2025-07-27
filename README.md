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
```

### Running the app

```bash
streamlit run app.py
```

Replace `app.py` with the filename of your script.

---

## Usage

1. Open the Streamlit app in your browser.
2. Upload a `.pcap` or `.pcapng` file containing SIP and RTP traffic.
3. Wait for the analysis to complete.
4. View the call summary table showing SIP messages, missing ACK/BYE flags, one-way audio detection, average RTP jitter, codecs, and media IP addresses.
5. Download the report as CSV or HTML for further analysis or sharing.

---

## Limitations and Notes

- RTP streams are currently identified by SSRC and analyzed independently of SIP Call-ID.  
- The app requires Tshark (part of Wireshark) installed and accessible in your system PATH.  
- Large PCAP files may take longer to analyze depending on system resources.  
- Future improvements planned include better RTP to SIP call correlation, packet loss detection, and enhanced UI filters.

---

## Contributing

Contributions and suggestions are welcome! Feel free to open issues or submit pull requests.

---

## License

MIT License © 2025 Your Name

---

## Acknowledgements

- [Pyshark](https://github.com/KimiNewt/pyshark) for packet parsing  
- [Streamlit](https://streamlit.io/) for easy web app UI  
- Wireshark community for packet capture tools
