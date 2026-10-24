# PCAP Traffic Analyzer

A Python command-line tool that reads a saved packet capture and summarises protocol counts, endpoint pairs, and DNS query names.

**Stage:** Initial prototype.

## Scope and safety

This tool reads a file supplied by the user and does not capture live traffic or transmit packets. Use only captures you created or are authorised to inspect. Review and redact sample files before sharing them.

## Requirements

- Python 3.10 or newer
- Scapy

Install Scapy with:

    python3 -m pip install scapy

## Usage

    python3 pcap_summary.py path/to/authorised-capture.pcap

## Findings

The first version produces a quick inventory of the capture: total packet count, protocol counts, frequent endpoint pairs, and DNS query names. It does not inspect payload contents or decide whether activity is malicious.

## Mitigations and lessons

Traffic summaries can help guide a manual investigation, but they are not proof of compromise. Correlate observations with host and application logs, and preserve the original capture when doing an investigation.

## Screenshots

Add a redacted terminal screenshot using a generated or authorised lab capture.
