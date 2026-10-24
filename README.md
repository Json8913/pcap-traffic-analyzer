# PCAP Traffic Analyzer

A Python command-line tool that reads a saved packet capture and summarises protocol counts, endpoint pairs, and DNS query names.

**Stage:** Initial prototype.

## Scope and safety

This tool reads a file supplied by the user and does not capture live traffic or transmit packets. Use only captures you created or are authorised to inspect. Review and redact captures before sharing them.

## Requirements

- Python 3.10 or newer
- Scapy

Install dependencies:

    python3 -m pip install -r requirements.txt

## Generate a safe sample

    python3 make_sample_pcap.py

This writes a local sample.pcap containing three synthetic TCP SYN packets and one synthetic DNS query for example.test. The generated file is ignored by Git.

## Usage

    python3 pcap_summary.py sample.pcap

The sample should show four packets and the example.test query.

## Findings and limits

The first version produces a quick inventory of the capture: total packet count, protocol counts, frequent endpoint pairs, and DNS query names. It does not inspect payload contents or decide whether activity is malicious.

## Mitigations and lessons

Traffic summaries can guide a manual investigation, but they are not proof of compromise. Correlate observations with host and application logs, and preserve the original capture when investigating.

## Screenshots

Add a redacted terminal screenshot using the generated sample or an authorised lab capture.
