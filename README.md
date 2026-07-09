📁 Threat Intel Feed Aggregator (STIX/TAXII)

Description
Connects to a TAXII 2.1 server (or generates mock indicators) and stores indicators of compromise (IPs, domains, hashes) in a local SQLite database.

Key Features

    Fetches STIX 2.1 objects from a TAXII collection.

    Parses indicators and stores them.

    Uses simulation mode if no TAXII server is available.

    SQLite database for persistence.

    Sample display of stored indicators.

Technologies

    stix2, taxii2client, sqlite3.

Prerequisites

    Python 3, packages.

Installation
bash

pip install stix2 taxii2client

Usage
bash

python stix_aggregator.py

Sample Output
text

[*] Current indicators in DB: 0
[*] Using simulation mode (generating mock indicators).
[+] Total indicators now: 3
[*] Sample indicators:
  indicator--abc... | indicator | [ipv4-addr:value = '192.168.1.100']

Notes

    Replace USE_SIMULATION = False and add a real TAXII URL and collection ID for live feeds.

    You can obtain a free TAXII feed from AlienVault OTX (with API key).
