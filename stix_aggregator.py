#!/usr/bin/env python3
"""
Project 29 – Threat Intel Feed Aggregator (STIX/TAXII)
Fetches indicators from TAXII servers and stores them locally.
"""

import sqlite3
import json
import sys
import time
from datetime import datetime
from taxii2client.v21 import Server, Collection
from stix2 import parse

# ---------- CONFIG ----------
# Use a public TAXII server – AlienVault OTX (requires API key for full access)
# For demo, we'll use a free TAXII 2.1 server (if available).
# Since free TAXII endpoints are often limited, we'll also include a fallback simulation.
TAXII_SERVER_URL = "https://otx.alienvault.com/taxii/"  # May require API key
COLLECTION_ID = "1234"  # You need to get a valid collection ID from the server

# If no TAXII server is available, we generate mock indicators.
USE_SIMULATION = True   # Set to False when you have a real TAXII endpoint

DB_FILE = "iocs.db"

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id TEXT PRIMARY KEY,
            type TEXT,
            pattern TEXT,
            created TEXT,
            modified TEXT,
            raw_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def store_indicator(indicator):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Try to extract key fields
    i_type = indicator.get('type', 'unknown')
    pattern = indicator.get('pattern', '')
    created = indicator.get('created', datetime.utcnow().isoformat())
    modified = indicator.get('modified', created)
    raw = json.dumps(indicator)
    try:
        c.execute('''
            INSERT OR REPLACE INTO indicators (id, type, pattern, created, modified, raw_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (indicator.get('id'), i_type, pattern, created, modified, raw))
        conn.commit()
    except Exception as e:
        print(f"[!] DB error: {e}")
    conn.close()

def count_indicators():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM indicators")
    count = c.fetchone()[0]
    conn.close()
    return count

# ---------- FETCH FROM TAXII ----------
def fetch_taxii(server_url, collection_id, api_key=None):
    """Fetch indicators from a TAXII 2.1 server."""
    try:
        server = Server(server_url)
        collection = server.get_collection(collection_id)
        print(f"[*] Fetching from collection: {collection.title}")
        fetched = 0
        for obj in collection.get_objects():
            # Parse the STIX object
            try:
                stix_obj = parse(obj)
                if stix_obj and stix_obj.get('type') == 'indicator':
                    store_indicator(stix_obj)
                    fetched += 1
                    if fetched % 10 == 0:
                        print(f"[*] Fetched {fetched} indicators...")
            except Exception as e:
                # Skip objects that can't be parsed
                continue
        return fetched
    except Exception as e:
        print(f"[!] TAXII fetch error: {e}")
        return 0

# ---------- SIMULATION (for demo) ----------
def generate_mock_indicators():
    """Generate sample indicators for demonstration."""
    from uuid import uuid4
    from datetime import datetime, timedelta
    now = datetime.utcnow().isoformat()
    indicators = [
        {
            "id": f"indicator--{uuid4()}",
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '192.168.1.100']",
            "created": now,
            "modified": now,
            "description": "Suspicious IP from mock feed"
        },
        {
            "id": f"indicator--{uuid4()}",
            "type": "indicator",
            "pattern": "[domain-name:value = 'malicious-domain.com']",
            "created": now,
            "modified": now,
            "description": "Malicious domain from mock feed"
        },
        {
            "id": f"indicator--{uuid4()}",
            "type": "indicator",
            "pattern": "[file:hashes.MD5 = '5f4dcc3b5aa765d61d8327deb882cf99']",
            "created": now,
            "modified": now,
            "description": "Malicious file hash (MD5)"
        }
    ]
    for ind in indicators:
        store_indicator(ind)

# ---------- MAIN ----------
def main():
    init_db()
    count = count_indicators()
    print(f"[*] Current indicators in DB: {count}")

    if USE_SIMULATION:
        print("[*] Using simulation mode (generating mock indicators).")
        generate_mock_indicators()
        print("[+] Mock indicators added.")
    else:
        print("[*] Connecting to TAXII server...")
        # You would need to provide a valid API key if required
        fetched = fetch_taxii(TAXII_SERVER_URL, COLLECTION_ID, api_key=None)
        print(f"[+] Fetched {fetched} new indicators.")

    new_count = count_indicators()
    print(f"[+] Total indicators now: {new_count}")

    # Export some sample indicators
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, type, pattern FROM indicators LIMIT 5")
    rows = c.fetchall()
    if rows:
        print("\n[*] Sample indicators:")
        for row in rows:
            print(f"  {row[0]} | {row[1]} | {row[2]}")
    else:
        print("[!] No indicators found.")
    conn.close()

if __name__ == "__main__":
    main()