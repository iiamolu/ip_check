# Allows script to interact directly with the OS that the computer us running
import os
import csv
import time
import ipaddress
# Makes it easier to locate, check, create, and organize files and folders
from pathlib import Path

# Lets program make HTTP requests
import requests
# Lets env vatiables be read
from dotenv import load_dotenv

# Reads from .env and adds key-value pairs to app's env variables
load_dotenv()

# Stores API keys in variables and allows interaction with OS
VT_API_KEY = os.environ("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.environ("ABUSEIPDB_API_KEY")

# Takes in input file and output file path
INPUT_FILE = Path("input/ip_addresses.txt")
OUTPUT_FILE = Path("output/ip_report.csv")

# API endpoints (found in official documentation)
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# Reads IPs from text file and checks if they're valid
def read_ips(file_path):
    # Empty list for IPs
    ips = []

    # Takes in file path, sets to read only
    with open(file_path, "r", encoding="utf-8") as file:
        # Checks line by line
        for line in file:
            # Strips extra spaces if needed
            value - line.strip()

            # Skips comments in text file
            if not value or value.startswith("#"):
                continue

            # Checks that IP is global, if not, print error
            # If invalid entry, try fails and goes to exception which prints error
            try:
                ip - str(ipaddress.ip_address(value))

                if ipaddress.ip_address(ip).is_global:
                    ips.append(ip)

                else:
                    print(f"Skipping non-public IP: {ip}")

            except ValueError:
                print(f"SKipping invalid entry: {value}")

    # Returns final list without duplicate IPs, preserves original order (Creates dictionary, dictionary keys must be unique; after, converts back to list)
    return list(dict.fromkeys(ips))

# Checks virus total
def check_virustotal(ip):
    # HTTP header (provides API key)
    headers = {
        "x-apikey": VT_API_KEY
    }

    # Sending API GET request to retrieve info at specified API endpoint
    response = requests.get(
        VT_URL + ip,
        # Passes HTTP header into request
        headers=headers,
        # Timeout after 15 seconds
        timeout=15
    )
    # Checking if request succeeded (200)
    response.raise_for_status()

    # Extracts JSON data
    attributes = reponse.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})

    # Return results; if key doesn't exist, return 0
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suispicious", 0),
        "vt_harmless": stats.get("harmless", 0)
    }