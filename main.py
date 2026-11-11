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
VT_API_KEY = os.environ["VIRUSTOTAL_API_KEY"]
ABUSE_API_KEY = os.environ["ABUSEIPDB_API_KEY"]

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
            value = line.strip()

            # Skips comments in text file
            if not value or value.startswith("#"):
                continue

            # Checks that IP is global, if not, print error
            # If invalid entry, try fails and goes to exception which prints error
            try:
                ip = str(ipaddress.ip_address(value))

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
    attributes = response.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})

    # Return results; if key doesn't exist, return 0
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0)
    }

# Checks AbuseIPDB
def check_abuseipdb(ip):
    headers = {
        "Key": ABUSE_API_KEY,
        # Accepting a response back in json format
         "Accept": "application/json"
    }

    # Defining request parameters: within the last 90 days and request additional details if available
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    response = requests.get(
        ABUSE_URL,
        headers=headers,
        params=params,
        timeout=15
    )
    response.raise_for_status()

    # Extracting JSON data and storing under "data" key
    data = response.json()["data"]

    reports = data.get("reports") or []

    # Creates empty set; sets prevent duplicates
    categories = set()

    # Loops through each report and each category in each report
    for report in reports:
        for category in report.get("categories", []):
            # Adding to set
            categories.add(category)

    return {
        "abuse_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "abuse_categories": ", ".join(
            # Sorts ints in categories set, converts ints to strings, joins the strings into 1 string seperated by commas and spaces
            str(c) for c in sorted(categories)
        )
    }

# Brings the 3 other functions together and saves results into a CSV file
def main():
    # Creates output folder (prepqres destination for CSV report)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    ips = read_ips(INPUT_FILE)

    # Column names for CSV report
    fieldnames = [
        "ip_address",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "abuse_score",
        "total_reports",
        "country",
        "isp",
        "abuse_categories",
        "vt_error",
        "abuse_error"
    ]

    # Opens CSV file for writing
    with open(
        OUTPUT_FILE, "w", newline="", encoding="utf-8"
    ) as file:

        # Creating CSV writer; writeheader() puts column labels
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for ip in ips:
            print(f"Checking {ip}...")
            
            # Each IP starts with its own dictionary
            result = {"ip_address": ip}

            try:
                # Adds key-value pairs ftom one dictionary into an existing dictionary
                result.update(check_virustotal(ip))
            # requests.RequestException = network failure, timeout, HTTP error; KeyError = expected JSON field missing; ValueError: invalid JSON response
            except (requests.RequestException, KeyError, ValueError) as error:
                result["vt_error"] = str(error)

            try:
                result.update(check_abuseipdb(ip))
            except(requests.RequestException, KeyError, ValueError) as error:
                result["abuse_error"] = str(error)

            writer.writerow(result)

        # Takes a pause between IP addresses because of rate limits
        time.sleep(16)

    print(f"Report saved to: {OUTPUT_FILE}")

    
# Python doesn't automatically execute main unless explicitly called at bottom
if __name__ == "__main__":
    main()