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

load_dotenv()

# Stores API keys in variables and allows interaction with OS
VT_API_KEY = os.environ("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.environ("ABUSEIPDB_API_KEY")

# Takes in input file and output file path
INPUT_FILE = Path("input/ip_addresses.txt")
OUTPUT_FILE = Path("output/ip_report.csv")