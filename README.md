# Subdomain-Enumrator

#!/bin/bash

# Check if a domain is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

DOMAIN=$1

# Run subfinder
echo "[*] Running subfinder..."
subfinder -d $DOMAIN -all > subdomain.txt

# Run assetfinder
echo "[*] Running assetfinder..."
assetfinder -subs-only $DOMAIN > subdomain1.txt

# Sort and remove duplicates
echo "[*] Sorting and removing duplicates..."
sort -u subdomain.txt subdomain1.txt > mainsubdomain.txt

# Run httpx to find alive subdomains
echo "[*] Checking alive subdomains with httpx..."
cat mainsubdomain.txt | httpx -sc > alive_subdomain.txt

echo "[*] Done. Results saved in alive_subdomain.txt"
