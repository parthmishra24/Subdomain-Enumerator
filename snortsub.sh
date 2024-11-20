#!/bin/bash

# Check if a domain is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

DOMAIN=$1

# Run subfinder and assetfinder, sort, and remove duplicates
echo "[*] Running subfinder and assetfinder, then sorting and removing duplicates..."
{
  subfinder -d $DOMAIN -all
  assetfinder -subs-only $DOMAIN
} | sort -u > mainsubdomain.txt

# Run httpx to find alive subdomains
echo "[*] Checking alive subdomains with httpx..."
cat mainsubdomain.txt | httpx -sc > alive_subdomain.txt

echo "[*] Done. Results saved in alive_subdomain.txt"
