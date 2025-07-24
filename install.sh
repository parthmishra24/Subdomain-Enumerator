#!/bin/bash
# install.sh - Install dependencies for Subdomain Enumerator
set -e

command -v go >/dev/null 2>&1 || { echo "Go is required but not installed. Please install Go and rerun."; exit 1; }

install_tool() {
  local binary="$1"
  local package="$2"
  if command -v "$binary" >/dev/null 2>&1; then
    echo "$binary already installed"
  else
    echo "Installing $binary..."
    GO111MODULE=on go install -v "$package"
  fi
}

install_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_tool assetfinder github.com/tomnomnom/assetfinder@latest
install_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_tool amass github.com/owasp-amass/amass/v3/...@latest
install_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "Installation complete. Make sure \$GOPATH/bin is in your PATH."
