```markdown
# Subdomain Finder Automation Script

This script automates the process of finding subdomains using `subfinder` and `assetfinder`, then checks which subdomains are alive using `httpx`.

## Prerequisites

Make sure you have the following tools installed:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [httpx](https://github.com/projectdiscovery/httpx)

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/parthmishra24/Subdomain-Enumrator.git
   cd Subdomain-Enumrator
   ```

2. Make the script executable:

   ```bash
   chmod +x find_subdomains.sh
   ```

3. Run the script with a domain as an argument:

   ```bash
   ./livesub.sh example.com
   ```

## How It Works

1. The script first runs `subfinder` to find subdomains and saves the output to `subdomain.txt`.
2. Then, it runs `assetfinder` to find more subdomains and saves the output to `subdomain1.txt`.
3. It sorts and removes duplicate subdomains from both lists, saving the result to `mainsubdomain.txt`.
4. Finally, it uses `httpx` to check which subdomains are alive and saves the output to `alive_subdomain.txt`.

## Output

- `subdomain.txt`: Subdomains found by `subfinder`.
- `subdomain1.txt`: Subdomains found by `assetfinder`.
- `mainsubdomain.txt`: Sorted and unique list of subdomains from both tools.
- `alive_subdomain.txt`: List of alive subdomains checked by `httpx`.

## Example

```bash
./livesub.sh example.com
```

The results will be saved in `alive_subdomain.txt`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```

Feel free to customize the repository URL, project name, or any other details as needed.
