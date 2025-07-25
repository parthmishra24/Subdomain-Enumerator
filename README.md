# Subdomain Finder Automation Script

This script automates the process of finding subdomains using `subfinder` and `assetfinder`, then checks which subdomains are alive using `httpx`. It includes features like progress reporting, error handling, rate limiting, and more.

## Features

- Automatic subdomain discovery using multiple tools
- Progress reporting with timestamps
- Dependency checking with installation guidance
- Rate limiting to avoid detection
- Customizable output directory
- Cleanup option for temporary files
- Verbose and quiet modes
- Comprehensive error handling
- JSON output support
- Filter results by status code
- Authentication-based URL filtering
- Chunked processing for large subdomain lists
- Resume interrupted scans
- Toggle progress bar display
- Optional enumeration with [amass](https://github.com/owasp-amass/amass)
- DNS resolution verification using [dnsx](https://github.com/projectdiscovery/dnsx)

## Prerequisites

This tool relies on a few external utilities:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [amass](https://github.com/owasp-amass/amass) (optional, for additional enumeration)
- [dnsx](https://github.com/projectdiscovery/dnsx) (optional, for DNS verification)

You can install all of them automatically using the included `install.sh` script.

### Installing Dependencies

Run the install script to download the required tools:

```bash
chmod +x install.sh
./install.sh
```

The script uses `go install` under the hood, so make sure Go is installed on your system.

## Usage

1. Clone the repository:

   ```
   git clone https://github.com/parthmishra24/Subdomain-Enumerator.git
   ```
   ```
   cd Subdomain-Enumerator
   ```

2. Make the script executable:

   ```
   chmod +x snortsub.sh
   ```

3. Run the script with a domain as an argument:

   ```
   ./snortsub.sh example.com
   ```

### Command-line Options

The script supports several command-line options:

```
Usage: ./snortsub.sh [OPTIONS] <domain>

Options:
  -h, --help              Show this help message and exit
  -V, --version           Display version information and exit
  -v, --verbose           Enable verbose output
  -q, --quiet             Suppress non-error messages
  -c, --cleanup           Remove temporary files after execution
  -r, --rate-limit RATE   Set rate limit for httpx using its `-rate` option (e.g., '100' for 100 requests/second)
  -o, --output-dir DIR    Specify output directory (default: current directory)
  -j, --json              Output results in JSON format
  -s, --status-code CODE  Filter results by status code (e.g., '200' or '200,301,302')
  --no-auth               Filter out authentication-based URLs (containing @ symbol)
  --auth-only             Show only authentication-based URLs
  --chunk-size SIZE       Process subdomains in chunks of SIZE (default: 1000)
  --resume FILE           Resume from a previous scan state file
  --no-progress           Disable progress bar display
  --amass                 Include passive results from amass
  --dnsx                  Verify DNS resolution with dnsx before running httpx
```

## How It Works

1. The script checks if all required dependencies are installed.
2. It then runs `subfinder` to find subdomains.
3. Next, it runs `assetfinder` to find more subdomains.
4. If the `--amass` option is used, it also runs `amass` in passive mode for additional results.
5. It sorts and removes duplicate subdomains from the enumeration tools, saving the result to `mainsubdomain.txt`.
6. If the `--dnsx` option is provided, the list is verified with `dnsx` to keep only resolving hosts.
7. Finally, it uses `httpx` to check which subdomains are alive and saves the output to `alive_subdomain.txt`.
8. If the cleanup option is enabled, it removes temporary files after execution.

## Output Files

- `mainsubdomain.txt`: Sorted and unique list of subdomains from both tools.
- `alive_subdomain.txt`: List of alive subdomains checked by `httpx`.

## Examples

Basic usage:
```bash
./snortsub.sh example.com
```

Using verbose mode with cleanup:
```bash
./snortsub.sh -v -c example.com
```

Rate limiting to 50 requests per second:
```bash
./snortsub.sh -r 50 example.com
```

Specifying a custom output directory:
```bash
./snortsub.sh -o /path/to/output example.com
```

Combining multiple options:
```bash
./snortsub.sh -v -c -r 100 -o /path/to/results example.com
```

Output results in JSON format:
```bash
./snortsub.sh -j example.com
```

Filter by status code 200:
```bash
./snortsub.sh -s 200 example.com
```

Process subdomains in smaller chunks:
```bash
./snortsub.sh --chunk-size 500 example.com
```

Resume a previous scan:
```bash
./snortsub.sh --resume state.json example.com
```

Include amass results:
```bash
./snortsub.sh --amass example.com
```

Verify DNS resolution before probing:
```bash
./snortsub.sh --dnsx example.com
```

## Features in Detail

### Rate Limiting

Rate limiting helps avoid detection by target systems when scanning large numbers of subdomains. Use the `-r` or `--rate-limit` option followed by the maximum number of requests per second:

```bash
./snortsub.sh -r 50 example.com
```

### Output Directory

You can specify a custom directory for output files using the `-o` or `--output-dir` option:

```bash
./snortsub.sh -o /path/to/output example.com
```

If the directory doesn't exist, the script will attempt to create it.

### Cleanup Mode

Enable cleanup mode with `-c` or `--cleanup` to automatically remove temporary files after the script completes:

```bash
./snortsub.sh -c example.com
```

### Verbose and Quiet Modes

- **Verbose Mode** (`-v` or `--verbose`): Provides detailed information about each step of the process.
- **Quiet Mode** (`-q` or `--quiet`): Suppresses all non-error messages, useful for automated scripts.

These modes can't be used together effectively, as quiet mode overrides verbose output.

### JSON Output

Enable JSON output with `-j` or `--json` to save results in machine-readable format.

### Status Code Filtering

Use `-s` or `--status-code` to only keep results with specific HTTP status codes.

### Authentication Filtering

`--no-auth` filters out URLs containing an `@` symbol. Use `--auth-only` to show only those URLs.

### Chunked Processing and Resume

The `--chunk-size` option processes subdomains in smaller batches, which is useful for large lists. You can resume an interrupted scan with `--resume <state_file>`.

### Progress Bar Control

Disable the progress bar with `--no-progress` if you prefer less output.

### Amass Integration

Enable `--amass` to include results from the Amass passive enumeration engine. This can uncover additional subdomains from multiple data sources.

### DNS Verification

Use `--dnsx` to verify that discovered domains resolve before sending them to `httpx`. This helps reduce noise and speeds up the alive check step.

## Error Handling

The script includes comprehensive error handling that will:

- Check for required dependencies before starting
- Validate command-line arguments
- Handle file operation errors
- Properly manage interruptions with Ctrl+C
- Report errors with timestamps

Each error type has a specific exit code to help diagnose issues in automated environments.
