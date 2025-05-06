#!/bin/bash

# Script version
VERSION="1.3.0"

# Exit codes
SUCCESS=0
ERROR_DEPENDENCY=1
ERROR_ARGUMENT=2
ERROR_FILE_OPERATION=3
ERROR_INTERRUPTED=4

# Default values
VERBOSE=false
QUIET=false
CLEANUP=false
RATE_LIMIT=""
OUTPUT_DIR="."
JSON_OUTPUT=false
STATUS_CODE_FILTER=""
NO_AUTH=false
AUTH_ONLY=false
CHUNK_SIZE=1000
RESUME=false
SHOW_PROGRESS=true
TEMP_FILES=("mainsubdomain.txt")
RESUME_FILE=""

# Track start time for duration calculation
START_TIME=$(date +%s)

# Function to print timestamp
timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

# Function to print verbose messages
verbose_echo() {
  if $VERBOSE && ! $QUIET; then
    echo "[$(timestamp)] [VERBOSE] $1"
  fi
}

# Function to print info messages
info_echo() {
  if ! $QUIET; then
    echo "[$(timestamp)] [INFO] $1"
  fi
}

# Function to format time in hh:mm:ss
format_time() {
  local total_seconds=$1
  local hours=$((total_seconds / 3600))
  local minutes=$(((total_seconds % 3600) / 60))
  local seconds=$((total_seconds % 60))
  printf '%02d:%02d:%02d' $hours $minutes $seconds
}

# Function to print progress messages with elapsed time
progress_echo() {
  if ! $QUIET; then
    local elapsed=$(($(date +%s) - START_TIME))
    local elapsed_fmt=$(format_time $elapsed)
    echo "[$(timestamp)] [PROGRESS] [$elapsed_fmt] $1"
  fi
}

# Function to print error messages
error_echo() {
  echo "[$(timestamp)] [ERROR] $1" >&2
}

# Function to print warning messages
warning_echo() {
  echo "[$(timestamp)] [WARNING] $1" >&2
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
  local missing_deps=()
  
  if ! command_exists subfinder; then
    missing_deps+=("subfinder")
  fi
  
  if ! command_exists assetfinder; then
    missing_deps+=("assetfinder")
  fi
  
  if ! command_exists httpx; then
    missing_deps+=("httpx")
  fi
  
  # Check for required utilities
  if ! command_exists awk; then
    missing_deps+=("awk")
  fi
  
  if ! command_exists grep; then
    missing_deps+=("grep")
  fi
  
  if ! command_exists sort; then
    missing_deps+=("sort")
  fi
  
  if [ ${#missing_deps[@]} -ne 0 ]; then
    error_echo "Missing dependencies: ${missing_deps[*]}"
    echo ""
    echo "Installation instructions:"
    echo "  - subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  - assetfinder: go install -v github.com/tomnomnom/assetfinder@latest"
    echo "  - httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    
    if [[ " ${missing_deps[*]} " =~ " awk " || " ${missing_deps[*]} " =~ " grep " || " ${missing_deps[*]} " =~ " sort " ]]; then
      echo "  - Core utilities (awk, grep, sort): These should be available on most systems."
      echo "    On macOS: brew install coreutils"
      echo "    On Ubuntu/Debian: apt-get install coreutils"
    fi
    
    exit $ERROR_DEPENDENCY
  fi
  
  # Check bash version
  local bash_version=${BASH_VERSINFO[0]}
  if [[ -z "$bash_version" || "$bash_version" -lt 4 ]]; then
    warning_echo "Running on Bash version < 4 ($BASH_VERSION). Some features will use fallback methods."
    warning_echo "For better performance, consider upgrading to Bash 4+ (macOS users: brew install bash)"
  fi
}

# Function to clean up temporary files
cleanup_files() {
  if $CLEANUP; then
    info_echo "Cleaning up temporary files..."
    for file in "${TEMP_FILES[@]}"; do
      if [ -f "$OUTPUT_DIR/$file" ]; then
        verbose_echo "Removing $OUTPUT_DIR/$file"
        rm -f "$OUTPUT_DIR/$file" || error_echo "Failed to remove $OUTPUT_DIR/$file"
      fi
    done
  fi
}

# Function to display progress bar
show_progress_bar() {
  local current=$1
  local total=$2
  local width=50
  
  # Prevent division by zero
  if [[ $total -eq 0 ]]; then
    total=1
  fi
  
  # Calculate progress metrics (using integer arithmetic only)
  local percent=$((current * 100 / total))
  local filled=$((width * current / total))
  
  # Prevent negative or overflow values
  if [[ $filled -lt 0 ]]; then
    filled=0
  elif [[ $filled -gt $width ]]; then
    filled=$width
  fi
  
  local empty=$((width - filled))
  
  # Calculate remaining time (using integer arithmetic only)
  local elapsed=$(($(date +%s) - START_TIME))
  local remaining_fmt="calculating..."
  
  if [[ $current -gt 0 ]]; then
    # Use a better rate calculation - time per item
    # Adding 1 to both numerator and denominator prevents division by zero
    # and provides better estimates at the start
    local rate=$(( (elapsed + 1) / (current + 1) ))
    
    # If rate is 0, use a small value to avoid division by zero
    if [[ $rate -eq 0 ]]; then
      rate=1
    fi
    
    # Calculate remaining time in seconds
    local remaining=$(( rate * (total - current) ))
    
    # Format remaining time
    remaining_fmt=$(format_time $remaining)
  fi
  
  # Create the fill string using a more compatible approach
  local fill_str=""
  local i=0
  for ((i=0; i<filled; i++)); do
    fill_str="${fill_str}#"
  done
  
  local empty_str=""
  for ((i=0; i<empty; i++)); do
    empty_str="${empty_str} "
  done
  
  # Create the progress bar with clear-to-end-of-line escape sequence
  printf "\r[%s%s] %3d%% (%d/%d) ETA: %s\033[K" "$fill_str" "$empty_str" $percent $current $total "$remaining_fmt"
}

# Function to save resume state
save_resume_state() {
  local state_file="$OUTPUT_DIR/resume_state.json"
  
  # Create the resume state
  cat > "$state_file" << EOF
{
  "domain": "$DOMAIN",
  "timestamp": "$(timestamp)",
  "completed_chunks": $COMPLETED_CHUNKS,
  "total_chunks": $TOTAL_CHUNKS,
  "processed_subdomains": $PROCESSED,
  "total_subdomains": $SUBDOMAIN_COUNT,
  "alive_count": $ALIVE_COUNT,
  "last_chunk": $CURRENT_CHUNK,
  "options": {
    "rate_limit": "$RATE_LIMIT",
    "status_filter": "$STATUS_CODE_FILTER",
    "no_auth": $NO_AUTH,
    "auth_only": $AUTH_ONLY,
    "chunk_size": $CHUNK_SIZE
  }
}
EOF
  
  info_echo "Resume state saved to $state_file"
  RESUME_FILE="$state_file"
}

# Function to handle script interruption
handle_interrupt() {
  echo ""
  error_echo "Script interrupted by user"
  
  # Calculate progress (with safeguard against division by zero)
  local percent=0
  if [[ $SUBDOMAIN_COUNT -gt 0 ]]; then
    percent=$((PROCESSED * 100 / SUBDOMAIN_COUNT))
  fi
  
  # Calculate elapsed time
  local elapsed=$(($(date +%s) - START_TIME))
  local elapsed_fmt=$(format_time $elapsed)
  
  # Report progress
  echo ""
  echo "Progress Summary:"
  echo "-------------------------"
  echo "Domain: $DOMAIN"
  echo "Total Subdomains: $SUBDOMAIN_COUNT"
  echo "Processed: $PROCESSED ($percent%)"
  echo "Alive Subdomains Found: $ALIVE_COUNT"
  echo "Elapsed Time: $elapsed_fmt"
  echo "-------------------------"
  
  # Save resume state if we've made progress
  if [[ $PROCESSED -gt 0 ]]; then
    save_resume_state
    echo "You can resume this scan later with:"
    echo "$0 --resume $RESUME_FILE $DOMAIN"
  fi
  
  cleanup_files
  exit $ERROR_INTERRUPTED
}

# Register the interrupt handler
trap handle_interrupt SIGINT SIGTERM

# Function to display help message
show_help() {
  echo "Subdomain Finder Automation Script v$VERSION"
  echo ""
  echo "Usage: $0 [OPTIONS] <domain>"
  echo ""
  echo "Options:"
  echo "  -h, --help              Show this help message and exit"
  echo "  -V, --version           Display version information and exit"
  echo "  -v, --verbose           Enable verbose output"
  echo "  -q, --quiet             Suppress non-error messages"
  echo "  -c, --cleanup           Remove temporary files after execution"
  echo "  -r, --rate-limit RATE   Set rate limit for httpx (e.g., '100' for 100 requests/second)"
  echo "  -o, --output-dir DIR    Specify output directory (default: current directory)"
  echo "  -j, --json              Output results in JSON format"
  echo "  -s, --status-code CODE  Filter results by status code (e.g., '200' or '200,301,302')"
  echo "  --no-auth               Filter out authentication-based URLs (containing @ symbol)"
  echo "  --auth-only             Show only authentication-based URLs"
  echo "  --chunk-size SIZE       Process subdomains in chunks of SIZE (default: 1000)"
  echo "  --resume FILE           Resume from a previous scan state file"
  echo "  --no-progress           Disable progress bar display"
  echo ""
  echo "Examples:"
  echo "  $0 example.com                        # Basic usage"
  echo "  $0 -v -c example.com                  # Verbose mode with cleanup"
  echo "  $0 -r 50 -o /path/to/output example.com  # Rate limited with custom output directory"
  echo "  $0 -j example.com                     # JSON output format"
  echo "  $0 -s 200 example.com                 # Filter by status code 200"
  echo "  $0 --no-auth example.com              # Filter out auth-based URLs"
  echo "  $0 --chunk-size 500 example.com       # Process in smaller chunks"
  echo "  $0 --resume state.json example.com    # Resume an interrupted scan"
  echo ""
}

# Function to display version information
show_version() {
  echo "Subdomain Finder Automation Script v$VERSION"
  echo "Author: Parth Mishra"
  echo "Repository: https://github.com/parthmishra24/Subdomain-Enumerator"
}

# Parse command line arguments
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      exit $SUCCESS
      ;;
    -V|--version)
      show_version
      exit $SUCCESS
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -q|--quiet)
      QUIET=true
      shift
      ;;
    -c|--cleanup)
      CLEANUP=true
      shift
      ;;
    -j|--json)
      JSON_OUTPUT=true
      shift
      ;;
    -s|--status-code)
      if [[ -z "$2" || "$2" =~ ^- ]]; then
        error_echo "Error: --status-code requires an argument (e.g., '200' or '200,301')"
        exit $ERROR_ARGUMENT
      fi
      STATUS_CODE_FILTER="$2"
      shift 2
      ;;
    --no-auth)
      NO_AUTH=true
      if $AUTH_ONLY; then
        error_echo "Error: --no-auth and --auth-only cannot be used together"
        exit $ERROR_ARGUMENT
      fi
      shift
      ;;
    --auth-only)
      AUTH_ONLY=true
      if $NO_AUTH; then
        error_echo "Error: --no-auth and --auth-only cannot be used together"
        exit $ERROR_ARGUMENT
      fi
      shift
      ;;
    --chunk-size)
      if [[ -z "$2" || "$2" =~ ^- ]]; then
        error_echo "Error: --chunk-size requires a numeric argument"
        exit $ERROR_ARGUMENT
      fi
      CHUNK_SIZE="$2"
      # Validate chunk size is a positive number
      if ! [[ "$CHUNK_SIZE" =~ ^[0-9]+$ ]] || [[ "$CHUNK_SIZE" -le 0 ]]; then
        error_echo "Error: chunk size must be a positive number"
        exit $ERROR_ARGUMENT
      fi
      shift 2
      ;;
    --resume)
      if [[ -z "$2" || "$2" =~ ^- ]]; then
        error_echo "Error: --resume requires a state file path"
        exit $ERROR_ARGUMENT
      fi
      RESUME_FILE="$2"
      RESUME=true
      if [[ ! -f "$RESUME_FILE" ]]; then
        error_echo "Error: resume state file not found: $RESUME_FILE"
        exit $ERROR_FILE_OPERATION
      fi
      shift 2
      ;;
    --no-progress)
      SHOW_PROGRESS=false
      shift
      ;;
    -r|--rate-limit)
      if [[ -z "$2" || "$2" =~ ^- ]]; then
        error_echo "Error: --rate-limit requires a numeric argument"
        exit $ERROR_ARGUMENT
      fi
      RATE_LIMIT="$2"
      shift 2
      ;;
    -o|--output-dir)
      if [[ -z "$2" || "$2" =~ ^- ]]; then
        error_echo "Error: --output-dir requires a directory path"
        exit $ERROR_ARGUMENT
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -*)
      error_echo "Unknown option: $1"
      echo "Use '$0 --help' for usage information"
      exit $ERROR_ARGUMENT
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

# Restore positional arguments
set -- "${POSITIONAL_ARGS[@]}"

# Check if output directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
  info_echo "Creating output directory: $OUTPUT_DIR"
  mkdir -p "$OUTPUT_DIR" || {
    error_echo "Failed to create output directory: $OUTPUT_DIR"
    exit $ERROR_FILE_OPERATION
  }
fi

# Check if a domain is provided
if [ -z "$1" ]; then
  error_echo "No domain specified"
  echo "Use '$0 --help' for usage information"
  exit $ERROR_ARGUMENT
fi

DOMAIN="$1"

# Check dependencies
check_dependencies

# Prepare file paths
MAIN_SUBDOMAIN_FILE="$OUTPUT_DIR/mainsubdomain.txt"
ALIVE_SUBDOMAIN_FILE="$OUTPUT_DIR/alive_subdomain.txt"
JSON_OUTPUT_FILE="$OUTPUT_DIR/results.json"
ALL_SUBDOMAINS_FILE="$OUTPUT_DIR/all_subdomains.txt"
FILTERED_OUTPUT_FILE="$OUTPUT_DIR/filtered_results.txt"

# Build httpx command
HTTPX_CMD="httpx -sc"
if [ -n "$RATE_LIMIT" ]; then
  HTTPX_CMD="$HTTPX_CMD -rate-limit $RATE_LIMIT"
  verbose_echo "Using rate limit: $RATE_LIMIT requests/second"
fi

# Run subfinder and assetfinder, sort, and remove duplicates
info_echo "Running subfinder for domain: $DOMAIN"
{
  verbose_echo "Executing: subfinder -d $DOMAIN -all"
  progress_echo "Starting subdomain enumeration with subfinder..."
  
  if ! subfinder -d "$DOMAIN" -all; then
    error_echo "Subfinder failed or returned non-zero exit code"
    error_echo "Try running 'subfinder -d $DOMAIN -all' directly to see the error"
    exit $ERROR_DEPENDENCY
  fi
  
  progress_echo "Subfinder completed, now running assetfinder..."
  info_echo "Running assetfinder for domain: $DOMAIN"
  verbose_echo "Executing: assetfinder -subs-only $DOMAIN"
  
  if ! assetfinder -subs-only "$DOMAIN"; then
    error_echo "Assetfinder failed or returned non-zero exit code"
    error_echo "Try running 'assetfinder -subs-only $DOMAIN' directly to see the error"
    exit $ERROR_DEPENDENCY
  fi
  
  progress_echo "Assetfinder completed, now processing results..."
} | sort -u > "$MAIN_SUBDOMAIN_FILE" || {
  error_echo "Failed to write to $MAIN_SUBDOMAIN_FILE"
  exit $ERROR_FILE_OPERATION
}

# Count discovered subdomains
if [ -f "$MAIN_SUBDOMAIN_FILE" ]; then
  SUBDOMAIN_COUNT=$(wc -l < "$MAIN_SUBDOMAIN_FILE" | tr -d ' ')
  info_echo "Found $SUBDOMAIN_COUNT unique subdomains"
else
  error_echo "Failed to create $MAIN_SUBDOMAIN_FILE"
  exit $ERROR_FILE_OPERATION
fi

# Keep a copy of all discovered subdomains
cp "$MAIN_SUBDOMAIN_FILE" "$ALL_SUBDOMAINS_FILE" || {
  error_echo "Failed to create backup of discovered subdomains"
  exit $ERROR_FILE_OPERATION
}

# Initialize chunk processing variables
TOTAL_CHUNKS=$(( (SUBDOMAIN_COUNT + CHUNK_SIZE - 1) / CHUNK_SIZE ))
COMPLETED_CHUNKS=0
CURRENT_CHUNK=1
PROCESSED=0
ALIVE_COUNT=0

# Create temporary directory for chunks
CHUNK_DIR=$(mktemp -d)
TEMP_FILES+=("$CHUNK_DIR")

# Check if resume was requested
if $RESUME && [[ -f "$RESUME_FILE" ]]; then
  info_echo "Resuming from state file: $RESUME_FILE"
  
  # Extract resume data
  if command_exists jq; then
    # Use jq if available
    CURRENT_CHUNK=$(jq -r '.last_chunk // 1' "$RESUME_FILE")
    COMPLETED_CHUNKS=$(jq -r '.completed_chunks // 0' "$RESUME_FILE")
    PROCESSED=$(jq -r '.processed_subdomains // 0' "$RESUME_FILE")
    ALIVE_COUNT=$(jq -r '.alive_count // 0' "$RESUME_FILE")
    
    # Validate the domain matches
    RESUME_DOMAIN=$(jq -r '.domain // ""' "$RESUME_FILE")
    if [[ "$RESUME_DOMAIN" != "$DOMAIN" ]]; then
      warning_echo "Resume state is for domain '$RESUME_DOMAIN', but current domain is '$DOMAIN'"
      warning_echo "Continuing anyway, but results may be inconsistent"
    fi
    
    # Check for option overrides
    if [[ -z "$RATE_LIMIT" ]]; then
      RESUME_RATE_LIMIT=$(jq -r '.options.rate_limit // ""' "$RESUME_FILE")
      if [[ -n "$RESUME_RATE_LIMIT" ]]; then
        RATE_LIMIT="$RESUME_RATE_LIMIT"
        verbose_echo "Resumed rate limit: $RATE_LIMIT"
      fi
    fi
    
    if [[ -z "$STATUS_CODE_FILTER" ]]; then
      RESUME_STATUS_FILTER=$(jq -r '.options.status_filter // ""' "$RESUME_FILE")
      if [[ -n "$RESUME_STATUS_FILTER" ]]; then
        STATUS_CODE_FILTER="$RESUME_STATUS_FILTER"
        verbose_echo "Resumed status filter: $STATUS_CODE_FILTER"
      fi
    fi
    
    RESUME_CHUNK_SIZE=$(jq -r '.options.chunk_size // 1000' "$RESUME_FILE")
    if [[ "$CHUNK_SIZE" -ne "$RESUME_CHUNK_SIZE" ]]; then
      warning_echo "Original scan used chunk size $RESUME_CHUNK_SIZE, but current chunk size is $CHUNK_SIZE"
      warning_echo "Using original chunk size for consistency"
      CHUNK_SIZE="$RESUME_CHUNK_SIZE"
    fi
  else
    # Basic parsing with grep if jq is not available
    warning_echo "jq not found, using basic resume state parsing"
    CURRENT_CHUNK=$(grep -o '"last_chunk": [0-9]\+' "$RESUME_FILE" | grep -o '[0-9]\+' || echo "1")
    COMPLETED_CHUNKS=$(grep -o '"completed_chunks": [0-9]\+' "$RESUME_FILE" | grep -o '[0-9]\+' || echo "0")
    PROCESSED=$(grep -o '"processed_subdomains": [0-9]\+' "$RESUME_FILE" | grep -o '[0-9]\+' || echo "0")
    ALIVE_COUNT=$(grep -o '"alive_count": [0-9]\+' "$RESUME_FILE" | grep -o '[0-9]\+' || echo "0")
  fi
fi

# Process subdomains in chunks
info_echo "Processing $SUBDOMAIN_COUNT subdomains in chunks of $CHUNK_SIZE (total: $TOTAL_CHUNKS chunks)"

# Create or append to alive subdomains file
if [[ ! -f "$ALIVE_SUBDOMAIN_FILE" || ! $RESUME ]]; then
  # Create new file if not resuming or file doesn't exist
  > "$ALIVE_SUBDOMAIN_FILE"
fi

# Process subdomains in chunks
for ((i=CURRENT_CHUNK; i<=TOTAL_CHUNKS; i++)); do
  # Calculate chunk start and end
  CHUNK_START=$(( (i-1) * CHUNK_SIZE + 1 ))
  CHUNK_END=$(( i * CHUNK_SIZE ))
  if [[ $CHUNK_END -gt $SUBDOMAIN_COUNT ]]; then
    CHUNK_END=$SUBDOMAIN_COUNT
  fi
  
  # Calculate chunk size
  CURRENT_CHUNK_SIZE=$((CHUNK_END - CHUNK_START + 1))
  
  # Display progress information
  progress_echo "Processing chunk $i/$TOTAL_CHUNKS (subdomains $CHUNK_START-$CHUNK_END)"
  
  # Extract current chunk to temporary file
  CHUNK_FILE="$CHUNK_DIR/chunk_$i.txt"
  sed -n "${CHUNK_START},${CHUNK_END}p" "$MAIN_SUBDOMAIN_FILE" > "$CHUNK_FILE"
  
  # Show progress bar if enabled
  if $SHOW_PROGRESS; then
    show_progress_bar $PROCESSED $SUBDOMAIN_COUNT
  fi
  
# Run httpx on the current chunk
  CHUNK_OUTPUT="$CHUNK_DIR/output_$i.txt"
  
  # Run with error handling
  if cat "$CHUNK_FILE" | eval "$HTTPX_CMD" > "$CHUNK_OUTPUT" 2>/dev/null; then
    # Process was successful
    
    # Count alive subdomains in this chunk (with error handling)
    if [[ -f "$CHUNK_OUTPUT" ]]; then
      CHUNK_ALIVE_COUNT=$(wc -l < "$CHUNK_OUTPUT" 2>/dev/null | tr -d ' ')
      # Ensure count is a valid number, default to 0 if not
      if ! [[ "$CHUNK_ALIVE_COUNT" =~ ^[0-9]+$ ]]; then
        CHUNK_ALIVE_COUNT=0
      fi
    else
      CHUNK_ALIVE_COUNT=0
    fi
    
    # Append results to main output file (if output file exists)
    if [[ -f "$CHUNK_OUTPUT" ]]; then
      cat "$CHUNK_OUTPUT" >> "$ALIVE_SUBDOMAIN_FILE"
    fi
    
    # Update progress
    PROCESSED=$((PROCESSED + CURRENT_CHUNK_SIZE))
    ALIVE_COUNT=$((ALIVE_COUNT + CHUNK_ALIVE_COUNT))
    COMPLETED_CHUNKS=$((COMPLETED_CHUNKS + 1))
    CURRENT_CHUNK=$((i + 1))
    
    # Save resume state periodically only for larger domains
    # Only save if:
    # - Domain is large (>1000 subdomains)
    # - Every 5 chunks or at the end of processing
    if [[ $SUBDOMAIN_COUNT -gt 1000 && ($((i % 5)) -eq 0 || $i -eq $TOTAL_CHUNKS) ]]; then
      verbose_echo "Saving resume state for large domain scan..."
      save_resume_state
    fi
    
    # Cleanup chunk files to save space
    rm -f "$CHUNK_FILE" "$CHUNK_OUTPUT"
    
    # Progress update
    if ! $QUIET && $SHOW_PROGRESS; then
      show_progress_bar $PROCESSED $SUBDOMAIN_COUNT
      echo ""
    fi
    
    verbose_echo "Chunk $i/$TOTAL_CHUNKS complete: $CHUNK_ALIVE_COUNT alive subdomains found"
  else
    # Process failed
    error_echo "Failed to process chunk $i/$TOTAL_CHUNKS (subdomains $CHUNK_START-$CHUNK_END)"
    error_echo "Try running the command directly to see the error"
    
    # Save resume state to allow resuming from failure
    save_resume_state
    
    # Clean up and exit
    cleanup_files
    exit $ERROR_DEPENDENCY
  fi
done

# Final progress update
if $SHOW_PROGRESS; then
  show_progress_bar $SUBDOMAIN_COUNT $SUBDOMAIN_COUNT
  echo ""
fi

# Count alive subdomains
if [ -f "$ALIVE_SUBDOMAIN_FILE" ]; then
  ALIVE_COUNT=$(wc -l < "$ALIVE_SUBDOMAIN_FILE" | tr -d ' ')
  info_echo "Found $ALIVE_COUNT alive subdomains out of $SUBDOMAIN_COUNT"
else
  error_echo "Failed to create $ALIVE_SUBDOMAIN_FILE"
  exit $ERROR_FILE_OPERATION
fi

# Apply filtering if requested
FILTERED_OUTPUT="$ALIVE_SUBDOMAIN_FILE"

# Create a temporary file for the filtered results
if [[ -n "$STATUS_CODE_FILTER" || "$NO_AUTH" == "true" || "$AUTH_ONLY" == "true" ]]; then
  info_echo "Applying filters to results..."
  
  # Create a temporary file
  cat "$ALIVE_SUBDOMAIN_FILE" > "$FILTERED_OUTPUT_FILE"
  FILTERED_OUTPUT="$FILTERED_OUTPUT_FILE"
  
# Filter by status code if requested
  if [[ -n "$STATUS_CODE_FILTER" ]]; then
    verbose_echo "Filtering by status code: $STATUS_CODE_FILTER"
    
    # Replace commas with pipes for grep pattern
    GREP_PATTERN=$(echo "$STATUS_CODE_FILTER" | tr ',' '|')
    
    # Temporary file for filter results
    FILTER_TMP=$(mktemp)
    TEMP_FILES+=("$FILTER_TMP")
    
    # Build grep pattern with word boundaries to ensure exact matches
    if [[ -f "$ALIVE_SUBDOMAIN_FILE" ]]; then
      while read -r line; do
        for status_code in $(echo "$STATUS_CODE_FILTER" | tr ',' ' '); do
          if [[ "$line" =~ \[($status_code)\] ]]; then
            echo "$line" >> "$FILTER_TMP"
            break
          fi
        done
      done < "$ALIVE_SUBDOMAIN_FILE"
    else
      warning_echo "Alive subdomains file not found: $ALIVE_SUBDOMAIN_FILE"
      touch "$FILTER_TMP"
    fi
    
    # Check if the filter found any matches
    if [[ -s "$FILTER_TMP" ]]; then
      # Copy filtered results to output file
      cat "$FILTER_TMP" > "$FILTERED_OUTPUT_FILE"
      verbose_echo "Found $(wc -l < "$FILTER_TMP" | tr -d ' ') subdomains with status code(s): $STATUS_CODE_FILTER"
    else
      # If no matches, create an empty file
      > "$FILTERED_OUTPUT_FILE"
      verbose_echo "No subdomains found with status code(s): $STATUS_CODE_FILTER"
    fi
    
    # Clean up temporary file
    rm -f "$FILTER_TMP"
  fi
  
  # Filter auth-based URLs if requested
  if [[ "$NO_AUTH" == "true" ]]; then
    verbose_echo "Filtering out authentication-based URLs"
    
    # Use grep to exclude lines containing '@' in the URL
    grep -v "@" "$FILTERED_OUTPUT_FILE" > "$FILTERED_OUTPUT_FILE.tmp" && mv "$FILTERED_OUTPUT_FILE.tmp" "$FILTERED_OUTPUT_FILE"
  fi
  
  # Show only auth-based URLs if requested
  if [[ "$AUTH_ONLY" == "true" ]]; then
    verbose_echo "Showing only authentication-based URLs"
    
    # Use grep to include only lines containing '@' in the URL
    grep "@" "$FILTERED_OUTPUT_FILE" > "$FILTERED_OUTPUT_FILE.tmp" && mv "$FILTERED_OUTPUT_FILE.tmp" "$FILTERED_OUTPUT_FILE"
  fi
  
  # Count filtered results
  FILTERED_COUNT=$(wc -l < "$FILTERED_OUTPUT_FILE" | tr -d ' ')
  info_echo "After filtering: $FILTERED_COUNT subdomains"
fi

# Calculate time statistics
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_FORMAT=$(printf '%02d:%02d:%02d' $((DURATION/3600)) $((DURATION%3600/60)) $((DURATION%60)))

# Function to calculate statistics about discovered subdomains
calculate_statistics() {
  # Count auth-based URLs
  AUTH_COUNT=$(grep -c "@" "$ALIVE_SUBDOMAIN_FILE" || echo "0")

  # Create empty status distribution variables
  STATUS_DISTRIBUTION_STR=""
  STATUS_CODES_JSON=""
  
  # Process the alive subdomains file to create status distribution
  if [[ -f "$ALIVE_SUBDOMAIN_FILE" && -s "$ALIVE_SUBDOMAIN_FILE" ]]; then
    # Extract status codes and their counts directly
    while read -r status_code count; do
      # Add to the display string
      STATUS_DISTRIBUTION_STR+="    - Status $status_code: $count"$'\n'
      
      # Add to the JSON format
      if [[ -z "$STATUS_CODES_JSON" ]]; then
        STATUS_CODES_JSON+="      \"$status_code\": $count"
      else
        STATUS_CODES_JSON+=",$'\n'      \"$status_code\": $count"
      fi
    done < <(grep -o '\[[0-9]\+\]' "$ALIVE_SUBDOMAIN_FILE" | tr -d '[]' | sort | uniq -c | awk '{print $2, $1}')
  fi

  # Handle empty or missing file case
  if [[ -z "$STATUS_DISTRIBUTION_STR" ]]; then
    STATUS_DISTRIBUTION_STR="    (No status codes found)"
    STATUS_CODES_JSON=""
  fi
  
  # If bash 4+ is available, also populate the associative array for advanced functionality
  if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
    declare -A STATUS_DISTRIBUTION
    while read -r status_code count; do
      STATUS_DISTRIBUTION["$status_code"]=$count
    done < <(grep -o '\[[0-9]\+\]' "$ALIVE_SUBDOMAIN_FILE" | tr -d '[]' | sort | uniq -c | awk '{print $2, $1}' 2>/dev/null || echo "")
    
    verbose_echo "Using associative arrays for additional status code processing"
  else
    verbose_echo "Using fallback method for status code distribution (Bash < 4)"
  fi
}

# Function to generate JSON output
generate_json_output() {
  info_echo "Generating JSON output..."
  
  # Create a temporary file for the JSON structure
  local JSON_TEMP_FILE=$(mktemp)
  
  # Begin JSON object
  echo "{" > "$JSON_TEMP_FILE"
  
  # Add scan metadata
  echo "  \"metadata\": {" >> "$JSON_TEMP_FILE"
  echo "    \"domain\": \"$DOMAIN\"," >> "$JSON_TEMP_FILE"
  echo "    \"timestamp\": \"$(timestamp)\"," >> "$JSON_TEMP_FILE"
  echo "    \"duration_seconds\": $DURATION," >> "$JSON_TEMP_FILE"
  echo "    \"duration_formatted\": \"$DURATION_FORMAT\"" >> "$JSON_TEMP_FILE"
  echo "  }," >> "$JSON_TEMP_FILE"
  
  # Add statistics
  echo "  \"statistics\": {" >> "$JSON_TEMP_FILE"
  echo "    \"total_subdomains\": $SUBDOMAIN_COUNT," >> "$JSON_TEMP_FILE"
  echo "    \"alive_subdomains\": $ALIVE_COUNT," >> "$JSON_TEMP_FILE"
  echo "    \"auth_based_urls\": $AUTH_COUNT," >> "$JSON_TEMP_FILE"
  
  # Add status code distribution
  echo "    \"status_distribution\": {" >> "$JSON_TEMP_FILE"
  
  # Check if we have the JSON string prepared by calculate_statistics
  if [[ -n "$STATUS_CODES_JSON" ]]; then
    # Use the pre-formatted JSON string
    echo -e "$STATUS_CODES_JSON" >> "$JSON_TEMP_FILE"
  else
    # Fallback for when STATUS_CODES_JSON is empty or not set
    echo "      \"info\": \"No status codes found\"" >> "$JSON_TEMP_FILE"
  fi
  
  echo "    }" >> "$JSON_TEMP_FILE"
  
  echo "  }," >> "$JSON_TEMP_FILE"
  
  # Add all discovered subdomains
  echo "  \"all_subdomains\": [" >> "$JSON_TEMP_FILE"
  
  # Read all subdomains file line by line
  local line_count=0
  local total_lines=$(wc -l < "$ALL_SUBDOMAINS_FILE" | tr -d ' ')
  
  # If file is empty, just close the array
  if [[ $total_lines -eq 0 ]]; then
    echo "  ]," >> "$JSON_TEMP_FILE"
  else
    while IFS= read -r line; do
      line_count=$((line_count + 1))
      
      # Escape any quotes in the subdomain
      line="${line//\"/\\\"}"
      
      # Add comma for all but the last item
      if [[ $line_count -lt $total_lines ]]; then
        echo "    \"$line\"," >> "$JSON_TEMP_FILE"
      else
        echo "    \"$line\"" >> "$JSON_TEMP_FILE"
      fi
    done < "$ALL_SUBDOMAINS_FILE"
    echo "  ]," >> "$JSON_TEMP_FILE"
  fi
  
  # Add alive subdomains with status codes
  echo "  \"alive_subdomains\": [" >> "$JSON_TEMP_FILE"
  
  # Read alive subdomains file line by line
  line_count=0
  total_lines=$(wc -l < "$ALIVE_SUBDOMAIN_FILE" | tr -d ' ')
  
  # If file is empty, just close the array
  if [[ $total_lines -eq 0 ]]; then
    echo "  ]" >> "$JSON_TEMP_FILE"
  else
    while IFS= read -r line; do
      line_count=$((line_count + 1))
      
      # Extract URL and status code
      if [[ "$line" =~ (.*)\[([0-9]+)\] ]]; then
        local url="${BASH_REMATCH[1]}"
        local status="${BASH_REMATCH[2]}"
        
        # Trim whitespace
        url=$(echo "$url" | xargs)
        
        # Escape any quotes in the URL
        url="${url//\"/\\\"}"
        
        # Add comma for all but the last item
        if [[ $line_count -lt $total_lines ]]; then
          echo "    {\"url\": \"$url\", \"status\": $status}," >> "$JSON_TEMP_FILE"
        else
          echo "    {\"url\": \"$url\", \"status\": $status}" >> "$JSON_TEMP_FILE"
        fi
      fi
    done < "$ALIVE_SUBDOMAIN_FILE"
    echo "  ]" >> "$JSON_TEMP_FILE"
  fi
  
  # Close the JSON object
  echo "}" >> "$JSON_TEMP_FILE"
  
  # Move the temporary file to the final JSON output file
  mv "$JSON_TEMP_FILE" "$JSON_OUTPUT_FILE"
  
  info_echo "JSON output saved to $JSON_OUTPUT_FILE"
}

# Function to display statistics summary
display_statistics() {
  if ! $QUIET; then
    echo ""
    echo "=================================="
    echo "       SUMMARY STATISTICS"
    echo "=================================="
    echo "Domain: $DOMAIN"
    echo "Scan Duration: $DURATION_FORMAT"
    echo "----------------------------------"
    echo "Total Subdomains: $SUBDOMAIN_COUNT"
    echo "Alive Subdomains: $ALIVE_COUNT"
    echo "Authentication-based URLs: $AUTH_COUNT"
    echo "----------------------------------"
    echo "Status Code Distribution:"
    echo "$STATUS_DISTRIBUTION_STR"
    echo "----------------------------------"
    
    # Show filtered results info if filters were applied
    if [[ -n "$STATUS_CODE_FILTER" || "$NO_AUTH" == "true" || "$AUTH_ONLY" == "true" ]]; then
      echo "Applied Filters:"
      if [[ -n "$STATUS_CODE_FILTER" ]]; then
        echo "  - Status Code: $STATUS_CODE_FILTER"
      fi
      if [[ "$NO_AUTH" == "true" ]]; then
        echo "  - No Authentication URLs"
      fi
      if [[ "$AUTH_ONLY" == "true" ]]; then
        echo "  - Only Authentication URLs"
      fi
      echo "Filtered Results: $FILTERED_COUNT"
      echo "----------------------------------"
    fi
    
    echo "Results saved to:"
    if [[ "$FILTERED_OUTPUT" != "$ALIVE_SUBDOMAIN_FILE" ]]; then
      echo "  - Filtered Domains: $FILTERED_OUTPUT_FILE"
    fi
    echo "  - Alive Domains: $ALIVE_SUBDOMAIN_FILE"
    echo "  - All Discovered Domains: $ALL_SUBDOMAINS_FILE"
    if $JSON_OUTPUT; then
      echo "  - JSON Results: $JSON_OUTPUT_FILE"
    fi
    echo "=================================="
    echo ""
  fi
}

# Calculate statistics
calculate_statistics

# Generate JSON output if requested
if $JSON_OUTPUT; then
  generate_json_output
fi

# Display statistics summary
display_statistics

# Clean up temporary files if requested
cleanup_files

# Clean up any temporary directories created during processing
if [[ -d "$CHUNK_DIR" ]]; then
  verbose_echo "Cleaning up chunk directory: $CHUNK_DIR"
  rm -rf "$CHUNK_DIR" || warning_echo "Failed to remove chunk directory: $CHUNK_DIR"
fi

# Clean up any other temporary files created during processing
for temp_file in $(find "$OUTPUT_DIR" -name "temp_*" 2>/dev/null); do
  verbose_echo "Cleaning up temporary file: $temp_file"
  rm -f "$temp_file" || warning_echo "Failed to remove temporary file: $temp_file"
done

# Handle resume state file according to user preferences
if [[ -f "$OUTPUT_DIR/resume_state.json" ]]; then
  if [[ "$CLEANUP" == "true" ]]; then
    verbose_echo "Removing resume state file (cleanup requested)"
    rm -f "$OUTPUT_DIR/resume_state.json" || warning_echo "Failed to remove resume state file"
  else
    if [[ $PROCESSED -eq $SUBDOMAIN_COUNT ]]; then
      verbose_echo "Keeping resume state file for reference (completed scan)"
    else
      verbose_echo "Keeping resume state file for potential later continuation (incomplete scan)"
    fi
  fi
fi

info_echo "Done. Results saved in $FILTERED_OUTPUT"
exit $SUCCESS
