# ScopeWatch
## Advanced Attack Surface Reconnaissance & Vulnerability Pipeline

ScopeWatch is an automated pipeline designed to take a domain (or a list of domains) and move through discovery, port scanning, and vulnerability assessment, delivering a human-readable report and real-time Discord notifications.

## Quick Start
1. Install Dependencies
Ensure you have the required tools installed on your Linux system.
```
chmod +x install-deps.sh
./install-deps.sh
source ~/.$(basename $SHELL)rc
```
2. Configuration (Optional)
Create a `.env` file in the project root to store your keys and IDs.
```
# .env
# .env
CHAOS_KEY="your_api_key_here"
RESULTS_WEBHOOK="https://discord.com/api/webhooks/..."
STATUS_WEBHOOK="https://discord.com/api/webhooks/..."
DISCORD_USER_ID="123456789012345678"
```
3. Run a Scan
```
# Single domain
./scopewatch.sh example.com

# List of domains with custom rate and ports
./scopewatch.sh targets.txt --rate 100 -p 80,443,8080
```
## The Pipeline Stages
1. Discovery: Combines `subfinder`, `gau`, and `chaos` for deep subdomain enumeration.
2. Resolution: Validates findings using `dnsx` with smart system fallbacks.
3. Probing: Identifies live web services via `httpx`.
4. Crawling: Deep JS and endpoint discovery using `katana`.
5. CIDR Filtering: Ensures scans stay within defined IP boundaries.
6. Naabu: Fast port discovery with integrated `nmap` service fingerprinting.
7. Nuclei: Template-based vulnerability scanning (CRITICAL to INFO).
8. Reporting: Generates a clean `vulnerabilities.txt` for human review.
9. Discord: Sends a summary report and pings your user ID.

## Project Structure
- `scopewatch.sh`: The Manager. Handles input loops and dependency checks.
- `engine.sh`: The Engine. Executes the 9-stage scanning logic.
- `install-deps.sh`: The Installer. Sets up the Go environment and PD tools.
- `.env`: The Vault. Stores sensitive API keys and IDs.

## Options & Flags
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-d, --domain` | Target single domain | Required (if no file) |
| `-f, --file` | File containing subdomains | - |
| `-p, --ports` | Port range or top-ports | `1-65535` |
| `-s, --severity` | Nuclei severities to scan | `info,low,medium,high,critical` |
| `--rate` | Requests Per Second (RPS) | `60` |
| `--threads` | Concurrent scan threads | `10` |
| `--cidr-file` | IP range filter | `cidr_ranges.txt` |

## Requirements
- Operating System: Linux (Ubuntu/Debian preferred)
- Language: Go 1.20+
- Permissions: sudo access (for initial tool installation)

## Acknowledgements

A massive shoutout to the **[ProjectDiscovery Team](https://github.com/projectdiscovery)** for their incredible work. This pipeline is built entirely on their suite of high-performance security tools.

| Tool | Purpose | Link |
| :--- | :--- | :--- |
| **Subfinder** | Subdomain Discovery | [Repo](https://github.com/projectdiscovery/subfinder) |
| **Dnsx** | DNS Resolution | [Repo](https://github.com/projectdiscovery/dnsx) |
| **Httpx** | HTTP Probing | [Repo](https://github.com/projectdiscovery/httpx) |
| **Naabu** | Port Scanning | [Repo](https://github.com/projectdiscovery/naabu) |
| **Nuclei** | Vulnerability Scanning | [Repo](https://github.com/projectdiscovery/nuclei) |
| **Katana** | Web Crawling | [Repo](https://github.com/projectdiscovery/katana) |
