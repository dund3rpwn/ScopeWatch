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

<img width="1041" height="406" alt="image" src="https://github.com/user-attachments/assets/6894f7d2-fdb3-48fa-a182-b3e5c1e09133" />


## Discord Integration
### 1. Setup Channels
For the best experience, create two separate channels in your Discord server:
- #scoping-status: For real-time "heartbeat" updates (Stage starts/stops).
- #scoping-results: For the final report and critical alerts.

### 2. Create Webhooks
- Right-click the channel -> Edit Channel.
- Go to Integrations -> Webhooks -> New Webhook.
- Copy the Webhook URL and paste it into your .env file.

### 3. Enable User Pings
If you want ScopeWatch to "tag" you when a Critical vulnerability is found:
- Go to User Settings -> Advanced.
- Enable Developer Mode.
- Right-click your own Avatar in any channel and select Copy User ID.
- Paste this ID into `DISCORD_USER_ID` in `.env`.

<img width="329" height="381" alt="image" src="https://github.com/user-attachments/assets/cbb2fb89-e8ed-411b-8ce1-009c8e2a8c02" />


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
