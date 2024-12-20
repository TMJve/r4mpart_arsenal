# R4mpart Arsenal 🛡️

**R4mpart Arsenal** is a modular CLI framework for web application pentesting and bug bounty hunting. It's designed to automate various tasks, including reconnaissance, subdomain enumeration, port scanning, vulnerability detection, and more. With built-in support for powerful tools like **Subfinder** and **httpx**, R4mpart Arsenal streamlines your pentesting workflow.

![R4mpart Arsenal CLI](https://via.placeholder.com/800x200) <!-- Add your logo or banner here -->

---

## Features 🚀

- **Subdomain Enumeration**: Uses Subfinder to discover subdomains of a target.
- **Reachability Check**: Integrates with httpx to verify subdomain reachability and check status codes.
- **DNS Lookup**: Perform DNS enumeration on discovered subdomains.
- **Port Scanning**: Run port scans on subdomains to discover open services (Nmap integration coming soon!).
- **SSL/TLS Analysis**: Analyze SSL certificates of target domains.
- **Modular Architecture**: Extendable design allows easy addition of new tools and modules.

---

## Getting Started 💻

### Prerequisites
Make sure you have Go installed. Install [Go](https://golang.org/doc/install) if you haven't already.

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/r4mpartArsenal.git
    cd r4mpartArsenal
    ```

2. Install dependencies:
    ```bash
    go mod tidy
    ```

3. Build the project:
    ```bash
    go build -o r4mpartArsenal
    ```

4. (Optional) Install the executable globally:
    ```bash
    sudo mv r4mpartArsenal /usr/local/bin/
    ```

---

## Usage 🛠️

R4mpart Arsenal offers various commands for recon and pentesting. Here’s how to get started:

### Basic Subdomain Enumeration:
```bash
r4mpartArsenal recon example.com --subdomains
