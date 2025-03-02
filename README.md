# Node Proxy For Managing Cursor Network Traffic

## Overview

**Node Proxy For Managing Cursor Network Traffic** is a Node.js application designed to monitor network connections associated with "Cursor" processes and dynamically block unwanted connections using Windows Firewall rules. The project includes a background process that scans active TCP connections, performs reverse DNS lookups, and blocks IPs based on configurable blocking strings. It also offers a web-based management interface (built with Express, EJS, and DataTables) for viewing and managing block rules and blocking strings.

## Features

- **Real-Time Network Monitoring:**  
  Continuously scans active TCP connections using `node-netstat`.

- **Dynamic IP Blocking:**  
  Automatically blocks remote IPs that match configurable blocking strings (e.g., "s3", "aws.amazon.com") via Windows Firewall.

- **Process Filtering:**  
  Monitors only those connections originating from processes with names that include "Cursor".

- **Reverse DNS Resolution & AWS IP Ranges:**  
  Attempts to resolve remote IP addresses for better identification, with a fallback to check AWS IP ranges for S3 endpoints.

- **Local Database:**  
  Utilizes `lowdb` to persist block rules and blocking strings.

- **Web Interface:**  
  An Express and EJS-based UI, enhanced with DataTables, allows you to view current block rules and manage blocking strings (add, delete, unblock).

- **Executable Packaging:**  
  The project can be packaged as a standalone executable (e.g., via `pkg`) that runs without a console window.

## Requirements

- **Node.js** (v18 recommended)
- **Windows** (for Windows-specific commands: `tasklist`, `netstat`, `netsh`)
- **Npcap/WinPcap** (for raw packet capture if needed)
- **Administrator Privileges** (required for creating and deleting Windows Firewall rules)

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/bruhtesfa-gh/cursor-firewall.git
   cd node-proxy
   ```
