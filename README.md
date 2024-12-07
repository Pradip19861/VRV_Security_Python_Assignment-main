# Log Analysis Script

## Overview

This project is a Python script that processes web server log files to extract and analyze important information. The script performs various operations such as identifying the most active IP addresses, finding the most frequently accessed endpoint, and detecting suspicious activity such as failed login attempts. It is particularly useful for security monitoring and traffic analysis.

---

## Features

1. **Requests per IP**:
   - Extracts IP addresses from the log file.
   - Counts the number of requests made by each IP address.
   - Sorts and displays results in descending order of request count.

   **Example Output**:

2. **Most Accessed Endpoint**:
- Extracts endpoints (URLs or resource paths) from the log file.
- Identifies the endpoint accessed the highest number of times.

**Example Output**:

3. **Suspicious Activity Detection**:
- Detects failed login attempts based on HTTP status code `401` or specific failure messages (e.g., "Invalid credentials").
- Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).

**Example Output**:

4. **Output Results**:
- Displays all results in the terminal for quick review.
- Saves results to a CSV file (`log_analysis_results.csv`) with the following sections:
  - **Requests per IP**: Columns: `IP Address`, `Request Count`
  - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
  - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

---

## Prerequisites

To run this script, you need the following:
- Python 3.7 or later installed on your system.
- A log file in the expected format, placed in the same directory as the script (e.g., `sample.log`).

---

## Log File Format

The script expects the log entries to follow a format similar to this:

Here are the key parts of the log:
- `192.168.1.1`: IP address of the client.
- `[03/Dec/2024:10:12:34 +0000]`: Date and time of the request.
- `"GET /home HTTP/1.1"`: HTTP method, endpoint, and protocol.
- `200`: HTTP status code (e.g., `200` for success, `401` for unauthorized).
- `512`: Response size in bytes.

---

## Installation and Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/log-analysis-script.git
   cd log-analysis-script
python log_analysis_script.py
IP Address,Request Count
192.168.1.1,234
203.0.113.5,187
Endpoint,Access Count
/home,403
IP Address,Failed Login Count
192.168.1.100,56
.
├── log_analysis_script.py    # Main Python script
├── sample.log                # Example log file
├── log_analysis_results.csv  # Generated CSV file with results
└── README.md                 # Project documentation
FAILED_LOGIN_THRESHOLD = 10
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312

This version is comprehensive, including usage instructions, examples, configuration details, and an example log format. Update placeholders like `Pradip19861` and `Pradip Dolai` before publishing.
