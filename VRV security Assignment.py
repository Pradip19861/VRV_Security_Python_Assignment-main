import re
from collections import Counter, defaultdict
import csv

# File paths
LOG_FILE_PATH = 'sample.log'
OUTPUT_CSV_PATH = 'log_analysis_results.csv'

def parse_log_file(file_path):
    """
    Reads the log file and returns the content as a list of lines.
    """
    with open(file_path, 'r') as file:
        return file.readlines()

def analyze_logs(log_entries, failed_attempts_threshold=10):
    """
    Analyzes log entries for:
    - Request counts by IP address
    - Endpoint access counts
    - Suspicious activity (failed login attempts)

    Returns:
    - Counter of requests per IP address
    - Counter of endpoint access counts
    - Dictionary of suspicious IP addresses with failed login attempts
    """
    ip_request_counts = Counter()
    endpoint_access_counts = Counter()
    failed_login_attempts = defaultdict(int)
    flagged_ips = {}

    for log_entry in log_entries:
        # Extract IP address
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log_entry)
        ip_address = ip_match.group(1) if ip_match else None

        # Extract endpoint
        endpoint_match = re.search(r'"[A-Z]+ (/[^ ]*)', log_entry)
        endpoint = endpoint_match.group(1) if endpoint_match else None

        # Extract HTTP status code
        status_code_match = re.search(r'" \d+ (\d+)', log_entry)
        status_code = int(status_code_match.group(1)) if status_code_match else None

        if ip_address:
            ip_request_counts[ip_address] += 1

        if endpoint:
            endpoint_access_counts[endpoint] += 1

        # Identify failed login attempts
        if status_code == 401 and "Invalid credentials" in log_entry:
            failed_login_attempts[ip_address] += 1
            if failed_login_attempts[ip_address] > failed_attempts_threshold:
                flagged_ips[ip_address] = failed_login_attempts[ip_address]

    return ip_request_counts, endpoint_access_counts, flagged_ips

def save_results_to_csv(ip_request_counts, endpoint_access_counts, flagged_ips, output_file):
    """
    Saves the analyzed results to a CSV file with the following sections:
    - Requests per IP address
    - Most accessed endpoint
    - Suspicious activity (failed login attempts)
    """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Section 1: Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_request_counts.most_common():
            writer.writerow([ip, count])
        writer.writerow([])  # Blank line

        # Section 2: Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint'])
        most_accessed = endpoint_access_counts.most_common(1)[0]
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])  # Blank line

        # Section 3: Suspicious Activity
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])

def display_results(ip_request_counts, endpoint_access_counts, flagged_ips):
    """
    Displays the analysis results in a clear and organized format on the terminal.
    """
    # Display Requests per IP
    print("Requests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_request_counts.most_common():
        print(f"{ip:<20}{count:<15}")
    print()

    # Display Most Frequently Accessed Endpoint
    most_accessed = endpoint_access_counts.most_common(1)[0]
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    print()

    # Display Suspicious Activity
    print("Suspicious Activity Detected:")
    if flagged_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")
    print()

def main():
    """
    Main function to orchestrate the log analysis workflow.
    """
    # Parse the log file
    log_entries = parse_log_file(LOG_FILE_PATH)

    # Analyze the logs with a configurable failed login threshold
    FAILED_ATTEMPTS_THRESHOLD = 10
    ip_request_counts, endpoint_access_counts, flagged_ips = analyze_logs(
        log_entries, FAILED_ATTEMPTS_THRESHOLD
    )

    # Display results in the terminal
    display_results(ip_request_counts, endpoint_access_counts, flagged_ips)

    # Save results to a CSV file
    save_results_to_csv(ip_request_counts, endpoint_access_counts, flagged_ips, OUTPUT_CSV_PATH)
    print(f"Analysis complete. Results saved to {OUTPUT_CSV_PATH}")

if __name__ == "__main__":
    main()
