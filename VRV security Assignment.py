import re
from collections import defaultdict, Counter
import csv

# File paths
log_file = 'sample.log'
output_csv = 'log_analysis_results.csv'

# Function to parse the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Analyze logs for requests, endpoints, and suspicious activity
def analyze_logs(logs, fail_threshold=10):
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_login_attempts = defaultdict(int)
    suspicious_ips = {}

    for line in logs:
        # Extract IP address
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else None

        # Extract endpoint
        endpoint_match = re.search(r'"[A-Z]+ (/[^ ]*)', line)
        endpoint = endpoint_match.group(1) if endpoint_match else None

        # Extract HTTP status code
        status_code_match = re.search(r'" \d+ (\d+)', line)
        status_code = int(status_code_match.group(1)) if status_code_match else None

        if ip:
            ip_requests[ip] += 1

        if endpoint:
            endpoint_access[endpoint] += 1

        # Detect failed login attempts
        if status_code == 401 and "Invalid credentials" in line:
            failed_login_attempts[ip] += 1
            if failed_login_attempts[ip] > fail_threshold:
                suspicious_ips[ip] = failed_login_attempts[ip]

    return ip_requests, endpoint_access, suspicious_ips

# Save analysis results to a CSV file
def save_results_to_csv(ip_requests, endpoint_access, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint'])
        most_accessed = endpoint_access.most_common(1)[0]
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Blank line

        # Write Suspicious Activity
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Display results in the terminal
def display_results(ip_requests, endpoint_access, suspicious_ips):
    # Display Requests per IP
    print("Requests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count:<15}")
    print()

    # Display Most Frequently Accessed Endpoint
    most_accessed = endpoint_access.most_common(1)[0]
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    print()

    # Display Suspicious Activity
    print("Suspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")
    print()

# Main function
def main():
    logs = parse_log_file(log_file)

    # Set threshold for suspicious activity detection
    fail_threshold = 10
    ip_requests, endpoint_access, suspicious_ips = analyze_logs(logs, fail_threshold)

    # Display and save results
    display_results(ip_requests, endpoint_access, suspicious_ips)
    save_results_to_csv(ip_requests, endpoint_access, suspicious_ips, output_csv)
    print(f"Results saved to {output_csv}")

if __name__ == "__main__":
    main()
