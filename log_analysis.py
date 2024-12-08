import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parses the log file to extract information about IPs, endpoints, and login attempts."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP, HTTP method, endpoint, and status code
            match = re.match(r'(\d+\.\d+\.\d+\.\d+).*"(\w+)\s(/[\w\-/]*)\sHTTP.*"\s(\d+)', line)
            if match:
                ip, method, endpoint, status_code = match.groups()

                # Increment counts
                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                # Track failed login attempts (HTTP status 401)
                if status_code == '401':
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def write_to_csv(ip_requests, most_accessed, suspicious_activities):
    """Writes the analysis results to a CSV file."""
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow(most_accessed)

        # Write suspicious activities
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def main():
    # File path to the log file
    log_file = 'sample.log'

    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file)

    # Sort IPs by request count
    sorted_ip_requests = ip_requests.most_common()

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Detect suspicious activities
    suspicious_activities = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results in the terminal
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_activities:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20}{count}")
    else:
        print("\nNo Suspicious Activity Detected.")

    # Save results to a CSV file
    write_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activities)

if __name__ == '__main__':
    main()
