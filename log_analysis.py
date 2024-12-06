import re
import csv
from collections import defaultdict

# Function to parse log file and process data
def process_log_file(log_file_path):
    ip_request_counts = defaultdict(int)
    endpoint_access_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_request_counts[ip_address] += 1

            # Extract endpoint
            endpoint_match = re.search(r'\"(?:GET|POST) (/[^\s]*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_counts[endpoint] += 1

            # Detect failed login attempts
            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_login_attempts[ip_address] += 1

    return ip_request_counts, endpoint_access_counts, failed_login_attempts

# Function to detect suspicious activity
def detect_suspicious_activity(failed_login_attempts, threshold=10):
    return {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

# Function to write results to a CSV file
def save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Empty row for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Empty row for separation

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function to run the analysis
def main():
    log_file_path = r'C:\Users\yadav\OneDrive\Desktop\VRV Security\sample.log'
    output_file = r'C:\Users\yadav\OneDrive\Desktop\VRV Security\log_analysis_results.csv'

    # Process log file
    ip_request_counts, endpoint_access_counts, failed_login_attempts = process_log_file(log_file_path)

    # Identify most accessed endpoint
    most_accessed_endpoint = max(endpoint_access_counts.items(), key=lambda x: x[1])

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(failed_login_attempts)

    # Display results
    print("IP Address Requests:")
    for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
