# Log-Analysis-Script
Log Analysis Script
A Python-based log analysis tool designed to process web server log files and extract valuable insights. This script is perfect for monitoring server usage, detecting suspicious activities, and generating detailed reports for analysis.

Features
1. Request Count per IP Address
   Counts the number of requests made by each IP address in the log file.
   Outputs the results sorted in descending order of request counts.
2. Most Accessed Endpoint
   Identifies the most frequently accessed resource or endpoint.
   Displays the endpoint along with its access count.
3. Suspicious Activity Detection
   Detects potential brute force attempts by identifying IP addresses with failed login attempts exceeding a threshold (default: 10).
   Flags suspicious IPs using HTTP status codes (401) or failure messages like "Invalid credentials."

Output Results
5. Terminal Output: Displays results in a clear and concise format.
   CSV Report: Exports the analysis to log_analysis_results.csv, including:
   Request counts per IP (IP Address, Request Count).
   Most accessed endpoint (Endpoint, Access Count).
   Suspicious activities (IP Address, Failed Login Count).
