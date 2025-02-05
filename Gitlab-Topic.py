import csv
import requests
import time
from urllib.parse import urlparse, quote
from getpass import getpass

# Configuration
GITLAB_DOMAIN = "gitlab.example.com"  # Update with your GitLab domain
API_ENDPOINT = f"https://{GITLAB_DOMAIN}/api/v4/projects"
INPUT_CSV = "projects.csv"
REPORT_CSV = "update_report.csv"
DELAY_SECONDS = 0.5  # Adjust to avoid rate limits

def get_project_id_from_url(url):
    parsed_url = urlparse(url)
    project_path = parsed_url.path.strip('/')
    return quote(project_path, safe='')

def main():
    # Prompt for token securely
    token = getpass("Enter your GitLab Private Token: ")
    
    # Prepare report file
    with open(REPORT_CSV, 'w', newline='') as report_file:
        report_writer = csv.writer(report_file)
        report_writer.writerow([
            "Project URL", "Topics Attempted", "Status", 
            "HTTP Status Code", "Error Message"
        ])
        
        # Read input CSV
        with open(INPUT_CSV, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                url = row['url']
                topics = row['topics'].split(',')
                encoded_path = get_project_id_from_url(url)
                api_url = f"{API_ENDPOINT}/{encoded_path}"
                
                # Send API request
                try:
                    response = requests.put(
                        api_url,
                        headers={"PRIVATE-TOKEN": token},
                        json={"topics": topics}
                    )
                    status_code = response.status_code
                    
                    # Check for success/failure
                    if status_code == 200:
                        status = "Success"
                        error_msg = ""
                        print(f"✅ Updated: {url}")
                    else:
                        status = "Failed"
                        error_msg = response.json().get("message", "Unknown error")
                        if status_code == 404:
                            error_msg = "Project not found"
                        elif status_code == 403:
                            error_msg = "Permission denied"
                        print(f"❌ Failed: {url} ({error_msg})")
                        
                except Exception as e:
                    status = "Failed"
                    status_code = "N/A"
                    error_msg = str(e)
                    print(f"❌ Error: {url} ({error_msg})")
                
                # Write to report
                report_writer.writerow([
                    url, 
                    ",".join(topics), 
                    status, 
                    status_code, 
                    error_msg
                ])
                time.sleep(DELAY_SECONDS)

if __name__ == "__main__":
    main()
    print(f"\nReport generated: {REPORT_CSV}")
