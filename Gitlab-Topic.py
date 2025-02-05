import csv
import requests
import time
from urllib.parse import urlparse, quote
from getpass import getpass

GITLAB_DOMAIN = "gitlab.example.com"  # Update this!
INPUT_CSV = "projects.csv"
REPORT_CSV = "update_report.csv"
DELAY_SECONDS = 0.5  # Avoid rate limits

def get_encoded_project_path(url):
    parsed_url = urlparse(url)
    project_path = parsed_url.path.strip('/')  # Handles any depth!
    return quote(project_path, safe='')  # Encode slashes (%2F)

def main():
    token = getpass("Enter your GitLab Private Token: ")
    
    with open(REPORT_CSV, 'w', newline='') as report_file:
        report_writer = csv.writer(report_file)
        report_writer.writerow([
            "Project URL", "Topics Attempted", "Status", 
            "HTTP Status Code", "Error Message"
        ])
        
        with open(INPUT_CSV, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                url = row['url']
                topics = row['topics'].split(',')
                encoded_path = get_encoded_project_path(url)
                api_url = f"https://{GITLAB_DOMAIN}/api/v4/projects/{encoded_path}"
                
                try:
                    response = requests.put(
                        api_url,
                        headers={"PRIVATE-TOKEN": token},
                        json={"topics": topics}
                    )
                    status_code = response.status_code
                    
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
                
                report_writer.writerow([
                    url, ",".join(topics), status, status_code, error_msg
                ])
                time.sleep(DELAY_SECONDS)

if __name__ == "__main__":
    main()
    print(f"\nReport generated: {REPORT_CSV}")
