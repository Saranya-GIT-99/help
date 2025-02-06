import csv
import requests
import time
from urllib.parse import urlparse, quote
from getpass import getpass

GITLAB_DOMAIN = "gitlab.example.com"  # Update with your domain
INPUT_CSV = "projects.csv"
REPORT_CSV = "update_report.csv"
DELAY_SECONDS = 0.5  # Adjust for rate limiting

def get_encoded_project_path(url):
    parsed_url = urlparse(url)
    project_path = parsed_url.path.strip('/')
    return quote(project_path, safe='')

def get_current_topics(api_url, token):
    try:
        response = requests.get(api_url, headers={"PRIVATE-TOKEN": token})
        if response.status_code == 200:
            return response.json().get('topics', [])
        else:
            return None  # Indicates failure to fetch
    except Exception as e:
        return None

def main():
    token = getpass("Enter your GitLab Private Token: ")
    
    # Get action type
    action = input("Choose action [replace/update/remove]: ").strip().lower()
    while action not in ['replace', 'update', 'remove']:
        print("Invalid action. Choose 'replace', 'update', or 'remove'.")
        action = input("Choose action: ").strip().lower()
    
    with open(REPORT_CSV, 'w', newline='') as report_file:
        report_writer = csv.writer(report_file)
        report_writer.writerow([
            "Project URL", "Action", "Topics Provided", "Status",
            "HTTP Status Code", "Error Message", "Final Topics"
        ])
        
        with open(INPUT_CSV, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Validate CSV columns
            required_columns = ['url', 'topics']
            if not all(col in reader.fieldnames for col in required_columns):
                print(f"Error: CSV must contain columns: {required_columns}")
                exit(1)
            
            for row in reader:
                url = row['url']
                topics_input = row['topics'].split(',')
                encoded_path = get_encoded_project_path(url)
                api_url = f"https://{GITLAB_DOMAIN}/api/v4/projects/{encoded_path}"
                final_topics = "N/A"
                error_msg = ""
                status_code = "N/A"
                status = "Failed"

                try:
                    # Fetch current topics for update/remove actions
                    current_topics = []
                    if action in ['update', 'remove']:
                        current_topics = get_current_topics(api_url, token)
                        if current_topics is None:
                            raise Exception("Failed to fetch current topics")

                    # Determine new topics based on action
                    if action == "replace":
                        new_topics = topics_input
                    elif action == "update":
                        new_topics = list(set(current_topics + topics_input))
                    elif action == "remove":
                        new_topics = [t for t in current_topics if t not in topics_input]

                    # Send API request
                    response = requests.put(
                        api_url,
                        headers={"PRIVATE-TOKEN": token},
                        json={"topics": new_topics}
                    )
                    status_code = response.status_code

                    if status_code == 200:
                        status = "Success"
                        final_topics = ",".join(new_topics)
                        print(f"✅ {action.capitalize()}d: {url}")
                    else:
                        error_msg = response.json().get("message", "Unknown error")
                        if status_code == 404:
                            error_msg = "Project not found"
                        elif status_code == 403:
                            error_msg = "Permission denied"
                        print(f"❌ Failed: {url} ({error_msg})")

                except Exception as e:
                    error_msg = str(e)
                    print(f"❌ Error: {url} ({error_msg})")

                # Write to report
                report_writer.writerow([
                    url, action, ",".join(topics_input), status,
                    status_code, error_msg, final_topics
                ])
                time.sleep(DELAY_SECONDS)

if __name__ == "__main__":
    main()
    print(f"\nReport generated: {REPORT_CSV}")
