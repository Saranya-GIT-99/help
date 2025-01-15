import requests
import datetime
import openpyxl

# Constants
GITLAB_URL = "https://gitlab.com"  # Change this to your GitLab instance URL
ACCESS_TOKEN = "your_personal_access_token"  # Replace with your GitLab access token
OUTPUT_FILE = "inactive_repositories.xlsx"

def fetch_projects():
    """
    Fetch all GitLab projects accessible to the user.
    """
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    projects = []
    page = 1

    while True:
        response = requests.get(
            f"{GITLAB_URL}/api/v4/projects?per_page=100&page={page}", headers=headers
        )
        if response.status_code != 200:
            print(f"Failed to fetch projects: {response.text}")
            break

        data = response.json()
        if not data:
            break

        projects.extend(data)
        page += 1

    return projects

def filter_inactive_projects(projects, inactive_since):
    """
    Filter projects with no activity since a given date.
    """
    inactive_projects = []
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    for project in projects:
        last_activity_at = project.get("last_activity_at")
        if last_activity_at:
            last_activity_date = datetime.datetime.strptime(last_activity_at, "%Y-%m-%dT%H:%M:%S.%fZ")
            if last_activity_date < inactive_since:
                inactive_projects.append({
                    "name": project.get("name"),
                    "id": project.get("id"),
                    "last_activity_at": last_activity_at,
                    "web_url": project.get("web_url")
                })

    return inactive_projects

def export_to_excel(inactive_projects):
    """
    Export the list of inactive projects to an Excel file.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Inactive Repositories"

    # Header
    ws.append(["Project Name", "Project ID", "Last Activity Date", "Project URL"])

    # Data
    for project in inactive_projects:
        ws.append([project["name"], project["id"], project["last_activity_at"], project["web_url"]])

    wb.save(OUTPUT_FILE)
    print(f"Inactive repositories exported to {OUTPUT_FILE}")

def main():
    # Date threshold: 1 year ago
    today = datetime.datetime.utcnow()
    inactive_since = today - datetime.timedelta(days=365)

    print("Fetching projects...")
    projects = fetch_projects()
    print(f"Found {len(projects)} projects.")

    print("Filtering inactive projects...")
    inactive_projects = filter_inactive_projects(projects, inactive_since)
    print(f"Found {len(inactive_projects)} inactive projects.")

    print("Exporting to Excel...")
    export_to_excel(inactive_projects)

if _name_ == "__main__":
    main()
