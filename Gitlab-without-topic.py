import requests
import getpass
import pandas as pd
from urllib.parse import urljoin
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment
from openpyxl.utils import get_column_letter

def get_gitlab_projects_without_topics():
    # Get credentials at runtime
    gitlab_url = input("Enter GitLab instance URL (e.g., https://gitlab.com): ").strip()
    access_token = getpass.getpass("Enter your GitLab access token: ")

    api_base = urljoin(gitlab_url, "/api/v4/")
    headers = {"PRIVATE-TOKEN": access_token}
    
    projects = []
    page = 1
    per_page = 100

    try:
        while True:
            url = f"{api_base}projects"
            params = {
                "per_page": per_page,
                "page": page,
                "simple": "false",
                "membership": "true",
                "statistics": "true",
                "with_shared": "false"
            }

            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()

            batch = response.json()
            if not batch:
                break

            for project in batch:
                if not project.get('topics'):
                    projects.append({
                        "Project ID": project['id'],
                        "Project Name": project['name'],
                        "Namespace": project['namespace']['full_path'],
                        "URL": project['web_url'],
                        "Created Date": project['created_at'],
                        "Last Activity": project['last_activity_at'],
                        "Visibility": project['visibility'],
                        "Open Issues": project['open_issues_count'],
                        "Storage (MB)": project['statistics']['storage_size'] // 1024 // 1024
                    })

            if 'X-Next-Page' in response.headers:
                page = int(response.headers['X-Next-Page'])
            else:
                break

    except requests.exceptions.RequestException as e:
        print(f"Error accessing GitLab API: {str(e)}")
        return None

    return projects

def create_excel_report(projects):
    if not projects:
        print("No projects found without topics. Exiting...")
        return

    # Create DataFrame
    df = pd.DataFrame(projects)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"GitLab_Projects_Without_Topics_{timestamp}.xlsx"
    
    # Create Excel writer
    writer = pd.ExcelWriter(filename, engine='openpyxl')
    df.to_excel(writer, index=False, sheet_name='Projects Report')
    
    # Get workbook and worksheet
    workbook = writer.book
    worksheet = writer.sheets['Projects Report']
    
    # Formatting
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = Alignment(horizontal="center", vertical="center")
    
    # Set column widths and formatting
    column_widths = {
        'A': 10,  # Project ID
        'B': 25,  # Project Name
        'C': 30,  # Namespace
        'D': 60,  # URL
        'E': 18,  # Created Date
        'F': 18,  # Last Activity
        'G': 12,  # Visibility
        'H': 12,  # Open Issues
        'I': 15   # Storage (MB)
    }
    
    for col, width in column_widths.items():
        worksheet.column_dimensions[col].width = width
    
    # Format headers
    for cell in worksheet[1]:
        cell.font = header_font
        cell.alignment = header_fill
        cell.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    
    # Freeze header row
    worksheet.freeze_panes = 'A2'
    
    # Save the workbook
    writer.close()
    print(f"\nReport generated successfully: {filename}")

if __name__ == "__main__":
    projects = get_gitlab_projects_without_topics()
    create_excel_report(projects)
