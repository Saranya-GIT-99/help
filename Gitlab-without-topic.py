import requests
import getpass
import pandas as pd
from urllib.parse import urljoin
from datetime import datetime

def get_gitlab_projects_without_topics():
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
                "order_by": "last_activity_at",
                "sort": "desc"
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

            # Fixed pagination handling
            next_page = response.headers.get('X-Next-Page')
            if not next_page or not next_page.isdigit():
                break
            page = int(next_page)

    except requests.exceptions.RequestException as e:
        print(f"Error accessing GitLab API: {str(e)}")
        return None
    except KeyError as e:
        print(f"Missing expected field in API response: {str(e)}")
        return None

    return projects

def create_excel_report(projects):
    if not projects:
        print("No projects found without topics. Exiting...")
        return

    df = pd.DataFrame(projects)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"GitLab_Projects_Without_Topics_{timestamp}.xlsx"
    
    # Create Excel writer with auto-adjusting columns
    with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Projects')
        
        # Get workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets['Projects']
        
        # Add header formatting
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#4472C4',
            'font_color': 'white',
            'border': 1
        })
        
        # Apply header format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
        
        # Auto-adjust column widths
        for i, col in enumerate(df.columns):
            max_len = max((
                df[col].astype(str).map(len).max(),
                len(col)
            )) + 2
            worksheet.set_column(i, i, max_len)

    print(f"\nReport generated successfully: {filename}")

if __name__ == "__main__":
    projects = get_gitlab_projects_without_topics()
    create_excel_report(projects)
