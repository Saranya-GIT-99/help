import pandas as pd
import requests
from urllib.parse import quote
from getpass import getpass

def main():
    # Get user inputs
    excel_path = input("Enter path to Excel file: ")
    gitlab_url = input("Enter GitLab API URL (default: https://gitlab.com/api/v4): ") or "https://gitlab.com/api/v4"
    token = getpass("Enter your GitLab access token: ")

    # Read Excel file
    try:
        df = pd.read_excel(excel_path)
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return

    # Verify required columns exist
    if not all(col in df.columns for col in ['Project URL/ID', 'Action']):
        print("Excel file must contain 'Project URL/ID' and 'Action' columns")
        return

    # Prepare API headers
    headers = {
        "PRIVATE-TOKEN": token
    }

    # Process each project
    for index, row in df.iterrows():
        project = row['Project URL/ID']
        action = row['Action'].strip().lower()

        # Parse project path
        try:
            if str(project).startswith('http'):
                # Extract path from URL
                path = project.split('://', 1)[1].split('/', 1)[1]
                if path.endswith('.git'):
                    path = path[:-4]
            else:
                path = project
            
            # URL-encode the project path
            encoded_path = quote(path, safe='')
            
        except Exception as e:
            print(f"Invalid Project format: {project} - {e}")
            continue

        # Validate action
        if action not in ['archive', 'unarchive']:
            print(f"Invalid action '{action}' for project {project}")
            continue

        # Prepare API endpoint
        endpoint = f"{gitlab_url}/projects/{encoded_path}/{action}"
        
        try:
            response = requests.post(endpoint, headers=headers)
            
            if response.status_code == 201:
                print(f"Successfully {action}d {path}")
            else:
                print(f"Failed to {action} {path}. Status: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"Error processing {path}: {e}")

if __name__ == "__main__":
    main()
