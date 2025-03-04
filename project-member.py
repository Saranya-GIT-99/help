import requests
import pandas as pd

# 🔹 Step 1: Get User Inputs for Domain & Token
domain_url = input("Enter GitLab domain URL (e.g., https://gitlab.com): ").strip()
access_token = input("Enter GitLab Access Token: ").strip()

# 🔹 Step 2: Read Project URLs from Excel File
input_file = "projects.xlsx"  # Ensure this file exists with a "Project_URL" column
df = pd.read_excel(input_file)

# Check if the "Project_URL" column exists
if "Project_URL" not in df.columns:
    raise ValueError("❌ 'Project_URL' column not found in Excel file!")

# 🔹 Step 3: Extract Project IDs from URLs
def get_project_id(project_url):
    """Extract project ID from GitLab project URL."""
    url_parts = project_url.rstrip('/').split('/')
    return f"{url_parts[-2]}%2F{url_parts[-1]}"  # URL encode namespace/project_name

df["Project_ID"] = df["Project_URL"].apply(get_project_id)

# 🔹 Step 4: Fetch Project Members from GitLab API
def fetch_project_members(project_id):
    """Fetch project members using GitLab API."""
    api_url = f"{domain_url}/api/v4/projects/{project_id}/members/all"
    headers = {"PRIVATE-TOKEN": access_token}
    
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Error fetching members for Project ID {project_id}: {response.text}")
        return []

# 🔹 Step 5: Collect Members Data
members_data = []

for _, row in df.iterrows():
    project_id = row["Project_ID"]
    members = fetch_project_members(project_id)

    for member in members:
        members_data.append({
            "Project_URL": row["Project_URL"],
            "Project_ID": project_id,
            "Username": member["username"],
            "Name": member["name"],
            "Access Level": member["access_level"],
            "Email": member.get("email", "N/A")  # Some API responses may not include emails
        })

# 🔹 Step 6: Save Data to Excel
output_file = "project_members.xlsx"
pd.DataFrame(members_data).to_excel(output_file, index=False)

print(f"✅ Project members list saved to '{output_file}'")
