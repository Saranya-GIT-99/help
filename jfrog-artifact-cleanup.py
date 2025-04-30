import requests
import pandas as pd
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configuration
JFROG_BASE_URL = 'https://artifactochprod.awsintranet.net/artifactory'
ACCESS_TOKEN = 'your_access_token_here'  # Securely load this, e.g., from environment variables
MAX_WORKERS = 5  # Threads for parallel processing
BACKUP_DIR = f'artifactory_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
DRY_RUN = False  # Set to True for testing (no deletion)

# Headers
BASE_HEADERS = {
    'Authorization': f'Bearer {ACCESS_TOKEN}',
    'Content-Type': 'application/json'
}
AQL_HEADERS = {
    'Authorization': f'Bearer {ACCESS_TOKEN}',
    'Content-Type': 'text/plain'
}

def get_artifact_type(repo, path):
    """Determine if the artifact is a file or folder."""
    url = f"{JFROG_BASE_URL}/api/storage/{repo}/{path}"
    try:
        response = requests.get(url, headers=BASE_HEADERS)
        response.raise_for_status()
        data = response.json()
        return 'file' if 'size' in data else 'folder'
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Artifact {repo}/{path} not found.")
        else:
            print(f"Error checking {repo}/{path}: {e}")
        return None
    except Exception as e:
        print(f"Error checking {repo}/{path}: {e}")
        return None

def find_files_in_folder(repo, path):
    """Find all files under a folder using AQL."""
    path_pattern = f"{path}/**" if path not in ('', '.') else "**"
    aql_query = f"""
    items.find({{
        "repo": "{repo}",
        "path": {{"$match": "{path_pattern}"}},
        "type": "file"
    }})
    .include("repo", "path", "name")
    """
    try:
        response = requests.post(
            f"{JFROG_BASE_URL}/api/search/aql",
            data=aql_query.strip(),
            headers=AQL_HEADERS
        )
        response.raise_for_status()
        return response.json().get('results', [])
    except Exception as e:
        print(f"Error finding files in {repo}/{path}: {e}")
        return []

def backup_file(artifact):
    """Download an artifact to the backup directory."""
    repo, path, name = artifact['repo'], artifact['path'], artifact['name']
    file_url = f"{JFROG_BASE_URL}/{repo}/{path}/{name}" if path != '.' else f"{JFROG_BASE_URL}/{repo}/{name}"
    local_path = os.path.join(BACKUP_DIR, repo, path, name) if path != '.' else os.path.join(BACKUP_DIR, repo, name)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    try:
        with requests.get(file_url, headers=BASE_HEADERS, stream=True) as r:
            r.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        print(f"Backed up: {file_url}")
        return True
    except Exception as e:
        print(f"Backup failed for {file_url}: {e}")
        return False

def delete_artifact(repo, path, name=None):
    """Delete a file or folder from Artifactory."""
    target = f"{repo}/{path}/{name}" if name else f"{repo}/{path}"
    url = f"{JFROG_BASE_URL}/{target}"
    if DRY_RUN:
        print(f"Dry Run: Would delete {url}")
        return True
    try:
        response = requests.delete(url, headers=BASE_HEADERS)
        response.raise_for_status()
        print(f"Deleted: {url}")
        return True
    except Exception as e:
        print(f"Deletion failed for {url}: {e}")
        return False

def process_repo_path(repo, path):
    """Process each repo/path entry from the Excel."""
    artifact_type = get_artifact_type(repo, path)
    if not artifact_type:
        return
    
    if artifact_type == 'file':
        dir_part, file_part = os.path.split(path)
        dir_part = dir_part if dir_part else '.'
        if not backup_file({'repo': repo, 'path': dir_part, 'name': file_part}):
            return
        delete_artifact(repo, dir_part, file_part)
    else:
        files = find_files_in_folder(repo, path)
        if not files:
            print(f"No files found in {repo}/{path}.")
            return
        all_backed_up = all(backup_file(f) for f in files)
        if all_backed_up:
            delete_artifact(repo, path)
        else:
            print(f"Skipped deletion for {repo}/{path} due to backup failures.")

def main():
    """Main function to read Excel and process entries."""
    input_excel = 'input.xlsx'  # Update with your Excel path
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    try:
        df = pd.read_excel(input_excel)
        if 'Repository' not in df.columns or 'Path' not in df.columns:
            print("Excel must contain 'Repository' and 'Path' columns.")
            return
        repo_paths = df[['Repository', 'Path']].drop_duplicates().values.tolist()
        print(f"Found {len(repo_paths)} entries to process.")
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_repo_path, repo, path) for repo, path in repo_paths]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Processing error: {e}")

    print(f"\nBackup saved to: {BACKUP_DIR}")

if __name__ == "__main__":
    main()
