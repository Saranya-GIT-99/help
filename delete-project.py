import os
import time
import requests
import pandas as pd
from urllib.parse import urlparse
from getpass import getpass
from datetime import datetime

# Configuration (UPDATED)
EXCEL_FILE = 'projects_to_delete.xlsx'
REPORT_FILE = 'deletion_report.csv'  # New report file
GITLAB_URL = 'https://gitlab.example.com'
BACKUP_DIR = 'gitlab_backups'
API_VERSION = 'api/v4'
LOG_FILE = 'deletion_log.txt'

# Security measures (unchanged)
VERIFY_SSL = True
TOKEN = os.getenv('GITLAB_TOKEN') or getpass("Enter your GitLab private token: ")

headers = {
    'PRIVATE-TOKEN': TOKEN,
    'Content-Type': 'application/json'
}

# NEW: Results tracking structure
results = []

def setup_environment():
    """Create backup directory and verify permissions"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    if not os.access(BACKUP_DIR, os.W_OK):
        raise PermissionError(f"Cannot write to backup directory: {BACKUP_DIR}")

def log_action(message):
    """Log all actions with timestamp"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

# NEW: Result tracking function
def track_result(project_url, project_path, status, backup_path='', error=''):
    results.append({
        'project_url': project_url,
        'project_path': project_path,
        'status': status,
        'backup_path': backup_path,
        'error_message': error,
        'timestamp': datetime.now().isoformat()
    })

def get_project_path(url):
    """Extract project path from GitLab URL"""
    parsed = urlparse(url)
    path = parsed.path.strip('/')
    return path

def trigger_backup(project_path):
    """Trigger GitLab project export"""
    url = f"{GITLAB_URL}/{API_VERSION}/projects/{project_path.replace('/', '%2F')}/export"
    response = requests.post(url, headers=headers, verify=VERIFY_SSL)
    if response.status_code != 202:
        raise Exception(f"Backup trigger failed: {response.text}")
    return response.json()

def wait_for_backup(project_path):
    """Wait for backup to be ready with timeout"""
    url = f"{GITLAB_URL}/{API_VERSION}/projects/{project_path.replace('/', '%2F')}/export"
    timeout = 600
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL)
        data = response.json()
        
        if data.get('export_status') == 'finished':
            return data['_links']['api_url']
        elif data.get('export_status') == 'failed':
            raise Exception("Backup failed")
        
        time.sleep(30)
    
    raise TimeoutError("Backup timed out")

def download_backup(download_url, project_path):
    """Download backup file"""
    safe_name = project_path.replace('/', '_')
    filename = f"{safe_name}_{int(time.time())}.tar.gz"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    response = requests.get(download_url, headers=headers, stream=True, verify=VERIFY_SSL)
    with open(filepath, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    return filepath

def delete_project(project_path):
    """Delete project after confirmation"""
    url = f"{GITLAB_URL}/{API_VERSION}/projects/{project_path.replace('/', '%2F')}"
    response = requests.delete(url, headers=headers, verify=VERIFY_SSL)
    return response.status_code == 202

# NEW: Report generation function
def generate_report():
    df = pd.DataFrame(results)
    df.to_csv(REPORT_FILE, index=False)
    print(f"\nReport generated: {REPORT_FILE}")

def main():
    setup_environment()
    log_action("Script started")
    
    try:
        df = pd.read_excel(EXCEL_FILE)
        print(f"Found {len(df)} projects in the list")
        
        for index, row in df.iterrows():
            project_url = row['url']
            project_path = get_project_path(project_url)
            backup_path = ''
            error_message = ''
            
            try:
                print(f"\nProcessing project: {project_path}")
                log_action(f"Starting processing for {project_path}")
                
                # Trigger backup
                trigger_backup(project_path)
                print("Backup triggered, waiting for completion...")
                download_url = wait_for_backup(project_path)
                
                # Download backup
                backup_path = download_backup(download_url, project_path)
                print(f"Backup downloaded to: {backup_path}")
                log_action(f"Backup completed for {project_path} at {backup_path}")
                
                # Delete project
                if delete_project(project_path):
                    print("Project deletion initiated successfully")
                    log_action(f"Successfully deleted {project_path}")
                    track_result(project_url, project_path, 'success', backup_path)
                else:
                    error = "Project deletion failed"
                    print(error)
                    log_action(f"Deletion failed for {project_path}")
                    track_result(project_url, project_path, 'failed', backup_path, error)
                    
            except Exception as e:
                error = str(e)
                print(f"Error processing {project_path}: {error}")
                log_action(f"ERROR processing {project_path}: {error}")
                track_result(project_url, project_path, 'error', backup_path, error)
                continue
                
    except Exception as e:
        error = str(e)
        print(f"Fatal error: {error}")
        log_action(f"FATAL ERROR: {error}")
    finally:
        generate_report()  # Generate report in all cases
        log_action("Script execution completed")

if __name__ == '__main__':
    main()
