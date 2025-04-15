import requests
import csv
from datetime import datetime
import argparse

def human_readable_size(size_bytes):
    """Convert bytes to human-readable format"""
    if not size_bytes or size_bytes == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def export_to_csv(artifacts, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'repo', 'path', 'name', 'size_bytes', 'size_human', 
            'created', 'modified', 'downloads', 'full_path'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for artifact in artifacts:
            # Handle different response formats
            if 'created' in artifact:
                created = datetime.strptime(artifact['created'], '%Y-%m-%dT%H:%M:%S.%fZ')
                modified = datetime.strptime(artifact['modified'], '%Y-%m-%dT%H:%M:%S.%fZ')
            else:
                created = modified = "N/A"
            
            downloads = artifact.get('downloads', 
                          artifact.get('stats', [{}])[0].get('downloads', 0))
            
            size_bytes = artifact.get('size', 0)
            full_path = f"{artifact['repo']}/{artifact.get('path', '')}/{artifact['name']}".replace('//', '/')
            
            writer.writerow({
                'repo': artifact['repo'],
                'path': artifact.get('path', ''),
                'name': artifact['name'],
                'size_bytes': size_bytes,
                'size_human': human_readable_size(size_bytes),
                'created': created.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created, datetime) else created,
                'modified': modified.strftime('%Y-%m-%d %H:%M:%S') if isinstance(modified, datetime) else modified,
                'downloads': downloads,
                'full_path': full_path
            })

def try_fallback_method(base_url, username, password, output_file):
    print("Trying fallback method using storage API...")
    try:
        api_url = f"{base_url}/api/storageinfo/artifacts"
        response = requests.get(
            api_url,
            auth=(username, password),
            timeout=60
        )
        response.raise_for_status()
        
        data = response.json()
        if 'artifacts' in data:
            export_to_csv(data['artifacts'], output_file)
        else:
            print("No artifacts found in storage API response")
    except Exception as e:
        print(f"Fallback method also failed: {e}")

def get_artifacts(base_url, username, password, output_file):
    endpoints = [
        "/api/search/aql",
        "/artifactory/api/search/aql",
        "/api/aql"
    ]
    
    headers = {"Content-Type": "text/plain"}
    aql_query = """
    items.find()
    .include("repo", "path", "name", "size", "created", "modified", "stats.downloads")
    .sort({"$desc": ["created"]})
    """
    
    for endpoint in endpoints:
        api_url = f"{base_url}{endpoint}"
        try:
            print(f"Trying endpoint: {api_url}")
            response = requests.post(
                api_url,
                auth=(username, password),
                headers=headers,
                data=aql_query,
                timeout=60
            )
            response.raise_for_status()
            
            artifacts = response.json().get("results", [])
            if artifacts:
                export_to_csv(artifacts, output_file)
                return
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"Endpoint not found: {api_url}")
                continue
            raise
        except requests.exceptions.RequestException as e:
            print(f"Error with endpoint {api_url}: {e}")
            continue
    
    try_fallback_method(base_url, username, password, output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Export JFrog Artifactory artifacts to CSV')
    parser.add_argument('--url', required=True, help='Artifactory base URL')
    parser.add_argument('--username', required=True, help='Artifactory username')
    parser.add_argument('--password', required=True, help='Artifactory password or API key')
    parser.add_argument('--output', default='artifacts.csv', help='Output CSV file path')
    
    args = parser.parse_args()
    base_url = args.url.rstrip('/')
    get_artifacts(base_url, args.username, args.password, args.output)
