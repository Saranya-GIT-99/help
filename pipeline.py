import requests
import csv
from datetime import datetime

# Configuration
SPINNAKER_GATE_URL = "http://your-spinnaker-gate-url"
COOKIE_STRING = "your-cookie-string-here"
CSV_FILENAME = "spinnaker_pipelines.csv"

def get_spinnaker_pipelines():
    headers = {
        "Cookie": COOKIE_STRING,
        "Content-Type": "application/json",
    }
    
    cookies = {}
    xsrf_token = None
    
    for cookie in COOKIE_STRING.split(";"):
        parts = cookie.strip().split("=", 1)
        if len(parts) == 2:
            key, value = parts
            cookies[key] = value
            if key == "XSRF-TOKEN":
                xsrf_token = value
                
    if xsrf_token:
        headers["X-XSRF-TOKEN"] = xsrf_token

    try:
        response = requests.get(
            f"{SPINNAKER_GATE_URL}/v2/pipelines/search",
            params={"pageSize": 10000},
            headers=headers,
            cookies=cookies
        )

        if response.status_code == 404:
            apps_response = requests.get(
                f"{SPINNAKER_GATE_URL}/applications",
                headers=headers,
                cookies=cookies
            )
            
            if apps_response.status_code != 200:
                print(f"Error fetching applications: {apps_response.status_code}")
                return []
                
            all_pipelines = []
            for app in apps_response.json():
                app_name = app["name"]
                pipelines_response = requests.get(
                    f"{SPINNAKER_GATE_URL}/applications/{app_name}/pipelines",
                    headers=headers,
                    cookies=cookies
                )
                
                if pipelines_response.status_code == 200:
                    all_pipelines.extend(pipelines_response.json())
                    
            return all_pipelines

        if response.status_code != 200:
            print(f"Error fetching pipelines: {response.status_code}")
            return []

        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return []

def write_to_csv(pipelines):
    if not pipelines:
        print("No pipelines found to export")
        return

    fieldnames = [
        'ID', 
        'Name', 
        'Application', 
        'Last Modified By', 
        'Last Modified Timestamp',
        'Disabled'
    ]

    csv_rows = []
    for pipeline in pipelines:
        modified_by = pipeline.get('lastModifiedBy') or {}
        if isinstance(modified_by, dict):
            modified_by = modified_by.get('email') or modified_by.get('username') or 'N/A'
        
        timestamp = pipeline.get('updateTs')
        if timestamp:
            try:
                timestamp = datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M:%S')
            except:
                timestamp = 'Invalid timestamp'
        else:
            timestamp = 'N/A'

        csv_rows.append({
            'ID': pipeline.get('id', 'N/A'),
            'Name': pipeline.get('name', 'Unnamed'),
            'Application': pipeline.get('application', 'N/A'),
            'Last Modified By': modified_by,
            'Last Modified Timestamp': timestamp,
            'Disabled': pipeline.get('disabled', False)
        })

    with open(CSV_FILENAME, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
        
    print(f"Successfully exported {len(csv_rows)} pipelines to {CSV_FILENAME}")

if __name__ == "__main__":
    pipelines = get_spinnaker_pipelines()
    write_to_csv(pipelines)
