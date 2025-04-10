import requests
import csv
from datetime import datetime

# Configuration
SPINNAKER_GATE_URL = "http://your-spinnaker-gate-url"  # Replace with your Spinnaker Gate URL
COOKIE_STRING = "your-cookie-string-here"  # Replace with your cookie from browser dev tools
CSV_FILENAME = "spinnaker_pipelines.csv"

def get_spinnaker_pipelines():
    # ... [Keep the same get_spinnaker_pipelines() function as previous script] ...

def write_to_csv(pipelines):
    if not pipelines:
        print("No pipelines found to export")
        return

    # Define CSV headers and field mappings
    fieldnames = [
        'ID', 
        'Name', 
        'Application', 
        'Last Modified By', 
        'Last Modified Timestamp',
        'Disabled'
    ]

    # Prepare data for CSV
    csv_rows = []
    for pipeline in pipelines:
        # Handle nested user information
        modified_by = pipeline.get('lastModifiedBy') or {}
        if isinstance(modified_by, dict):
            modified_by = modified_by.get('email') or modified_by.get('username') or 'N/A'
        
        # Convert timestamp from milliseconds to readable format
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

    # Write to CSV
    with open(CSV_FILENAME, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
        
    print(f"Successfully exported {len(csv_rows)} pipelines to {CSV_FILENAME}")

if __name__ == "__main__":
    pipelines = get_spinnaker_pipelines()
    write_to_csv(pipelines)
