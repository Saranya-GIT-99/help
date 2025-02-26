import csv
import json
import os
import sys
import requests

script_dir = os.path.dirname(os.path.abspath(__file__))

# Script inputs
application_name = "appdemosamples"
gate_cookie = "your-spinnaker-cookie-with-access"

input_csv_path = os.path.join(script_dir, "input-data.csv")
pipelines_json_path = os.path.join(script_dir, f"pipelines-{application_name}.json")
output_json_path = os.path.join(script_dir, f"updated_pipelines_{application_name}.json")

def update_spinnaker_pipeline(payload):
    url = "https://oes.intranet.net/gate/pipelines?staleCheck=true"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Content-Type": "application/json;charset=UTF-8",
        "Cookie": f"{gate_cookie}"
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Pipeline updated successfully: {payload['name']} from application: {payload['application']}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to update pipeline: {e}")

def get_pipeline(application_name):
    url = f"https://oes.intranet.net/gate/applications/{application_name}/pipelineConfigs"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Cookie": f"{gate_cookie}"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_data = response.json()
        with open(pipelines_json_path, "w") as json_file:
            json.dump(json_data, json_file, indent=4)
        print(f"Latest pipeline JSON saved to {pipelines_json_path}")
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
    except ValueError as e:
        print(f"Error parsing JSON: {e}")

# Get user input for operation type
while True:
    action = input("Enter operation type (add/remove/replace): ").lower()
    if action in ['add', 'remove', 'replace']:
        break
    print("Invalid operation! Please enter add, remove, or replace.")

# Get tag details based on operation
tag_name = ""
tag_value = ""
if action in ['add', 'replace']:
    tag_name = input("Enter tag name: ").strip()
    tag_value = input("Enter tag value: ").strip()
elif action == 'remove':
    tag_name = input("Enter tag name to remove: ").strip()

# Fetch latest pipelines
get_pipeline(application_name)

# Read input CSV and pipeline data
with open(input_csv_path, mode='r', encoding='utf-8') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    input_data = [row for row in csv_reader]

with open(pipelines_json_path, mode='r', encoding='utf-8') as jsonfile:
    pipelines_data = json.load(jsonfile)

total_pipelines = len(pipelines_data)
total_updated = 0

# Process each pipeline
for row in input_data:
    app = row['application']
    pipeline_name = row['pipeline']
    
    for pipeline in pipelines_data:
        if pipeline.get('application') == app and pipeline.get('name') == pipeline_name:
            tags = pipeline.setdefault('tags', [])
            
            if action == 'add':
                if not any(t['name'] == tag_name for t in tags):
                    tags.append({'name': tag_name, 'value': tag_value})
                    update_spinnaker_pipeline(pipeline)
                    total_updated += 1
                    
            elif action == 'remove':
                original_count = len(tags)
                pipeline['tags'] = [t for t in tags if t.get('name') != tag_name]
                if len(pipeline['tags']) != original_count:
                    update_spinnaker_pipeline(pipeline)
                    total_updated += 1
                    
            elif action == 'replace':
                updated = False
                for t in tags:
                    if t['name'] == tag_name:
                        if t['value'] != tag_value:
                            t['value'] = tag_value
                            updated = True
                if not updated:
                    if not any(t['name'] == tag_name for t in tags):
                        tags.append({'name': tag_name, 'value': tag_value})
                        updated = True
                if updated:
                    update_spinnaker_pipeline(pipeline)
                    total_updated += 1

# Save updated pipelines
with open(output_json_path, mode='w') as jsonfile:
    json.dump(pipelines_data, jsonfile, indent=4)

print(f"\nOperation Summary:")
print(f"Total pipelines in system: {total_pipelines}")
print(f"Pipelines processed from CSV: {len(input_data)}")
print(f"Successfully updated pipelines: {total_updated}")
print(f"Updated configurations saved to: {output_json_path}")
