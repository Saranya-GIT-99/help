import pandas as pd
import json
import os
import requests

script_dir = os.path.dirname(os.path.abspath(__file__))

# Configuration
SPINNAKER_URL = "https://oes-prd.rod.intranet.net/gate"
GATE_COOKIE = "your-spinnaker-cookie-here"
INPUT_EXCEL_PATH = os.path.join(script_dir, "input-data.xlsx")
OUTPUT_JSON_PATH = os.path.join(script_dir, "updated_pipelines.json")

def get_spinnaker_pipelines(application):
    """Fetch all pipelines for an application"""
    url = f"{SPINNAKER_URL}/applications/{application}/pipelineConfigs"
    headers = {
        "Accept": "application/json",
        "Cookie": GATE_COOKIE
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching pipelines for {application}: {str(e)}")
        return []

def update_pipeline(pipeline_data):
    """Update pipeline in Spinnaker"""
    url = f"{SPINNAKER_URL}/pipelines?staleCheck=true"
    headers = {
        "Content-Type": "application/json",
        "Cookie": GATE_COOKIE
    }
    try:
        response = requests.post(url, json=pipeline_data, headers=headers)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error updating pipeline {pipeline_data['name']}: {str(e)}")
        return False

def modify_metadata(pipeline, action, key, value=None):
    """Modify pipeline metadata based on action"""
    if 'metadata' not in pipeline:
        pipeline['metadata'] = {}
    
    if action == 'add':
        pipeline['metadata'][key] = value
    elif action == 'replace':
        if key in pipeline['metadata']:
            pipeline['metadata'][key] = value
    elif action == 'remove':
        if key in pipeline['metadata']:
            del pipeline['metadata'][key]
    return pipeline

def process_input_file():
    """Process Excel input file and update pipelines"""
    # Read Excel file
    try:
        df = pd.read_excel(INPUT_EXCEL_PATH)
    except Exception as e:
        print(f"Error reading input file: {str(e)}")
        return

    # Get user action
    while True:
        action = input("Enter operation (add/replace/remove): ").lower()
        if action in ['add', 'replace', 'remove']:
            break
        print("Invalid operation! Please choose add/replace/remove")

    total_updated = 0
    errors = []

    # Process each row
    for index, row in df.iterrows():
        app = row.get('application')
        pipeline_name = row.get('pipeline')
        key = row.get('key')
        value = row.get('value') if action != 'remove' else None

        if not all([app, pipeline_name, key]):
            errors.append(f"Row {index+1}: Missing required fields")
            continue

        # Get pipelines for application
        pipelines = get_spinnaker_pipelines(app)
        if not pipelines:
            errors.append(f"{app}: No pipelines found")
            continue

        # Find matching pipeline
        target_pipeline = next(
            (p for p in pipelines if p.get('name') == pipeline_name), 
            None
        )
        if not target_pipeline:
            errors.append(f"{app}/{pipeline_name}: Pipeline not found")
            continue

        # Modify metadata
        modified_pipeline = modify_metadata(
            target_pipeline, 
            action, 
            key, 
            value
        )

        # Update Spinnaker
        if update_pipeline(modified_pipeline):
            total_updated += 1
        else:
            errors.append(f"{app}/{pipeline_name}: Update failed")

    # Print summary
    print(f"\nOperation completed: {action.upper()}")
    print(f"Total attempts: {len(df)}")
    print(f"Successfully updated: {total_updated}")
    print(f"Errors: {len(errors)}")
    
    if errors:
        print("\nError details:")
        for error in errors:
            print(f"- {error}")

if __name__ == "__main__":
    process_input_file()
