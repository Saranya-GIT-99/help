import pandas as pd
import requests
from getpass import getpass

def get_pipeline_config(gate_url, app, pipeline_name, headers):
    # Get all pipelines for the application
    url = f"{gate_url}/applications/{app}/pipelineConfigs"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Failed to get pipelines for {app}. Status: {response.status_code}")
    
    pipelines = response.json()
    pipeline = next((p for p in pipelines if p['name'] == pipeline_name), None)
    
    if not pipeline:
        raise Exception(f"Pipeline '{pipeline_name}' not found in {app}")
    
    # Get full pipeline configuration
    pipeline_id = pipeline['id']
    url = f"{gate_url}/pipelines/{pipeline_id}"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Failed to get pipeline config. Status: {response.status_code}")
    
    return response.json(), pipeline_id

def update_metadata(action, key, value, pipeline_config):
    metadata = pipeline_config.get('metadata', {})
    
    if action == 'update':
        metadata[key] = value
        print(f"Updating {key} = {value}")
    elif action == 'replace':
        metadata = {key: value}
        print(f"Replacing metadata with {key} = {value}")
    elif action == 'remove':
        if key in metadata:
            del metadata[key]
            print(f"Removed key: {key}")
        else:
            print(f"Key {key} not found in metadata")
    
    pipeline_config['metadata'] = metadata
    return pipeline_config

def main():
    # User inputs
    gate_url = input("Enter Spinnaker Gate URL (e.g., https://gate.example.com): ").strip()
    cookie = getpass("Enter session cookie (e.g., SESSION=abc123): ").strip()
    excel_path = input("Enter path to Excel file: ").strip()
    action = input("Enter action (update/replace/remove): ").strip().lower()
    
    if action not in ['update', 'replace', 'remove']:
        print("Invalid action. Must be: update, replace, or remove")
        return
    
    # Read Excel file
    try:
        df = pd.read_excel(excel_path)
        required_columns = ['Application', 'Pipeline Name', 'Key']
        if action != 'remove':
            required_columns.append('Value')
            
        if not all(col in df.columns for col in required_columns):
            print(f"Excel file must contain columns: {', '.join(required_columns)}")
            return
    except Exception as e:
        print(f"Error reading Excel file: {str(e)}")
        return
    
    headers = {'Cookie': cookie, 'Content-Type': 'application/json'}
    
    for index, row in df.iterrows():
        app = row['Application']
        pipeline_name = row['Pipeline Name']
        key = row['Key']
        value = row.get('Value', None)
        
        print(f"\nProcessing {app}/{pipeline_name} - {key}")
        
        try:
            # Get current pipeline config
            pipeline_config, pipeline_id = get_pipeline_config(gate_url, app, pipeline_name, headers)
            
            # Update metadata
            updated_config = update_metadata(action, key, value, pipeline_config)
            
            # Push changes
            url = f"{gate_url}/pipelines/{pipeline_id}"
            response = requests.put(url, json=updated_config, headers=headers)
            
            if response.status_code == 200:
                print("Successfully updated pipeline")
            else:
                print(f"Failed to update pipeline. Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {str(e)}")
            continue

if __name__ == "__main__":
    main()
