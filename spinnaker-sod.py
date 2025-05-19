import csv
import json
import os
import sys
import requests
from datetime import datetime

# Existing configuration
application_name = "appdemosamples"
gate_cookie = "your-sponnaker-cookie-with-access"
script_dir = os.path.dirname(os.path.realpath(__file__))

# New report configuration
validation_report_path = os.path.join(script_dir, f"pipeline_validation_report_{datetime.now().strftime('%Y%m%d%H%M')}.csv")

# --- NEW VALIDATION FUNCTIONS ---
def analyze_pipeline(pipeline):
    """Analyze pipeline for required validation checks"""
    validation = {
        'has_manual_judgment': False,
        'mj_before_deploy': False,
        'spel_expression_found': False,
        'opa_policy_found': False,
        'mj_stage_position': None,
        'deploy_stage_position': None
    }

    stages = pipeline.get('stages', [])
    deploy_types = {'deploy', 'cloneServerGroup', 'destroyServerGroup'}

    # Find stage positions
    stage_sequence = []
    for idx, stage in enumerate(stages):
        stage_type = stage.get('type', '')
        stage_sequence.append(stage_type)
        
        if stage_type == 'manualJudgment':
            validation['has_manual_judgment'] = True
            validation['mj_stage_position'] = idx + 1  # 1-based index
            
            # Check SpEL expression
            instructions = stage.get('instructions', '')
            if any(expr in instructions for expr in ['${trigger.user}', '${#trigger.user}']):
                validation['spel_expression_found'] = True

        if stage_type in deploy_types:
            validation['deploy_stage_position'] = idx + 1  # 1-based index

    # Check OPA policy
    opa_indicator = pipeline.get('metadata', {}).get('opaPolicy') or \
                    pipeline.get('annotations', {}).get('policy/opa')
    validation['opa_policy_found'] = bool(opa_indicator)

    # Position validation
    if validation['mj_stage_position'] and validation['deploy_stage_position']:
        validation['mj_before_deploy'] = validation['mj_stage_position'] < validation['deploy_stage_position']

    return validation

def generate_validation_report(pipelines_data):
    """Generate CSV report with validation results"""
    with open(validation_report_path, 'w', newline='') as csvfile:
        fieldnames = [
            'Pipeline Name',
            'Has Manual Judgment',
            'MJ Before Deploy',
            'SpEL Expression',
            'OPA Policy',
            'Validation Status'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for pipeline in pipelines_data:
            validation = analyze_pipeline(pipeline)
            
            # Determine overall validation status
            validation_status = "PASS" if all([
                validation['has_manual_judgment'],
                validation['mj_before_deploy'],
                validation['spel_expression_found'],
                validation['opa_policy_found']
            ]) else "FAIL"

            writer.writerow({
                'Pipeline Name': pipeline['name'],
                'Has Manual Judgment': validation['has_manual_judgment'],
                'MJ Before Deploy': validation['mj_before_deploy'],
                'SpEL Expression': validation['spel_expression_found'],
                'OPA Policy': validation['opa_policy_found'],
                'Validation Status': validation_status
            })

# --- MODIFIED EXISTING CODE ---
def get_pipeline(application_name):
    url = f"sara"
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
        
        # NEW: Generate validation report
        generate_validation_report(json_data)
        
        with open(pipelines_json_path, "w") as json_file:
            json.dump(json_data, json_file, indent=4)

        print(f"Latest pipeline JSON saved to {pipelines_json_path}")
        print(f"Validation report generated: {validation_report_path}")

    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
    except ValueError as e:
        print(f"Error parsing JSON: {e}")

# Rest of the original script remains unchanged below this line
# [Keep original update_spinnaker_pipeline, CSV processing, and file operations]
