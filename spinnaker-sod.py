import requests
import json
import csv
from datetime import datetime

# Configuration
SPINNAKER_GATE_URL = "https://your-spinnaker-gate-url"
APPLICATION_NAME = "your-application-name"
COOKIES = {
    "cookie": "your-gate-cookie-value"
}
REPORT_FILE = f"spinnaker_pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

def get_pipelines():
    """Fetch all pipelines for the application"""
    url = f"{SPINNAKER_GATE_URL}/applications/{APPLICATION_NAME}/pipelines"
    try:
        response = requests.get(url, cookies=COOKIES)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching pipelines: {e}")
        return []

def get_pipeline_details(pipeline_id):
    """Fetch detailed configuration for a specific pipeline"""
    url = f"{SPINNAKER_GATE_URL}/pipelines/{pipeline_id}"
    try:
        response = requests.get(url, cookies=COOKIES)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching pipeline {pipeline_id}: {e}")
        return None

def analyze_pipeline(pipeline_details):
    """Analyze pipeline for required criteria"""
    result = {
        "manual_judgment_position": "Not Found",
        "initiator": "",
        "approver_expression": "",
        "opa_policy": "",
        "validation_result": "FAIL"
    }
    
    stages = pipeline_details.get("stages", [])
    triggers = pipeline_details.get("triggers", [])
    annotations = pipeline_details.get("annotations", {})
    
    # Find stage positions
    stage_types = [stage.get("type", "") for stage in stages]
    mj_indices = [i for i, typ in enumerate(stage_types) if typ == "manualJudgment"]
    deploy_indices = [i for i, typ in enumerate(stage_types) if "deploy" in typ.lower()]
    
    # Check Manual Judgment position
    if mj_indices and deploy_indices:
        first_mj = min(mj_indices)
        first_deploy = min(deploy_indices)
        if first_mj < first_deploy:
            result["manual_judgment_position"] = f"Before Deploy (Stage {first_mj + 1})"
    
    # Get initiator from triggers
    manual_triggers = [t for t in triggers if t.get("type") == "manual"]
    if manual_triggers:
        result["initiator"] = manual_triggers[0].get("user", "")
    
    # Find Manual Judgment approval expression
    for stage in stages:
        if stage.get("type") == "manualJudgment":
            instructions = stage.get("instructions", "")
            if "${trigger.user}" in instructions or "${#trigger.user}" in instructions:
                result["approver_expression"] = "Found SpEL reference"
            break
    
    # Check for OPA policy
    result["opa_policy"] = annotations.get("opaPolicy", "") or annotations.get("OPAPolicy", "")
    
    # Determine validation result
    if (result["manual_judgment_position"] != "Not Found" and 
        result["approver_expression"] and 
        result["opa_policy"]):
        result["validation_result"] = "PASS"
    
    return result

def generate_report():
    """Generate the CSV report"""
    pipelines = get_pipelines()
    
    with open(REPORT_FILE, mode='w', newline='') as csvfile:
        fieldnames = [
            "Pipeline Name",
            "Manual Judgment Position",
            "Initiator",
            "Approver Expression",
            "OPA Policy",
            "Validation Result"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for pipeline in pipelines:
            pipeline_id = pipeline.get("id")
            pipeline_name = pipeline.get("name")
            
            details = get_pipeline_details(pipeline_id)
            if not details:
                continue
                
            analysis = analyze_pipeline(details)
            
            writer.writerow({
                "Pipeline Name": pipeline_name,
                "Manual Judgment Position": analysis["manual_judgment_position"],
                "Initiator": analysis["initiator"],
                "Approver Expression": analysis["approver_expression"],
                "OPA Policy": analysis["opa_policy"],
                "Validation Result": analysis["validation_result"]
            })
    
    print(f"Report generated successfully: {REPORT_FILE}")

if __name__ == "__main__":
    generate_report()
