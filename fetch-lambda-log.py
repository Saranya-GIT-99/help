import os
import re
import boto3
from datetime import datetime, timedelta

def extract_api_details(error_message):
    """
    Extract API Gateway URL, region, and stage from the error message.
    """
    api_url_pattern = r'https://[^\s]+'
    api_url_match = re.search(api_url_pattern, error_message)
    if not api_url_match:
        raise ValueError("Could not extract API Gateway URL from error message!")

    api_url = api_url_match.group(0)
    api_gw_id = api_url.split('/')[2].split('.')[0]
    aws_region = re.search(r'(?<=execute-api\.)[^.]+', api_url).group(0)
    api_stage = api_url.split('/')[-1]

    return api_gw_id, aws_region, api_stage

def fetch_api_gateway_logs(api_gw_id, aws_region, api_stage):
    """
    Fetch API Gateway logs from CloudWatch.
    """
    logs_client = boto3.client('logs', region_name=aws_region)
    log_group_name = f"/aws/api-gateway/{api_gw_id}/{api_stage}"

    try:
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            filterPattern='ERROR',
            limit=10
        )
        return response['events']
    except logs_client.exceptions.ResourceNotFoundException:
        print(f"No logs found for API Gateway: {api_gw_id}")
        return []

def fetch_lambda_logs(lambda_name, aws_region):
    """
    Fetch Lambda function logs from CloudWatch.
    """
    logs_client = boto3.client('logs', region_name=aws_region)
    log_group_name = f"/aws/lambda/{lambda_name}"

    try:
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            filterPattern='ERROR',
            startTime=int((datetime.now() - timedelta(hours=1)).timestamp() * 1000),
            limit=10
        )
        return response['events']
    except logs_client.exceptions.ResourceNotFoundException:
        print(f"No logs found for Lambda: {lambda_name}")
        return []

def main():
    # Read environment variables
    pipeline_id = os.getenv('PIPELINE_ID')
    stage_name = os.getenv('STAGE_NAME')
    error_message = os.getenv('ERROR_MESSAGE')

    if not error_message:
        print("No error message provided!")
        return

    try:
        # Extract API Gateway details from the error message
        api_gw_id, aws_region, api_stage = extract_api_details(error_message)

        # Fetch API Gateway logs
        api_logs = fetch_api_gateway_logs(api_gw_id, aws_region, api_stage)
        if not api_logs:
            print("No API Gateway logs found!")
            return

        # Extract Lambda function name from API Gateway logs
        lambda_name = None
        for log_event in api_logs:
            lambda_match = re.search(r'(?<=function: )[^ ]+', log_event['message'])
            if lambda_match:
                lambda_name = lambda_match.group(0)
                break

        if not lambda_name:
            print("No Lambda function found in API Gateway logs!")
            return

        # Fetch Lambda logs
        lambda_logs = fetch_lambda_logs(lambda_name, aws_region)
        if not lambda_logs:
            print("No Lambda logs found!")
            return

        # Output logs
        print("API Gateway Logs:")
        for log in api_logs:
            print(log['message'])

        print("\nLambda Logs:")
        for log in lambda_logs:
            print(log['message'])

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
