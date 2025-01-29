#!/bin/bash
set -e

echo "Step 1: Identifying All Webhook Stages in the Pipeline"

# Get all webhook stages from execution context
WEBHOOK_STAGES=$(jq -c '.execution.stages[] | select(.type=="webhook")' <<< "$PIPELINE_JSON")

if [ -z "$WEBHOOK_STAGES" ]; then
    echo "No webhook stages found. Exiting..."
    exit 0
fi

echo "Found $(echo "$WEBHOOK_STAGES" | wc -l) Webhook Stages"

# Iterate through each webhook stage
for stage in $(echo "$WEBHOOK_STAGES" | jq -c '.'); do
    STAGE_NAME=$(echo "$stage" | jq -r '.name')
    STAGE_STATUS=$(echo "$stage" | jq -r '.status')
    FAILURE_MESSAGE=$(echo "$stage" | jq -r '.context.error')

    echo "Checking Webhook Stage: $STAGE_NAME - Status: $STAGE_STATUS"

    if [ "$STAGE_STATUS" == "SUCCEEDED" ]; then
        echo "Webhook Stage $STAGE_NAME Passed. Skipping..."
        continue
    fi

    echo "Webhook Stage $STAGE_NAME Failed! Extracting Error Details..."

    # Extract API Gateway URL from the error message
    API_URL=$(echo "$FAILURE_MESSAGE" | grep -oP 'https://[^\s]+')

    if [ -z "$API_URL" ]; then
        echo "Could not extract API Gateway URL from error message!"
        continue
    fi

    # Extract API Gateway ID, AWS Region, and Stage Name
    API_GW_ID=$(echo "$API_URL" | awk -F'[/.]' '{print $3}')
    AWS_REGION=$(echo "$API_URL" | grep -oP '(?<=execute-api\.)[^.]+')
    API_STAGE=$(echo "$API_URL" | awk -F'/' '{print $NF}')

    echo "Extracted API Gateway ID: $API_GW_ID"
    echo "Extracted API Stage: $API_STAGE"
    echo "Extracted AWS Region: $AWS_REGION"

    echo "Fetching API Gateway Logs for Failed Webhook Stage"

    ERROR_LOGS=$(aws logs filter-log-events --log-group-name "/aws/api-gateway/$API_GW_ID/$API_STAGE" \
    --region "$AWS_REGION" --filter-pattern 'ERROR' --limit 1)

    if [ -z "$ERROR_LOGS" ]; then
        echo "No API Gateway error logs found!"
        continue
    fi

    echo "Found API Gateway Logs"

    # Extract Lambda Function Name from API Gateway Logs
    LAMBDA_NAME=$(echo "$ERROR_LOGS" | grep -oP '(?<=function: )[^ ]+')

    if [ -z "$LAMBDA_NAME" ]; then
        echo "No Lambda function found in API Gateway logs!"
        continue
    fi

    echo "Fetching Lambda Logs for $LAMBDA_NAME"

    # Fetch Lambda logs
    LOG_GROUP="/aws/lambda/$LAMBDA_NAME"
    LAMBDA_LOGS=$(aws logs tail "$LOG_GROUP" --region "$AWS_REGION" --since 5m --format short)

    if [ -z "$LAMBDA_LOGS" ]; then
        echo "No logs found for Lambda: $LAMBDA_NAME"
        continue
    fi

    echo "Successfully retrieved Lambda logs!"

    # Save logs in a JSON file for Spinnaker UI
    echo "{\"stage\":\"$STAGE_NAME\",\"lambdaLogs\":\"$LAMBDA_LOGS\"}" >> /mnt/spinnaker/output.json
done

echo "All Failed Webhook Stages Processed. Logs Available in Spinnaker UI!"
