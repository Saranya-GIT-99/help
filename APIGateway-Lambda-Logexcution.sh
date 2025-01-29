#!/bin/bash
set -e

AWS_REGION="us-east-1"
API_GW_STAGE="your-stage"
API_GW_ID="your-api-gateway-id"

# Find the last failed API Gateway request
ERROR_LOGS=$(aws logs filter-log-events --log-group-name "/aws/api-gateway/$API_GW_ID/$API_GW_STAGE" --region "$AWS_REGION" --filter-pattern 'ERROR' --limit 1)

# Extract Lambda function name
LAMBDA_NAME=$(echo "$ERROR_LOGS" | jq -r '.events[0].message' | grep -oP '(?<=function: )[^ ]+')

# Fetch Lambda logs
if [ -n "$LAMBDA_NAME" ]; then
    LOG_GROUP="/aws/lambda/$LAMBDA_NAME"
    echo "Fetching logs for Lambda: $LAMBDA_NAME"
    aws logs tail "$LOG_GROUP" --region "$AWS_REGION" --since 5m --format short
else
    echo "No failed Lambda invocation found."
fi
