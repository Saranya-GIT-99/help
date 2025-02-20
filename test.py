import os
import json
import urllib.parse
import requests

def validate_git_sod(jfrogurl):
    # Fetch metadata from JFrog
    outfull = jfrogurl + '?properties'
    x = requests.get(outfull, headers={"X-JFrog-Art-Api": os.environ['jfrogApiKey']})

    if x.status_code != 200:
        return {"status": "error", "message": f"Failed to fetch JFrog metadata: {x.text}"}

    out_prop = json.loads(x.content)

    env_tagging = 'git.url'
    env_tagging_1 = 'git.branch'
    env_tagging_2 = 'git.hash'

    if env_tagging in out_prop['properties']:
        git_url = out_prop['properties'][env_tagging][0]
    else:
        return {"status": "error", "message": "Git URL not found in JFrog metadata."}

    if env_tagging_1 in out_prop['properties']:
        git_branch = out_prop['properties'][env_tagging_1][0]
    else:
        return {"status": "error", "message": "Git branch not found in JFrog metadata."}

    if env_tagging_2 in out_prop['properties']:
        git_hash = out_prop['properties'][env_tagging_2][0]
    else:
        return {"status": "error", "message": "Git hash not found in JFrog metadata."}

    # Parse GitLab project details
    GITLAB_DOMAIN = "gitlab.abcd.net"
    parsed = urllib.parse.urlparse(git_url)
    path = parsed.path.strip('/')
    encoded_path = urllib.parse.quote(path, safe='')

    # Extract commit ID
    commit_id = git_hash.split("-")[-1]

    # Fetch GitLab Token from environment
    TOKEN = os.getenv("GITLAB_TOKEN")
    if not TOKEN:
        return {"status": "error", "message": "GITLAB_TOKEN environment variable not set."}

    # Get GitLab project ID
    gitlab_url = f"https://{GITLAB_DOMAIN}"
    api_url = f"{gitlab_url}/api/v4/projects/{encoded_path}"
    headers = {"Private-Token": TOKEN}

    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        return {"status": "error", "message": f"Error fetching project ID: {response.text}"}
    
    project_id = response.json()["id"]

    # Get commit details
    commit_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/repository/commits/{commit_id}"
    commit_response = requests.get(commit_api_url, headers=headers)

    if commit_response.status_code == 200:
        commit_data = commit_response.json()
        commit_author = commit_data["author_email"]
        committer = commit_data["committer_email"]
    else:
        return {"status": "error", "message": f"Error fetching commit details: {commit_response.text}"}

    # Get merge request approvers
    mr_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests"
    mr_response = requests.get(mr_api_url, headers=headers)

    approver_emails = []
    if mr_response.status_code == 200:
        merge_requests = mr_response.json()
        for mr in merge_requests:
            approvers = mr.get("approved_by", [])
            approver_emails = [approver["user"]["email"] for approver in approvers] if approvers else []
    else:
        return {"status": "error", "message": f"Error fetching merge request approvers: {mr_response.text}"}

    return {
        "commit_author": commit_author,
        "committer": committer,
        "approver_emails": approver_emails
    }

def lambda_handler(event, context):
    try:
        jfrog_url = event.get("jfrog_url")
        pipeline_executor = event.get("pipeline_executor")

        if not jfrog_url or not pipeline_executor:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing required parameters: jfrog_url or pipeline_executor"})
            }

        result = validate_git_sod(jfrog_url)

        if "error" in result:
            return {
                "statusCode": 500,
                "body": json.dumps(result)
            }

        commit_author = result["commit_author"]
        committer = result["committer"]
        approver_emails = result["approver_emails"]

        # **❌ Fail pipeline if executor is in commit/approval process**
        if pipeline_executor in [commit_author, committer] or pipeline_executor in approver_emails:
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "status": "failed",
                    "message": f"❌ Pipeline execution failed! {pipeline_executor} is part of the commit/approval process."
                })
            }

        # ✅ Pipeline execution allowed
        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "success",
                "message": f"✅ Pipeline execution allowed. {pipeline_executor} is not part of the commit/approval process."
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
