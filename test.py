import os
import requests
import json
import urllib.parse

def validate_git_sod(jfrogurl):
    # Fetch metadata from JFrog
    outfull = jfrogurl + '?properties'
    x = requests.get(outfull, headers={"X-JFrog-Art-Api": os.environ['jfrogApiKey']})
    out_prop = json.loads(x.content)
    
    # Extract Git metadata properties
    env_tagging = 'git.url'
    env_tagging_1 = 'git.branch'
    env_tagging_2 = 'git.hash'

    if env_tagging in out_prop['properties']:
        git_url = out_prop['properties'][env_tagging][0]
    else:
        print("Error: Git URL not found in JFrog metadata.")
        return

    if env_tagging_1 in out_prop['properties']:
        git_branch = out_prop['properties'][env_tagging_1][0]
    else:
        print("Error: Git branch not found in JFrog metadata.")
        return

    if env_tagging_2 in out_prop['properties']:
        git_hash = out_prop['properties'][env_tagging_2][0]
    else:
        print("Error: Git hash not found in JFrog metadata.")
        return

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
        print("Error: GITLAB_TOKEN environment variable not set.")
        return

    # Get GitLab project ID
    gitlab_url = f"https://{GITLAB_DOMAIN}"
    api_url = f"{gitlab_url}/api/v4/projects/{encoded_path}"
    headers = {"Private-Token": TOKEN}

    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        print(f"Error fetching project ID: {response.text}")
        return
    project_id = response.json()["id"]

    # Get commit details
    commit_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/repository/commits/{commit_id}"
    commit_response = requests.get(commit_api_url, headers=headers)

    if commit_response.status_code == 200:
        commit_data = commit_response.json()
        print("\nFiltered Commit Details:")
        print(f"Commit: {commit_data['id']}")
        print(f"  Author: {commit_data['author_name']} ({commit_data['author_email']})")
        print(f"  Committer: {commit_data['committer_name']} ({commit_data['committer_email']})")
        print(f"  Message: {commit_data['title']}\n")
    else:
        print(f"Error fetching commit details: {commit_response.text}")

    # Get merge request approvers
    mr_api_url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests"
    mr_response = requests.get(mr_api_url, headers=headers)

    if mr_response.status_code == 200:
        merge_requests = mr_response.json()
        print("\nMerge Request Approvers:")
        for mr in merge_requests:
            approvers = mr.get("approved_by", [])
            approver_names = [approver["user"]["name"] for approver in approvers] if approvers else ["None"]
            print(f"  MR ID: {mr['id']}, Approvers: {', '.join(approver_names)}")
    else:
        print(f"Error fetching merge request approvers: {mr_response.text}")
