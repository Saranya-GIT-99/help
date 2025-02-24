import requests
import getpass
from urllib.parse import urljoin

def get_gitlab_projects_without_topics():
    # Get credentials at runtime
    gitlab_url = input("Enter GitLab instance URL (e.g., https://gitlab.com): ").strip()
    access_token = getpass.getpass("Enter your GitLab access token: ")

    # API configuration
    api_base = urljoin(gitlab_url, "/api/v4/")
    headers = {"PRIVATE-TOKEN": access_token}
    
    projects = []
    page = 1
    per_page = 100  # Max allowed by GitLab API

    try:
        while True:
            # Get paginated projects
            url = f"{api_base}projects"
            params = {
                "per_page": per_page,
                "page": page,
                "simple": "true",
                "membership": "true"  # Only projects you have access to
            }

            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()

            batch = response.json()
            if not batch:
                break

            # Filter projects without topics
            for project in batch:
                if not project['topics']:  # Exclude projects with topics
                    projects.append({
                        "id": project['id'],
                        "name": project['name'],
                        "web_url": project['web_url'],
                        "path_with_namespace": project['path_with_namespace']
                    })

            # Check for next page
            if 'X-Next-Page' in response.headers:
                page = int(response.headers['X-Next-Page'])
            else:
                break

    except requests.exceptions.RequestException as e:
        print(f"Error accessing GitLab API: {str(e)}")
        return None

    return projects

if __name__ == "__main__":
    projects = get_gitlab_projects_without_topics()
    
    if projects:
        print("\nProjects without topics:")
        for idx, project in enumerate(projects, 1):
            print(f"{idx}. {project['path_with_namespace']}")
            print(f"   URL: {project['web_url']}\n")
    else:
        print("No projects found without topics or error occurred.")
