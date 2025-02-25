import gitlab
import pandas as pd
import getpass

def get_gitlab_credentials():
    """Get GitLab URL and access token from user input"""
    print("Enter GitLab configuration:")
    url = input("GitLab URL (e.g., https://gitlab.example.com): ").strip()
    token = getpass.getpass("Personal Access Token: ").strip()
    return url, token

def get_all_projects(gl):
    projects = []
    try:
        # Get all projects with topics in initial listing
        all_projects = gl.projects.list(
            get_all=True,
            iterator=True,
            with_topics=True  # Include topics in initial response
        )
        
        for project in all_projects:
            try:
                projects.append({
                    'id': project.id,
                    'name': project.name,
                    'path_with_namespace': project.path_with_namespace,
                    'web_url': project.web_url,
                    'created_at': project.created_at,
                    'last_activity_at': project.last_activity_at,
                    'topics': ', '.join(project.topics) if project.topics else 'No Topics'
                })
                print(f"Processed: {project.path_with_namespace}")
            except Exception as e:
                print(f"Error processing project {project.id}: {str(e)}")
    except Exception as e:
        print(f"Error fetching projects: {str(e)}")
    return projects

def generate_report(projects):
    df = pd.DataFrame(projects)
    df['has_topic'] = df['topics'].apply(lambda x: 'Yes' if x != 'No Topics' else 'No')
    
    filename = 'gitlab_projects_report.xlsx'
    df.to_excel(filename, index=False)
    print(f"\nReport generated: {filename}")

def main():
    url, token = get_gitlab_credentials()
    
    try:
        print("\nConnecting to GitLab...")
        gl = gitlab.Gitlab(url, private_token=token)
        gl.auth()
        print("Connection successful!\n")
        
        projects = get_all_projects(gl)
        if projects:
            generate_report(projects)
        else:
            print("No projects found or error occurred during fetching.")
    except Exception as e:
        print(f"\nError connecting to GitLab: {str(e)}")
        print("Please verify your URL and access token.")

if __name__ == "__main__":
    main()
