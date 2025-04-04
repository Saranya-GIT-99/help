import requests
import csv

def get_gitlab_users(gitlab_url, access_token):
    """
    Retrieves a list of GitLab users with their ID, username, and email.

    Args:
        gitlab_url (str): The base URL of your GitLab instance (e.g., "https://gitlab.example.com").
        access_token (str): A personal access token with the 'read_user' scope.

    Returns:
        list: A list of dictionaries, where each dictionary represents a user and contains their 'id', 'username', and 'email'.
        Returns None on error with printing the error.
    """
    users = []
    page = 1
    per_page = 100  # Adjust as needed

    headers = {"PRIVATE-TOKEN": access_token}

    try:
        while True:
            url = f"{gitlab_url}/api/v4/users?page={page}&per_page={per_page}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            page_users = response.json()
            if not page_users:
                break

            for user in page_users:
                users.append({
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"]
                })

            page += 1
        return users

    except requests.exceptions.RequestException as e:
        print(f"Error fetching users: {e}")
        return None
    except KeyError as e:
        print(f"Error parsing user data: {e}. Check if the access token has the correct scope.")
        return None

def main():
    gitlab_url = input("Enter your GitLab URL (e.g., https://gitlab.example.com): ")
    access_token = input("Enter your GitLab personal access token: ")
    output_file = input("Enter the output CSV file name (default: gitlab_users.csv): ") or "gitlab_users.csv"

    users = get_gitlab_users(gitlab_url, access_token)

    if users:
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["id", "username", "email"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for user in users:
                writer.writerow(user)

        print(f"User data saved to {output_file}")

if __name__ == "__main__":
    main()
