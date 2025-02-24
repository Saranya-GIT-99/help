import requests
import getpass
import pandas as pd
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class GitLabProjectExporter:
    def __init__(self):
        self.base_url = None
        self.headers = None
        self.session = requests.Session()
        self.per_page = 100  # Max allowed by GitLab API
        self.total_projects = 0

    def configure(self):
        """Get runtime configuration"""
        self.base_url = urljoin(
            input("Enter GitLab instance URL (e.g., https://gitlab.com): ").strip(),
            "/api/v4/"
        )
        self.headers = {"PRIVATE-TOKEN": getpass.getpass("Enter your GitLab access token: ")}
        
    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, max=10))
    def fetch_page(self, page):
        """Fetch a single page of projects with retry logic"""
        try:
            response = self.session.get(
                f"{self.base_url}projects",
                headers=self.headers,
                params={
                    "per_page": self.per_page,
                    "page": page,
                    "membership": "true",
                    "statistics": "true",
                    "order_by": "last_activity_at",
                    "sort": "desc",
                    "simple": "false"
                },
                timeout=30
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch page {page}: {str(e)}")
            raise

    def process_projects(self, response):
        """Process batch of projects"""
        projects = []
        for project in response.json():
            if not project.get('topics'):
                try:
                    projects.append({
                        "id": project['id'],
                        "name": project['name'],
                        "path_with_namespace": project['path_with_namespace'],
                        "web_url": project['web_url'],
                        "created_at": project['created_at'],
                        "last_activity_at": project['last_activity_at'],
                        "visibility": project['visibility'],
                        "open_issues": project.get('open_issues_count', 0),
                        "storage_size": project.get('statistics', {}).get('storage_size', 0) // 1024 // 1024,
                        "archived": project.get('archived', False)
                    })
                except KeyError as e:
                    logging.warning(f"Skipping project {project.get('id')} missing field: {e}")
        return projects

    def fetch_all_projects(self):
        """Fetch all projects using parallel requests"""
        logging.info("Starting project export...")
        
        # Get first page to determine total count
        initial_response = self.fetch_page(1)
        total_pages = int(initial_response.headers.get('X-Total-Pages', 1))
        self.total_projects = int(initial_response.headers.get('X-Total', 0))
        
        logging.info(f"Total projects to process: {self.total_projects} ({total_pages} pages)")

        # Process first page
        all_projects = self.process_projects(initial_response)

        # Process remaining pages in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for page in range(2, total_pages + 1):
                futures.append(executor.submit(self.fetch_page, page))
                
            for future in futures:
                try:
                    response = future.result()
                    all_projects.extend(self.process_projects(response))
                except Exception as e:
                    logging.error(f"Failed to process page: {str(e)}")

        logging.info(f"Successfully processed {len(all_projects)} projects")
        return all_projects

    def export_to_excel(self, projects):
        """Export results to optimized Excel file"""
        if not projects:
            logging.warning("No projects found to export")
            return

        logging.info("Creating Excel report...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"gitlab_projects_export_{timestamp}.xlsx"

        # Create DataFrame with optimized data types
        df = pd.DataFrame(projects)
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['last_activity_at'] = pd.to_datetime(df['last_activity_at'])

        # Use efficient Excel writer
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Projects')
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Projects']
            for column in worksheet.columns:
                max_length = max(len(str(cell.value)) for cell in column)
                worksheet.column_dimensions[column[0].column_letter].width = max_length + 2

        logging.info(f"Excel report generated: {filename}")

if __name__ == "__main__":
    exporter = GitLabProjectExporter()
    exporter.configure()
    projects = exporter.fetch_all_projects()
    exporter.export_to_excel(projects)
