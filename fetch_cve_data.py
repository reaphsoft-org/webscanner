import os
import time
import requests
import django
from django.core.paginator import Paginator
from django.utils import timezone
from django.utils.dateparse import parse_datetime

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web_scanner.settings")
django.setup()

from zap.models import CVE
from zap.tasks import get_cves_by_cwe

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")


def fetch_cve_data(start_index=0, results_per_page=2000, last_request_time=None):
    headers = {"apiKey": API_KEY}  # API key in headers
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    if last_request_time:
        elapsed_time = time.time() - last_request_time
        if elapsed_time < 6:
            time.sleep(6 - elapsed_time)  # Ensure at least 6 seconds between requests

    start_time = time.time()
    response = requests.get(NVD_API_URL, params=params, headers=headers)

    if response.status_code != 200:
        print(f"Error fetching data at start_index {start_index}: {response.status_code}")
        return [], start_time

    response_json = response.json()
    get_start_index = response_json.get("startIndex", 0)
    get_total_results = response_json.get("totalResults", 0)
    if get_start_index > get_total_results:
        print(f"Response Start Index: {get_start_index}, Response Total Results: {get_total_results}, Start Index: {start_index}")
    return response_json.get("vulnerabilities", []), start_time


def save_cve_data():
    start_index = 150000 # continue from 48000, network has issues at that time.
    results_per_page = 2000
    cve_objects = []
    last_request_time = None

    while True:
        print(f"Fetching at Start Index: {start_index} with API Key: {API_KEY}")
        cve_items, last_request_time = fetch_cve_data(start_index, results_per_page, last_request_time)
        if not cve_items:
            break  # Stop if there are no more results

        for item in cve_items:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            source_identifier = cve_data.get("sourceIdentifier", "")
            vuln_status = cve_data.get("vulnStatus", "")
            published_date = timezone.make_aware(parse_datetime(cve_data.get("published", "")))
            last_modified_date = timezone.make_aware(parse_datetime(cve_data.get("lastModified", "")))

            # Optional fields
            evaluator_comment = cve_data.get("evaluatorComment", "")
            evaluator_solution = cve_data.get("evaluatorSolution", "")
            evaluator_impact = cve_data.get("evaluatorImpact", "")
            descriptions = cve_data.get("descriptions", [])
            metrics = cve_data.get("metrics", {})
            weaknesses = cve_data.get("weaknesses", [])
            configurations = cve_data.get("configurations", [])
            references = cve_data.get("references", [])
            vendor_comments = cve_data.get("vendorComments", [])

            # CISA fields
            cisa_exploit_add = cve_data.get("cisaExploitAdd")
            cisa_action_due = cve_data.get("cisaActionDue")
            cisa_required_action = cve_data.get("cisaRequiredAction")
            cisa_vulnerability_name = cve_data.get("cisaVulnerabilityName")
            cve_tags = cve_data.get("cveTags", [])

            cve_objects.append(CVE(
                cve_id=cve_id,
                source_identifier=source_identifier,
                vuln_status=vuln_status,
                published_date=published_date,
                last_modified_date=last_modified_date,
                evaluator_comment=evaluator_comment,
                evaluator_solution=evaluator_solution,
                evaluator_impact=evaluator_impact,
                descriptions=descriptions,
                metrics=metrics,
                weaknesses=weaknesses,
                configurations=configurations,
                references=references,
                cisa_exploit_add=cisa_exploit_add,
                cisa_action_due=cisa_action_due,
                cisa_required_action=cisa_required_action,
                cisa_vulnerability_name=cisa_vulnerability_name,
                cve_tags=cve_tags,
                vendor_comments=vendor_comments,
            ))

        CVE.objects.bulk_create(cve_objects, ignore_conflicts=True)
        cve_objects.clear()  # Clear list after inserting
        start_index += results_per_page  # Move to the next batch


def check():
    """"""
    cve = CVE.objects.get(id=1)
    print(cve, cve.weaknesses, CVE.objects.all().count())


if __name__ == "__main__":
    """"""
    # save_cve_data()
    # check()