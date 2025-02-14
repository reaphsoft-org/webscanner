import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VulnerabilitySignature
from .serializers import VulnerabilitySignatureSerializer


class FetchVulnerabilitiesAPI(APIView):
    def get(self, request):
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
        response = requests.get(api_url)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                vuln = {
                    "name": cve_data.get("id", "Unknown"),
                    "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                    "severity": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get(
                        "baseSeverity", "Unknown"),
                    "affected_component": "General",
                    "pattern": "N/A",
                }
                vulnerabilities.append(vuln)
            import pprint
            pprint.pprint(vulnerabilities)
            return Response(vulnerabilities, status=status.HTTP_200_OK)

        return Response({"error": "Failed to fetch data"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)