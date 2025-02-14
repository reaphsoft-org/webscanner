import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VulnerabilitySignature
from .serializers import VulnerabilitySignatureSerializer


class FetchVulnerabilitiesAPI(APIView):
    def get(self, request):
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response = requests.get(api_url)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            for item in data.get("result", {}).get("CVE_Items", []):
                vuln = {
                    "name": item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown"),
                    "description": item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get(
                        "value", ""),
                    "severity": item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity",
                                                                                                     "Unknown"),
                    "affected_component": "General",
                    "pattern": "N/A",
                }
                vulnerabilities.append(vuln)

            return Response(vulnerabilities, status=status.HTTP_200_OK)

        return Response({"error": "Failed to fetch data"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
