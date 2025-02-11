import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

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

# Example usage:
if __name__ == "__main__":
    target_url = "https://example.com"
    crawler = WebCrawler(target_url, max_depth=2)
    urls = crawler.start_crawl()
    print("Discovered URLs:", urls)
