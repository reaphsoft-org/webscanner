from celery import shared_task
from .crawler import WebCrawler  # Import your crawler

@shared_task
def run_crawler(target_url, max_depth=2):
    crawler = WebCrawler(target_url, max_depth)
    return list(crawler.start_crawl())

@shared_task
def run_fuzzy(target_url):
    crawler = WebCrawler(target_url)
    return crawler.send_fuzz_request()