from .crawler import WebCrawler  # Import your crawler


class AsyncResult:
    """"""
    def __init__(self, task_id):
        self.state = "RUNNING"
        self.results = []


class LongRunningTask:
    def __init__(self, function):
        self.id = 0
        self.function = function
    def delay(self, *args):
        # self.results = self.function(*args) # Call the original function, potentially long running
        return self


shared_task = LongRunningTask

@shared_task
def run_crawler(target_url, max_depth=2):
    crawler = WebCrawler(target_url, max_depth)
    return list(crawler.start_crawl())

@shared_task
def run_fuzzy(target_url):
    crawler = WebCrawler(target_url)
    return crawler.send_fuzz_request()