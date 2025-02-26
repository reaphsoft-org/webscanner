#!/usr/bin/env python
import time

from requests.exceptions import ProxyError
from zapv2 import ZAPv2
from django.conf import settings

zap = ZAPv2(apikey=settings.ZAP_API_KEY)

def spider(target_url):
    """"""
    try:
        scan_id = zap.spider.scan(target_url)
        return int(scan_id), ""
    except ProxyError:
        return -1, "Scanner was unable to connect to proxy."
