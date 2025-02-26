#!/usr/bin/env python
import time
from zapv2 import ZAPv2
from django.conf import settings

zap = ZAPv2(apikey=settings.ZAP_API_KEY)

def spider(target_url):
    """"""
    return zap.spider.scan(target_url)
