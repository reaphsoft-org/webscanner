#!/usr/bin/env python
import time
from itertools import groupby

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


def ajax_spider(target_url):
    """
    When this function is called, do
    >>> timeout = time.time() * 60 * 2 # 2 minutes from now
    Then

    >>> while zap.ajaxSpider.status == 'running':
            if time.time() > timeout:
                break
            print('Ajax Spider status' + zap.ajaxSpider.status)
            time.sleep(2)
    """
    try:
        scan_id = zap.ajaxSpider.scan(target_url)
        return int(scan_id), ""
    except ProxyError:
        return -1, "Scanner was unable to connect to proxy."


def passive_scan_results(target_url):
    alerts = zap.core.alerts(baseurl=target_url)
    groups = groupby(alerts, lambda i: i["name"])

    results = []
    for group, items in groups:
        dic = {"name": group}
        _list = list(items)
        _sample = _list[0]
        dic["cweid"] = _sample["cweid"]
        dic["description"] = _sample["description"]
        dic["risk"] = _sample["risk"]
        dic["solution"] = _sample["solution"]
        dic["urls"] = [(i["confidence"], i["url"]) for i in _list]
        dic["tags"] = list(_sample["tags"].keys())
        results.append(dic)

    return results