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
    cwes = list(filter(lambda i: i["cweid"] != "-1", alerts))
    non_cwes = filter(lambda i: i["cweid"] == "-1", alerts)
    cwes.sort(key=lambda x: int(x["cweid"]))
    groups = groupby(cwes, lambda i: int(i["cweid"]))

    results = []
    for group, items in groups:
        _list = list(items)
        _sample = _list[0]
        dic = {"name": _sample["name"], "cweid": _sample["cweid"], "description": _sample["description"],
               "risk": _sample["risk"], "solution": _sample["solution"],
               "urls": [(i["confidence"], i["url"]) for i in _list], "tags": list(_sample["tags"].items())}
        results.append(dic)
    results.extend(
        [
            {"name": _sample["name"], "cweid": _sample["cweid"], "description": _sample["description"],
             "risk": _sample["risk"], "solution": _sample["solution"],
             "urls": [(_sample["confidence"], _sample["url"])],
             "tags": list(_sample["tags"].items())}
            for _sample in non_cwes
        ]
    )
    return results