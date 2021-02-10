# 暴力测试代码基本流程
# test url
# http://192.168.15.128/xss/example1.php?name=hacker
from urllib.parse import urlparse
from core.utils import getParams, getUrl
import copy
import requests


def brutePayload(target, payloadfile):
    payloads = ['<script>alert("xss")</script>']
    host = urlparse(target).netloc
    print('Brute host:{}'.format(host))
    url = getUrl(target)
    print('Brute url:{}'.format(url))
    params = getParams(target)
    if not params:
        print('没有检测到待测试的参数')
        return
    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        print('Brute Testing param:{}'.format(paramName))
        for payload in payloads:
            paramsCopy[paramName] = payload
            print(paramsCopy)
            response = requests.get(url=url, params=paramsCopy)
            if payload in response.text:
                print('Find XSS url:{} param:{} payload:{}'.format(url, paramName, payload))
