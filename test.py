import os
import random
import string
import test
import requests
from core.utils import getUrl, getParams, random_upper, get_complete_url,add_extra_params
import copy
from bs4 import BeautifulSoup
import re
from core.htmlparser import MyHTMLParser, searchInputInResponse
from urllib.parse import urlparse


def testurl():
    urls = ['http://192.168.15.128/xss/example1.php?name=hacker',
            'http://192.168.15.128/xss/example2.php?name=hacker',
            'http://192.168.15.128/xss/example3.php?name=hacker',
            'http://192.168.15.128/xss/example4.php?name=hacker',
            'http://192.168.15.128/xss/example5.php?name=hacker',
            'http://192.168.15.128/xss/example6.php?name=hacker',
            'http://192.168.15.128/xss/example7.php?name=hacker'
            ]
    return urls


html_doc = '''
<!DOCTYPE html>

<html lang="en">
<head>
<meta charset="utf-8"/>
<title>PentesterLab » Web for Pentester</title>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<meta content="Web For Pentester" name="description"/>
<meta content="Louis Nyffenegger (louis@pentesterlab.com)" name="author"/>
<!-- Le styles -->
<link href="/css/bootstrap.css" rel="stylesheet"/>
<style type="text/css">
      body {
        padding-top: 60px;
        padding-bottom: 40px;
      }
    </style>
<link href="/css/bootstrap-responsive.css" rel="stylesheet"/>
</head>
<body>
<div class="navbar navbar-inverse navbar-fixed-top">
<div class="navbar-inner">
<div class="container">
<a class="btn btn-navbar" data-target=".nav-collapse" data-toggle="collapse">
<span class="icon-bar"></span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
</a>
<a class="brand" href="https://pentesterlab.com/">PentesterLab.com</a>
<div class="nav-collapse collapse">
<ul class="nav">
<li class="active"><a href="/">Home</a></li>
</ul>
</div><!--/.nav-collapse -->
</div>
</div>
</div>
<div class="container">
<html>
Hello 
xsscheck
      <footer>
<p>© PentesterLab 2013</p>
</footer>
</html></div> <!-- /container -->
</body>
</html>

'''


class Test(object):
    def __init__(self, result):
        self.result = result

    def test(self):
        print(self.result)

    def test2(self):
        print(self.result)

    pass


if __name__ == '__main__':
    # print('Find XSS vul :{} param:{} payload:{}'.format(11, 22, 33))
    # params = {'name': '<script>alert("xss")</script>'}
    urls = getUrl(url=testurl())
    # res = requests.get(url=url, params=params)
    # print(res.text)

    # 测试htmlparser
    # for url in urls:
    #     _url = getUrl(url)
    #     print('***********' + '正在解析' + _url + '*************')
    #     params = getParams(url)
    #     for paramsName in params.keys():
    #         params[paramsName] = 'xsscheck'
    #     res = requests.get(url=_url, params=params)
    #     occurences = searchInputInResponse(html_doc=res.text, xsscheck='xsscheck')
    #     for o in occurences:
    #         print('注入点类型:' + o['type'])
    #         print('注入点id:' + str(o['position']))
    #         print('注入点详细信息:')
    #         print('标签名:' + o['details']['tagname'], end='')
    #         print('\t标签属性:' + str(o['details']['attributes']), end='')
    #         print('\n标签内容:' + o['details']['content'] + '\n', end='')

    url = 'https://cn.bing.com/search?q=python+%E5%A6%82%E4%BD%95%E8%8E%B7%E5%BE%97request%E6%8A%A5%E6%96%87&qs=n&form=QBRE&msbsrank=0_0__0&sp=-1&pq=python+%E5%A6%82%E4%BD%95%E8%8E%B7%E5%BE%97request%E6%8A%A5%E6%96%87&sc=0-20&sk=&cvid=FECCAF3B63174E258EA64ACC74B461B3'
    params = getParams(url)
    host = getUrl(url)
    # print(params)
    # print(host)
    # print(url)
    # print(get_complete_url(url=host, params=params))
    params = add_extra_params(params=params)
    print(params)
