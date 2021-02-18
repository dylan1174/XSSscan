import os
import random
import string
import test
import requests
from core.utils import getUrl, getParams, random_upper, get_complete_url, add_extra_params
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
import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", help="set thread count",
                        type=int, dest='thread_count')
    args = parser.parse_args()
    print(type(args.thread_count))
    print('线程数被设置为' + str(args.thread_count))


