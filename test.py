from core.checkstatus import check_status
import requests
from urllib.parse import urlparse
from core.utils import request_info

def testurl():
    # pentester 测试
    # urls = ['http://192.168.15.128/xss/example1.php?name=hacker',
    #         'http://192.168.15.128/xss/example2.php?name=hacker',
    #         'http://192.168.15.128/xss/example3.php?name=hacker',
    #         'http://192.168.15.128/xss/example4.php?name=hacker',
    #         'http://192.168.15.128/xss/example5.php?name=hacker',
    #         'http://192.168.15.128/xss/example6.php?name=hacker',
    #         'http://192.168.15.128/xss/example7.php?name=hacker'
    #         ]
    urls = [
        '127.0.0.1/htmlcontent.php?payload=1'
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

if __name__ == '__main__':
    # urls = [
    #     'ad.nearme.com.cn/administracion',
    #     'ad.nearme.com.cn/consumer',
    #     'ad.nearme.com.cn/admin_files',
    #     'ad.nearme.com.cn/page/Administrator',
    #     'ad.nearme.com.cn/pub/sitemap',
    #     'ad.nearme.com.cn/d.php',
    #     'www.baidu.com',
    #     'www.bing.com'
    # ]
    #
    # res = check_status(urls)
    # print(res)
    # file_path = 'E:\\test.txt'
    # with open(file_path, 'w') as f:
    #     for u in res:
    #         f.write(u + '\n')
    # print('结束')

    # url = 'https://cn.bing.com/search?q=1'
    # res = requests.get('https://cn.bing.com/search?q=1')
    # dic = request_info(url, res)
    # print(dic)

    print("\033[0;31;40m{url}参数{param}发现潜在注入点 \033[0m".format(url='b', param='a'))



