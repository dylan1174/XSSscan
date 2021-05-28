# 潜在注入点测试
# 输入response响应页面 测试字段  返回页面中所有回显的信息字典
# 信息字典包含内容 测试字段在响应报文中的位置 执行环境(script标签 html页面 标签的属性) 详细信息 (标签的类型 key or value 被什么包裹)

from html.parser import HTMLParser

'''
开始标签: 将标签名 属性(key value)字典加入到树中
结束标签: 如果树不为空 则弹出树中的开始标签 并将开始标签信息加入分词器tokenizer中
自结束标签 如<img/>: 调用开始标签压入树 再调用结束标签加入分词器中
文本内容: 默认文本内容在两个标签中 将文本内容加入树中最后一个压入的标签content属性中
getTokenizer将树中的值压入tokenizer中
'''


class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tree = []
        self.tokenizer = []
        self.root = None
        temp = {
            "tagname": "",
            "content": "",
            "attributes": []
        }

    def handle_starttag(self, tag, attrs):
        if len(self.tree) == 0:
            self.root = tag
        self.tree.append(
            {
                "tagname": tag,
                "content": "",
                "attributes": attrs
            }
        )

    def handle_endtag(self, tag):
        if len(self.tree) > 0:
            r = self.tree.pop()
            self.tokenizer.append(r)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data):
        if self.tree:
            self.tree[-1]["content"] += data

    def handle_comment(self, data):
        self.tokenizer.append({
            "tagname": "#comment",
            "content": data,
            "attributes": []
        })

    def getTokenizer(self):
        while len(self.tree):
            r = self.tree.pop()
            self.tokenizer.append(r)
        return self.tokenizer


# 潜在注入点检测
def searchInputInResponse(html_doc, xsscheck):
    parse = MyHTMLParser()
    parse.feed(html_doc)
    tokens = parse.getTokenizer()
    occurences = []
    index = 0
    # 遍历每一个标签 找到注入点的环境信息
    for token in tokens:
        _xsscheck = xsscheck
        origin_length = len(occurences)
        tagname = token["tagname"]
        content = token["content"]
        attributes = token["attributes"]
        # 如果xsscheck处于tagname中
        if _xsscheck in tagname:
            occurences.append({
                'type': 'inTag',
                'position': index,
                'details': token
            })
        # 如果xsscheck处于content中
        elif _xsscheck in content:
            if tagname == "#comment":
                occurences.append({
                    "type": "comment",
                    "position": index,
                    "details": token,
                })
            elif tagname == "script":
                occurences.append({
                    "type": "script",
                    "position": index,
                    "details": token,
                })
            elif tagname == "style":
                occurences.append({
                    "type": "html",
                    "position": index,
                    "details": token,
                })
            else:
                occurences.append({
                    "type": "html",
                    "position": index,
                    "details": token,
                })
        # 如果xsscheck在标签属性中
        else:
            # 判断是在name中还是value中
            for k, v in attributes:
                content = None
                if _xsscheck in k:
                    content = "key"
                elif v and _xsscheck in v:
                    content = "value"

                if content:
                    occurences.append({
                        "type": "attribute",
                        "position": index,
                        "details": {"tagname": tagname, "content": content, "attributes": [(k, v)]},
                    })
        # 如果找到潜在注入点则index+1
        if len(occurences) > origin_length:
            index += 1
    return occurences


test_html_doc = '''
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
<h2>
Hello 
xsscheck
      <footer>
<p>© PentesterLab 2013</p>
</h2>
</footer>
</html></div> <!-- /container -->
</body>
</html>
# html解析器

'''

if __name__ == '__main__':
    occureneces = searchInputInResponse(html_doc=test_html_doc, xsscheck='xsscheck')
    for o in occureneces:
        print('注入点类型:' + o['type'])
        print('注入点index:' + str(o['position']))
        print('注入点详细信息:')
        print('标签名:' + o['details']['tagname'], end='')
        print('\t标签属性:' + str(o['details']['attributes']), end='')
        print('\t标签内容:' + o['details']['content'].strip('\n'), end='')

