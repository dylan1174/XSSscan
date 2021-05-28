from core.config import HEADER, USER_AGENTS, TOP_RISK_GET_PARAMS
from urllib.parse import urlparse
import random
import string
import re


# 传入url 返回字典(key:参数名 value:参数值)
def getParams(url):
    params = {}
    data = ''
    if '=' in url and '?' in url:
        data = url.split('?')[1]
    if not data:
        return params
    else:
        parts = data.split('&')
        for part in parts:
            each = part.split('=')
            # 当存在仅有参数名没有参数值的情况下 value=''
            if len(each) < 2:
                each.append('')
            try:
                params[each[0]] = each[1]
            except IndexError:
                print('url参数解析错误')
                params = None
    return params


def getUrl(url):
    if '?' in url:
        return url.split('?')[0]
    else:
        return url


def getHeader():
    HEADER['User-Agent'] = random.choice(USER_AGENTS)
    return HEADER


# 将文本随机大小写
def random_upper(text):
    length = len(text)
    for i in range(length // 2):
        rand = random.randint(0, length - 1)
        while text[rand].isupper():
            rand = random.randint(0, length - 1)
        temp = text[rand].upper()
        text = text[0:rand] + temp + text[rand + 1:]
    return text


def get_random_str(length=10, chars=string.ascii_lowercase):
    return ''.join(random.sample(chars, length))


def get_complete_url(url, params):
    complete_url = url + '?'
    for k, v in params.items():
        tmp = k + '=' + v
        if k in TOP_RISK_GET_PARAMS and v == '':
            continue
        complete_url = complete_url + tmp + '&'
    if not complete_url.startswith('http'):
        complete_url = 'http://' + complete_url
    return complete_url.strip('&')


# 内置危险的get参数与url提取的params合并
def add_extra_params(params):
    risk_params = TOP_RISK_GET_PARAMS
    for p in risk_params:
        params[p] = ''
    return params


def replace_rewrite_data(part):
    # 纯数字
    int_flag = True
    for ch in part:
        if ord(ch) < 48 or ord(ch) > 57:
            int_flag = False
            break
    if int_flag:
        return "{{data}}"
    # 中文
    for ch in part:
        if '\u4e00' <= ch <= '\u9fff':
            return "{{data}}"
    # 长度超过15
    if len(part) > 15:
        return "{{data}}"
    # 超过4位的连续纯数字
    if re.findall('[0-9]{4,}', part):
        return "{{data}}"
    if '%' in part or '#' in part:
        return "{{data}}"
    return part


def remove_schema(url):
    if url.startswith('https://'):
        return url[8:]
    elif url.startswith('http://'):
        return url[7:]
    else:
        return url


def request_info(url, method, header, body):
    _path = urlparse(url).path
    _schema = urlparse(url).scheme
    _header = header
    _body = body
    s = '{method} {path} {schema}\n {header}'.format(method=method, path=_path, schema=_schema, header=header)
    # dic = {
    #     'method': _method,
    #     'path': _path,
    #     'schema': _schema,
    #     'headers': _header,
    #     'body': _body
    # }
    return s
