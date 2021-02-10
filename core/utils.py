from core.config import HEADER, USER_AGENTS, TOP_RISK_GET_PARAMS
import random
import string


# 传入url 返回字典(key:参数名 value:参数值)
def getParams(url):
    params = {}
    data = ''
    if '=' in url:
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
