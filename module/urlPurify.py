from urllib.parse import urlparse
from core.config import file_extensions
from core.checkstatus import check_status
from core.utils import getParams, replace_rewrite_data, remove_schema

# 此模块进行url的去重
if __name__ == '__main__':
    targets = []
    url_raw = []
    url_rewrite = []
    # 去除静态资源
    with open('../targets.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()
        print('文件中共有' + str(len(lines)) + '条url')
        for i in lines:
            flag = True
            for extension in file_extensions:
                if extension in i:
                    flag = False
                    continue
            if flag:
                targets.append(i.strip('\n'))

    print('去除静态资源后共有' + str(len(targets)) + '条url')
    # 将重写url与常规url区分开
    for url in targets:
        if '=' in url:
            url_raw.append(url)
        else:
            url_rewrite.append(url)

    # 处理常规url
    # {host:[key,key,key],host:[key,key,key]}
    print('开始处理常规url,共计' + str(len(url_raw)))
    dic = {}
    checked_url = []
    for url in url_raw:
        if not url.startswith('http'):
            url = 'http://' + url
        host = urlparse(url).hostname + urlparse(url).path
        params = getParams(url)
        keys = list(params.keys())
        if host not in dic.keys() and keys:
            dic[host] = keys
            checked_url.append(url)
        elif host not in dic.keys() and len(keys) == 0:
            pass
        else:
            exist_keys = dic[host]
            # 如果url中存在之前没有请求过的参数名 则在去重结果集中加入此url
            if set(keys) > set(exist_keys):
                for key in keys:
                    if key not in exist_keys:
                        exist_keys.append(key)
                        checked_url.append(url)
    print('常规url剩余' + str(len(checked_url)) + '条')

    # 处理重写后的url
    print('开始处理重写url,共计' + str(len(url_rewrite)) + '条')
    checked_rewriteurl = []
    for url in url_rewrite:
        # 处理末尾的文件拓展名 ? .557891
        ext_part = ''
        file_part = url.split('/')[-1]
        if '.' in file_part:
            ext_part = file_part.split('.')[-1]
            # url = url[0:url.rfind('.')]
        # 进行data参数替换
        url = remove_schema(url)
        parts = url.split('/')
        replace_url = parts[0] + '/'
        for part in parts[1:]:
            part = replace_rewrite_data(part)
            replace_url += part + '/'
        replace_url = replace_url[:-1]
        checked_rewriteurl.append(replace_url)
    checked_rewriteurl = list(set(checked_rewriteurl))
    print('重写url剩余' + str(len(checked_rewriteurl)) + '条')
    # 测试去重后的url连通性
    all_url = []
    all_url.extend(checked_url)
    all_url.extend(checked_rewriteurl)
    print('去重后共剩余url' + str(len(all_url)) + '条')
    file_path = 'E:\\purify.txt'
    with open(file_path, 'w') as f:
        for u in all_url:
            f.write(u + '\n')

    purify_url = check_status(all_url)
    file_path = 'E:\\reachable.txt'
    with open(file_path, 'w') as f:
        for u in purify_url:
            f.write(u + '\n')
    print('结果保存在路径' + file_path)
