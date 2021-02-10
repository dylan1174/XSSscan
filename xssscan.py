import os
from module.scan import scan

'''
1.读取target文件 把所有目标target压入队列中
2.根据线程数 构造scan实例 传入target队列
3.接受返回的result数组 写入result.json文件中

result中字典的格式
url:
position:query
paramKey:
payload:
Request:
Response:
msg(什么类型的XSS)
'''
if __name__ == '__main__':
    # 读取目标文件
    targets = []
    result = []
    with open(file='targets.txt', mode='r') as f:
        for line in f.readlines():
            targets.append(line.strip('\n'))

    if targets is not None:
        for url in targets:
            result.extend(scan(url))
    else:
        print('没有检测到url')

    count = len(result)
    print('共发现漏洞' + str(count) + '处')
    i = 1
    for r in result:
        print('*********' + str(i) + '*********')
        print('url:' + r['host'])
        print('ParamName:' + r['ParamKey'])
        print('Payload:' + r['Payload'])
        print('message:' + r['msg'])
        i += 1
