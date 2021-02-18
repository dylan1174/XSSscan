import os
from module.scan import Scan
import queue
import argparse
import json

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
msg
'''
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--thread', help='set thread count', dest='thread_count', default=5)
    parser.add_argument('-f', '--output', help='output file path', dest='output', default='result.json')
    args = parser.parse_args()
    thread_count = args.thread_count

    # 读取目标文件
    targets = []
    result = []
    q = queue.Queue()
    with open(file='targets.txt', mode='r') as f:
        for line in f.readlines():
            targets.append(line.strip('\n'))

    if targets is not None:
        for url in targets:
            q.put(url)
    else:
        print('没有检测到url')

    threads = []
    for i in range(thread_count):
        threads.append(Scan(q=q, result=result))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    count = len(result)
    print('共发现漏洞' + str(count) + '处')
    json_data = json.dumps(result, indent=4, ensure_ascii=False)

    root_path = os.getcwd()
    result_path = root_path + '\\' + args.output
    with open(result_path, 'w', encoding='utf-8') as f:
        f.write(json_data)

    i = 1
    for r in result:
        print('*********' + str(i) + '*********')
        print('url:' + r['host'])
        print('ParamName:' + r['ParamKey'])
        print('Payload:' + r['Payload'])
        print('message:' + r['msg'])
        i += 1
