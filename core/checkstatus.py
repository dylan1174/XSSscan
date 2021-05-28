import threading
import requests
import queue
import sys
import time

class checkStatus(threading.Thread):
    def __init__(self, q, result):
        super().__init__()
        self.q = q
        self.result = result

    def run(self) -> None:
        while not self.q.empty():
            url = self.q.get()
            sys.stdout.write('\r剩余url:' + str(self.q.qsize()))
            if not url.startswith('http'):
                url = 'http://' + url
            try:
                res = requests.get(url=url, timeout=5)
                if res.status_code == 200:
                    self.result.append(url)
            except:
                pass

def check_status(urls):
    thread_count = 100
    threads = []
    result = []
    q = queue.Queue()
    for u in urls:
        q.put(u)

    for i in range(thread_count):
        threads.append(checkStatus(q, result))
    print('开始进行url连通性测试' + time.ctime())
    for t in threads:
        t.start()

    for t in threads:
        t.join()
    print('\nurl连通性测试结束' + time.ctime())
    print('有效url共' + str(len(result)) + '条')
    return result
