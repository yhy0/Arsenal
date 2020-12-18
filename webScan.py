#!/usr/bin/python
# -*- coding:utf-8 -*-
# @Author : yhy


import argparse
import sys
import signal
import urllib2
import re
from Queue import Queue
import socket
import ipaddress
import threading
import time
import ssl
ssl._create_default_https_context = ssl._create_unverified_context


def quit(signum, frame):
    print 'You choose to stop me.'
    sys.exit()


class Spider(threading.Thread):

    def __init__(self,queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        """
        start()让run()在新线程里面运行。直接调用run()就是在当前线程运行了。
        start()调用_thread的start_new_thread去运行一个bootstrap方法，在里面做一些准备工作后会调用run()
        """
        # 检测80、443端口是否开放
        while not self._queue.empty():
            try:
                ip = self._queue.get_nowait()
            except Queue.Empty as e:
                break
            port_80 = is_port_open(ip, 80)
            port_443 = is_port_open(ip, 443)
            title = None
            url = None
            if port_80:
                url = 'http://%s' % ip
                title = get_title(url)

            if port_443:
                url = 'https://%s' % ip
                title = get_title(url)

            if port_80 or port_443:
                print('[+] url: %s   title: %s' % (url, title))


def parse_args():
    parser = argparse.ArgumentParser(prog='webScan',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description='* A fast vulnerability Scanner. *\n'
                                                 'By yhy (https://github.com/yhy0/Arsenal)',
                                     usage='webScan.py [options]')

    group_target = parser.add_argument_group('Targets', '')
    group_target.add_argument('--host', metavar='HOST', type=str, default='',
                              help='Scan several hosts from command line')
    group_target.add_argument('-v', action='version',
                             version='%(prog)s 1.5 (https://github.com/yhy0/Arsenal)')

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()
    check_args(args)

    return args


def check_args(args):
    if not args.host:
        msg = 'Args missing! One of following args should be specified  \n' \
              '           --host 8.8.8.8 10.11.1.1/24'
        print(msg)
        exit(-1)


# 根据network的值添加A/B/C段
def get_targets(processed_targets, network, q_targets):

    for ip in processed_targets:
        if ip.find('/') > 0:  # 网络本身已经处理过
            continue
        _network = u'%s/%s' % ('.'.join(ip.split('.')[:3]), network)
        if _network in processed_targets:
            continue
        processed_targets.append(_network)

        if network >= 20:
            sub_nets = [ipaddress.IPv4Network(u'%s/%s' % (ip, network), strict=False).hosts()]
        else:
            sub_nets = ipaddress.IPv4Network(u'%s/%s' % (ip, network), strict=False).subnets(new_prefix=22)
        for sub_net in sub_nets:
            if sub_net in processed_targets:
                continue
            if type(sub_net) == ipaddress.IPv4Network:  # add network only
                processed_targets.append(str(sub_net))
            for _ip in sub_net:
                _ip = str(_ip)
                if _ip not in processed_targets:
                    q_targets.put(_ip)


def is_port_open(ip, port):
    open_flag = True
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    tcp_sock.settimeout(3.0)
    try:
        result = tcp_sock.connect_ex((ip, int(port)))
        if result != 0:
            open_flag = False
        tcp_sock.close()

    except socket.error as e:
        open_flag = False
        # print repr(e), ip
        pass

    return open_flag


def get_title(url):
    title = ''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36',
        'Connection': 'close',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    }

    req = urllib2.Request(url, headers=headers)
    urllib2.socket.setdefaulttimeout(10)  # 10 秒钟后超时
    try:
        response = urllib2.urlopen(req)
        html, charset = decode_response_text(response.read(), url)
        title = "".join(re.findall(r"<title.*?>(.+?)</title>", html)).encode(charset)

    except Exception as e:
        print e, url

    return title


def decode_response_text(txt, url):
    for _ in ['UTF-8', 'GBK', 'GB2312', 'iso-8859-1', 'big5']:
        try:
            html = txt.decode(_)
            return html, _
        except Exception as e:
            print('%s   -22-  %s', str(e), url)
            pass
    try:
        return txt.decode('ascii', 'ignore'), 'ascii'
    except Exception as e:
        print('%s   -123-  %s', str(e), url)
        pass
    print txt
    raise Exception('Fail to decode response Text')


if __name__ == '__main__':
    start_time = time.time()
    args = parse_args()
    print('*** webScan v0.1  https://github.com/yhy0/ ***')
    signal.signal(signal.SIGINT, quit)
    signal.signal(signal.SIGTERM, quit)

    threads = []
    thread_count = 10

    hosts = args.host

    network = -1

    if hosts.find('/') > 0:
        hosts, network = hosts.split('/')
        network = int(network)
        if not (8 <= network <= 32):
            print('[ERROR] Network should be an integer between 8 and 32')
            exit(-1)

    try:
        q_targets = Queue()  # targets Queue
        if network == -1:
            q_targets.put(hosts)
        else:
            hosts = hosts.split()
            get_targets(hosts, network, q_targets)

        for i in xrange(thread_count):
            threads.append(Spider(q_targets, ))

        for t in threads:
            t.setDaemon(True)
            t.start()
        for t in threads:
            t.join()

        print('[*] webScan finished in %s s' % (time.time() -start_time))
        # while True:
        #     pass
    except Exception, exc:
        print exc






