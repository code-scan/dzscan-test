#!/usr/bin/env python
# -*- coding:utf-8 -*-

from gevent import monkey; monkey.patch_all()
from string import strip
from urlparse import urljoin
from Queue import Queue, Empty

import datetime
import json, gevent
import re, sys, time
import argparse, requests
from dzextend import dzextend

USAGE = './dzscan.py [options]'


def parseCmd():
    """
    @cmdline parser
    """

    parser = argparse.ArgumentParser(usage=USAGE, formatter_class=argparse.RawTextHelpFormatter, add_help=False)

    parser.add_argument('-u', '--url', dest='url',
                        help='The Discuz! URL/domain to scan.')

    parser.add_argument('--gevent', dest='gevent', metavar='<number of gevent>',
                        help='The number of gevents to use when multi-requests')

    parser.add_argument('-f', '--force', dest='force', action='store_true', default=False,
                        help='Forces DzScan to not check if the remote site is running Discuz!')

    parser.add_argument('-h', '--help', action='help', 
                        help='Show help message and exit.')

    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False, help='Show verbose message during scaning')

    parser.add_argument('--update', dest='update', action='store_true', default=False,
                        help='Update database to the latests version.')

    parser.add_argument('--log', dest='log', action='store_true', default=False,
                        help='Record scan output in .log file')
    parser.add_argument('--founder',dest='founder', action='store_true', default=False,
                        help='crack founder password')
    parser.add_argument('--dic',dest='dict',
                        help='crack founder password dict')

    args = parser.parse_args()
    return args.__dict__


def banner():
    """
    @dzscan banner
    """
    str = """_______________________________________________________________

    ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║  ██║  ███╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ██║  ██║ ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    Dizscan! Security Scanner by the DzScan Team
    Version 0.2
    http://dzscan.org wyc@Dzscan
_______________________________________________________________
    """
    print str


class DzscanBase():

    def __init__(self, argsDic):
        self.plugin_pages = 3
        self.addonTol = set()
        self.url = argsDic['url'] or 'http://www.discuz.net'
        self.addon_path = '%s?id=' % urljoin(self.url, '/plugin.php')
        self.queue = Queue()
        self.gevents = int(argsDic['gevent']) if argsDic['gevent'] else 10
        self.pool = []
        self.ctn = True
        self.verbose = argsDic['verbose']
        self.reqs = 0
        self.plugin_result=''
        self.outs = 0
        self.scan_count=0
        self.log = argsDic['log']
        self.count=len(open('adds.txt').read().split("\n"))
        self.passdic=argsDic['dict'] or 'pass.dic'
        self.quepass=Queue()
        self.founder=argsDic['founder'] or False
        self.dzext=dzextend()
        self.found_result=False
    def update(self):
        print '[i] Updateing Database ...'
        fetch_url = 'http://addon.discuz.com/index.php?view=plugins&f_order=create&page=%s'
        pattern = re.compile(r'<img src="resource/plugin/(.*)"')

        for page in xrange(1, self.plugin_pages + 1):
            req = requests.get(fetch_url % page)
            self.reqs += 1
            addons = pattern.findall(req.content)

            for addon in addons:
                self.addonTol.add((addon.split('.png?')[0],
                    addon.split('alt="')[1].decode('gbk').encode('utf8')))
            print 'page %s' % page

        with open('adds.txt', 'w') as fp:
            for add in self.addonTol:
                fp.write('%s, %s\n' % add)
    def fetch_index_plugin(self):
        print "\n[+] Found Plugin of index page ...\n"
        dzext=dzextend()
        inedxplugin=dzext.GetIndexPlugin(self.url)
        for i in inedxplugin:
            print "[!] Found Plugin ['%s']"%i
    def fetch_admin(self):
        print "[+] Enumerating Admin from passive detection ...\n"
        dzext=dzextend()
        respone=dzext.GetAdminId(self.url)
        for i in respone:
            print "[!] Found Admin ['%s']"%i
    def fetch_version(self):
        robots_path = urljoin(self.url, '/robots.txt')
        req = requests.get(robots_path)
        self.reqs += 1
        if req.status_code == 200:
            print '[!] The Discuz! \'%s\' file exists .\n' % robots_path
            try:
                ver = req.content.split('#')[2].split(' for ')[1]
                print '[+] Discuz! version \'%s\' .\n\n' % strip(ver)
            except IndexError:
                print '[!] But seems no version revealed'

        robots_path = urljoin(self.url, '/source/plugin/tools/tools.php')
        req = requests.get(robots_path)
        self.reqs += 1
        if req.status_code == 200:
            print '[!] The Discuz! \'%s\' file exists.\n' % robots_path       

        #/utility/convert/index.php?a=config&source=d7.2_x2.0 
        robots_path = urljoin(self.url, '/utility/convert/index.php?a=config&source=d7.2_x2.0')
        req = requests.get(robots_path)
        self.reqs += 1
        if req.status_code == 200:
            print '[!] The Discuz! \'%s\' file exists.\n' % robots_path   

        #develop.php
        robots_path = urljoin(self.url, '/develop.php')
        req = requests.get(robots_path)
        self.reqs += 1
        if req.status_code == 200:
            print '[!] The Discuz! \'%s\' file exists.\n' % robots_path  

    def stdout(self, name):
        scanow ='[*] Scan %d of %d and found %d , Please wait..'%(self.reqs,self.count,len(self.plugin_result.split("\n")))
        sys.stdout.write(str(scanow)+" "*20+"\b\b\r")
        sys.stdout.flush()
        

    
    def fetch_addons(self):

        while self.ctn:
            try:
                addon_name = self.queue.get_nowait()               
                self.stdout(addon_name)
                self.exist_examine(addon_name)
                self.scan_count += 1
            except Empty:
                self.ctn = False

    def init_passdic(self):
        pass_=open(self.passdic).read()
        pass_=pass_.replace("\r","").split("\n")
        pass_=set(pass_)
        self.count=len(pass_)
        for p in pass_:
            self.quepass.put(p)
    def run_fetch_founder(self):
        while self.ctn:
            try:
                self.fetch_founder()
            except Empty:
                self.ctn=False

    def fetch_founder(self):
        self.plugin_result=''
        try:
            password=self.quepass.get_nowait()
            path='/uc_server/'
            found=self.dzext.LoginFounder(self.url,password,path)
            self.reqs+=1
            self.stdout(password)
            #print password
            if found!="-1":
                self.found_result=True
                print "[!] Founder Password ['%s']                                                                                                                  "%password
                found=found.split("|")
                #print found
                uckey=found[0]
                host=found[2]
                dbname=found[3]
                dbuname=found[4]
                dbupass=found[5]
                printdata="[!] Uc Key  ['%s']\n[!] DB Host ['%s']\n[!] DB Name ['%s']\n[!] DB User ['%s'] \n[!] DB Pass ['%s']\n"%(uckey,host,dbname,dbuname,dbupass)
                print printdata
                '''
                print "[!] Uc Key  ['%s']                                                                    "%uckey
                print "[!] DB Host ['%s']                                                                   "%host
                print "[!] DB Name ['%s']                                                                   "%dbname
                print "[!] DB User ['%s']                                                                    "%dbuname
                print "[!] DB Pass ['%s']                                                                    "%dbupass
                '''
                exit()
        except Exception as ex:
            print ex
                  
    def init_addon(self):
        self.addonTol = set()
        with open('adds.txt') as fp:
            for line in fp.readlines():
                self.addonTol.add((line.split(',')[0], line.split(',')[1]))
                self.queue.put(line.split(',')[0])

    def execute(self):
        for event in xrange(self.gevents):
            if self.founder:
                self.pool.append(gevent.spawn(self.run_fetch_founder))
            else:
                self.count=len(open('adds.txt').read().split("\n"))
                self.pool.append(gevent.spawn(self.fetch_addons))
        gevent.joinall(self.pool)

    def exist_examine(self, addon_name):
        examine_url = '{}{}'.format(self.addon_path, addon_name)
        if self.verbose:

            print '[*] scan addon \'%s\' for exisitance... ' % addon_name
        try:    
            req = requests.get(examine_url)
            self.reqs += 1
            if 'charset=gbk' in req.content:
                exist = examine(req.content.decode('gbk').encode('utf8'))
            else:
                exist = examine(req.content)

            if exist:

                sucMsg = '\n[!] Find addon \'{}\' : \'{}\' !'.format(addon_name, examine_url)
                self.plugin_result=self.plugin_result+sucMsg
                #print sucMsg
                self.outs += 1
        except Exception as ex:
            print ex


def examine(content):
    if '插件不存在或已关闭' not in content and len(content) > 1000 \
            and 'http://error.www.xiaomi.cn' not in content:
        return True
    return False


def fetch_vul(addon):
    fetch_url = 'http://dzscan.org/index.php/welcome/view?plugin=%s' % addon
    json_data = json.loads(requests.get(fetch_url).content)
    for vul in json_data:
        return "http://dzscan.org/index.php/welcome/view?id=%s" % vul['id']


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    banner()
    cmdArgs = parseCmd()

    base = DzscanBase(cmdArgs)
    # {'url': None, 'force': False, 'gevents': 10, 'update': True, 'verbose': False, 'log': False}

    if cmdArgs['update']:
        base.update()

    elif cmdArgs['url'] == None:
        print "usage: ./dzscan.py --help"

    else:
        base.fetch_version()
        base.fetch_admin()
        base.fetch_index_plugin()
        print "\n[+] Enumerating plugins from passive detection ...\n"
        base.init_addon()
        base.init_passdic()
        base.execute()

    if not base.log:
        pointer = sys.stdout
    else:
        from urlparse import urlsplit
        log_name = urlsplit(base.url)[1].replace('.', '_')
        pointer = open('%s.log' % log_name, 'a')

    pointer.write('[+] %s plugins found.                                                               ' % (base.outs or 'No'))
    pointer.write(base.plugin_result+"\n")
    pointer.write('[+] Finished: %s.\n' % time.ctime())
    pointer.write('[+] Requests Done: %s.\n' % base.reqs)
    sec = (datetime.datetime.now() - start_time).seconds
    pointer.write('[+] Elapsed time: {}:{}:{}.\n'.format(sec / 3600, sec % 3600 / 60, sec % 60))

    pointer.close()
