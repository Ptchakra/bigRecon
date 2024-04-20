#!/usr/bin/python3
# coding: utf-8

#import simplejson
import json as simplejson
import subprocess
import warnings
import time
import threading
import queue
import sys


warnings.filterwarnings(action='ignore')

chrome_path = "/usr/lib/chromium/chrome"
#crawlergo_path = "/root/go/bin/crawlergo"
crawlergo_path = "/app/tools/crawlergo"

exitFlag = 0

class myThread (threading.Thread):
    def __init__(self, threadID, name, q):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q
    def run(self):
        print ("start sub_thread：" + self.name)
        process_data(self.threadID,self.name, self.q)
        print ("exit sub_thread：" + self.name)
        
def process_data(id,threadName, q):
    while not exitFlag:
        if q.empty() == False:
            req = q.get()
            print ("%s processing domain %s" % (threadName, req))
            
            target = req
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                "X-Forwarded-For": "127.0.0.1"
            }   
            cmd = [crawlergo_path, "-c", chrome_path,"-t", "10","-f","smart","--fuzz-path", "--output-mode", "json","--ignore-url-keywords", "quit,exit,logout",  "--custom-headers", simplejson.dumps(headers),"--robots-path","--log-level","debug","--push-pool-max", "10", "--push-to-proxy","http://127.0.0.1:7777/",target]
            #cmd = ["./crawlergo", "-c", chrome_path ,"-t", "5","-f","smart","--fuzz-path","--custom-headers",json.dumps(get_random_headers()), "--push-to-proxy", "http://127.0.0.1:7777/", "--push-pool-max", "10","--output-mode", "json" , target]
            rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = rsp.communicate()
            try:
                result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
            except:
                return
        time.sleep(1)


workQueue = queue.Queue(10000)
threads = []
threadID = 1


file = open(sys.argv[1])
for text in file.readlines():
    domain = text.strip('\n')
    workQueue.put(domain)


for num in range(1, 3):
    tName = "thread-" + str(num)
    thread = myThread(threadID, tName, workQueue)
    thread.start()
    threads.append(thread)
    threadID += 1

while not workQueue.empty():
    pass

exitFlag = 1

for t in threads:
    t.join()
print ("exit main thread")
