import os, signal, time
os.system('fuser -k 5002/tcp 2>/dev/null')
time.sleep(1)
