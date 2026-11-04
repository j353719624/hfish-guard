import time
open('/vol2/1000/workspace/work/unitdiag.txt', 'w').write(
    'unit ran at ' + time.strftime('%H:%M:%S') + '\npython=' + __import__('sys').version)
