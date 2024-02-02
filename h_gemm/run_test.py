import numpy as np

import shutil
import os
import sys
import time

if len(sys.argv) < 2:
    print(f'usage: {sys.argv[0]} {__file__} ICASENUM')
    exit(1)

ICASE = int(sys.argv[1])
shutil.copy(f'conf.data.{ICASE}', 'conf.data')

st = time.time()
os.system('./quick')
dur = time.time() - st
print(f"duration: {dur}")

ans = np.fromfile(f'answer.data.{ICASE}')
out = np.fromfile(f'out.data')

err = np.max(np.abs(ans - out))
print(f'max err {err}')