import numpy as np

import struct

CASE = [(1024, 1024, 1024), (8192, 8192, 8192)]

for icase, (n1, n2, n3) in enumerate(CASE):
    m1 = np.random.rand(n1, n2).astype(np.double)
    m2 = np.random.rand(n2, n3).astype(np.double)
    m3 = np.matmul(m1, m2)

    with open(f'conf.data.{icase}', 'wb') as fp:
        fp.write(np.array([n1, n2, n3], dtype=np.int64))
        fp.write(m1.tobytes())
        fp.write(m2.tobytes())
    
    with open(f'answer.data.{icase}', 'wb') as fp:
        fp.write(m3.tobytes())