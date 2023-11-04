import re
import json
from time import sleep
with open('asciinema_rec/asciinema_restore.rec', 'r') as fp:
    all_lines = fp.read().strip().split('\n')

all_line_json = [json.loads(l) for l in all_lines]
# ignore first line

metadata, record = all_line_json[0], all_line_json[1:]

assert all([s[1] == 'o' for s in record])

record_cmd = [s[2] for s in record]

SHA256SUM = '6bbbb91b7adc465fa086ec4ad453bca38beef9967800bf24d046a27b8cb70042'
segment = "\r\u001b[K \u001b[KESC\b\b\bESC\u001b[K[\b[\u001b[K6\b6\u001b[K~\b~\r\u001b[K"
CONTENT_START = 37
CONTENT_END = 1883

LESS_TRAIL = '\r\n:\u001b[K'

content_cmd = record_cmd[CONTENT_START:CONTENT_END]

segment_index = [i for i, s in enumerate(content_cmd) if '\b' not in s]
# print(segment_index)
# check others?

# print(content_cmd[8].__repr__())
# print(content_cmd[9].__repr__())

full_output = ''.join(content_cmd).strip().split('\r\n')

control_l = []
js_l = []

for i,l in enumerate(full_output):
    if '\x1b[7m(END)' in l:
        # final line
        control_l += [l]
        break

    if '\x1b' in l:
        # control line also contain contents after
        assert l.startswith(':\x1b') or l.startswith('\x1b')
        needle = '\x1b[K'
        trail_content_index = l.rindex(needle) + len(needle)

        js_l += [l[trail_content_index:]]
        control_l += [f"{i:05d} " + l[:trail_content_index]]
    else:
        js_l += [l]



with open('asciinema_rec/main.js','w') as fp:
    fp.write('\n'.join(js_l))
with open('asciinema_rec/control.txt','w') as fp:
    fp.write('\n'.join(control_l))

# result_js = []
# for i in segment_index:
#     # sleep(.2)
#     content_l = content_cmd[i].split('\r\n')
#     assert all(['\x1b' not in s for s in content_l[:-1]])
#     if '\x1b' in content_l[-1]:
#         content_l = content_l[:-1]
        

#     result_js += content_l

# with open('asciinema_rec/main.js','w') as fp:
#     fp.write('\n'.join(result_js))

