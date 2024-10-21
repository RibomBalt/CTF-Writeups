import re
from pwn import *

with open('sunshine.log', 'r') as fp:
    RAW_LOG = fp.read()


def get_keyboard_packets(logs:str):
    ST_TAG = '--begin keyboard packet--'
    ED_TAG = '--end keyboard packet--'

    key_packets = []
    while logs:
        try:
            st_ind, ed_ind = logs.index(ST_TAG), logs.index(ED_TAG)
            key_body, logs = logs[st_ind + len(ST_TAG):ed_ind], logs[ed_ind + len(ED_TAG):]
            new_key_obj = {}
            for l in key_body.strip().split('\n'):
                key_match = re.match("^([A-Za-z0-9]+?) \\[([0-9A-F]+?)\\]", l)
                if key_match:
                    new_key_obj[key_match.group(1)] = key_match.group(2)
                else:
                    raise AttributeError('not recognized key')

            key_packets += [new_key_obj]

        except ValueError:
            break
    
    return key_packets

def key_code_parse(code):
    '''
    https://github.com/LizardByte/Sunshine/blob/25ed2d5b4a5bde402bc573b5dd1c8479757a9735/src/platform/macos/input.cpp#L47
    '''
    code = code & 0xff
    if 0x30 <= code <= 0x39:
        return str(code - 0x30)

    elif 0x41 <= code <= 0x5a:
        return chr(ord('A') + code - 0x41)
    
    elif code == 0x20:
        return ' '
    
    elif 0x70 <= code <= 0x87:
        return f"F{code - 0x6f}"
    
    elif code == 0xd:
        return 'ret'
    
    elif code == 0xa0:
        return 'lshift'
    elif code == 0xa1:
        return 'rshift'
    elif code == 0xbc:
        return ','
    elif code == 0xbf:
        return '\\'
    
    elif code == 0xdd:
        return ']'
    elif code == 0xdb:
        return '['

    else:
        return hex(code)


key_objs = get_keyboard_packets(RAW_LOG)
print(key_objs)

assert all([int(kobj['keyAction']) in (3, 4) for i, kobj in enumerate(key_objs)])
assert all([int(kobj['flags']) in (0,) for i, kobj in enumerate(key_objs)])
assert all([int(kobj['keyCode'], 16) & 0xff00 == 0x8000 for i, kobj in enumerate(key_objs)])
print(set([int(kobj['modifiers']) for i, kobj in enumerate(key_objs)]))

key_mapping = [(key_code_parse(int(kobj['keyCode'], 16) & 0xff), int(kobj['keyAction']), int(kobj['modifiers'])) for i, kobj in enumerate(key_objs)]

key_all_press = [k for k, press, _ in key_mapping if press == 3]

for key in key_mapping:
    print(key)
print(key_all_press)
print(''.join(key_all_press).lower())

# flaglshift[onlyapplecandolshift]
# flag{onlyapplecando}