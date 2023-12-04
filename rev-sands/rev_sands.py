
import pickle
MAP = b'\x2e\x23\x23\x23\x2e\x2e\x2e\x2e\x2e\x23\x2e\x2e\x23\x53\x2e\x23\x23\x2e\x2e\x23\x23\x2e\x53\x23\x2e\x23\x53\x53\x2e\x23\x23\x2e\x2e\x23\x2e\x23\x2e\x2e\x23\x23\x2e\x53\x2e\x23\x2e\x23\x2e\x53\x53\x2e\x2e\x23\x23\x23\x2e\x23\x2e\x53\x2e\x2e\x2e\x2e\x2e\x23\x2e\x23\x2e\x2e\x2e\x53\x23\x23\x2e\x23\x2e\x23\x23\x23\x23\x2e\x2e\x53\x2e\x53\x2e\x23\x2e\x2e\x53\x2e\x2e\x2e\x53\x2e\x2e\x23\x4c\x53\x2e\x2e'

for i in range(0, 100, 10):
    print(MAP[i:i+10].decode())

'''
.###.....#
..#S.##..#
#.S#.#SS.#
#..#.#..##
.S.#.#.SS.
.###.#.S..
...#.#...S
##.#.####.
.S.S.#..S.
..S..#LS..
'''
# # is wall, S is sand, L is target
# sdssds

from pwn import *

# context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
conn =process('./sands')
pid, gdbapi = gdb.attach(pidof(conn)[0], 'b *0x401afa', api=True)


# conn.sendline(b'd'*32)
# MAPS = []
with open('maps.pkl','rb') as fp:
    MAPS = pickle.load(fp)

cmd = ''
buf = ''

cur_row = b'\x00'
cur_col = b'\x00'

for iround in range(0x32):

    for i in range(0, 100, 10):
        print(MAPS[iround % 4][i:i+10].decode())
    
    if not buf:
        buf = input('> ')
    c, buf = buf[0], buf[1:]

    cmd += c
    conn.sendline(c.encode())
    

    gdbapi.continue_and_wait()
    map_res = gdbapi.execute('call puts(0x404080)')
    time.sleep(.02)
    cur_map = conn.recvline(keepends=False)
    # MAPS += [cur_map]

    
    map_res = gdbapi.execute('call write(1, $rsp + 0x10, 1)')
    time.sleep(.02)
    cur_col = conn.recv(1)
    map_res = gdbapi.execute('call write(1, $rsp + 0x14, 1)')
    time.sleep(.02)
    cur_row = conn.recv(1)

    # for i in range(0, 100, 10):
    #     print(cur_map[i:i+10].decode())
    print(cur_row[0], cur_col[0])
    print('==========================')

# with open('maps.pkl','wb') as fp:
#     pickle.dump(MAPS, fp)
print(cmd)
conn.interactive()

'sdsssssassddssddwwwwddwwwwdddssssddsssssssaaaa'