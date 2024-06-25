# flag1: euuuuuu (where e is valid) in round1 1st turn
from pwn import *
import re
import random

token = '??:fake-token'
con = remote('prob03.geekgame.pku.edu.cn', 10003)
con.sendline(token.encode('utf-8'))
con.recvline_contains('Good luck'.encode('utf-8'))

def find_element(m, cb):
    # m is square map always
    # m row j column 0~n+1
    return [(i,j) for i in range(len(m)) for j in range(len(m)) if cb(m[i][j])]

def recv_map(n, timeout=5, first_line=None):
    '''
    return: map, available_step, self, ending
    '''
    map = []
    if first_line is None:
        map.append(con.recvline_contains('###'.encode(),timeout=timeout).decode('utf-8'))
    else:
        map.append(first_line)

    for i in range(n+1):
        map.append(con.recvline(keepends=False).decode('utf-8'))
    raw_available = con.recvline(keepends=False).decode('utf-8')
    available = re.findall(r' ([A-Z]+) R\(', raw_available)[0]
    print(*map, available, sep='\n')
    # ending
    find_E = find_element(map, lambda c: c=='E')
    ending = find_E[0] if find_E else None
    # self
    me = find_element(map, lambda c: c=='@')[0]
    return (map, available, me, ending)

def go_upstair(map, available, n, prefer_move = ''):
    
    for i in range(n):
        move_prior = list(c for c in available if c in prefer_move) + list(c for c in available if c not in prefer_move)
        con.sendline(move_prior[0] + 'U')
        map, available, me, ending = recv_map(len(map)-2)
    return map, available, me, ending

def loop(level):
    'manual'
    map, available, me, ending = recv_map(level[0]-2)
    # if ending:
    curr_z = 0
    prefer = ''
    if me[0] < level[0]/2:
        prefer += 'S'
    else:
        prefer += 'N'
    if me[1] < level[0]/2:
        prefer += 'E'
    else:
        prefer += 'W'

    while True:
        print(me, '=>' ,ending)
        # print(*map, available, sep='\n')
        s = input('')
        if re.findall(r'G(\d+)', s):
            upstair_z = int(re.findall(r'G(\d+)', s)[0])
            map, available, me, ending = go_upstair(map, available, upstair_z, prefer_move=prefer)
            curr_z += upstair_z
            print(curr_z)
            continue
        else:
            con.sendline(s[:-1].encode('utf-8'))
        line = con.recvline(keepends=False).decode('utf-8')
        print(line)
        if 'Congrat' in line:
            return 0
        elif '###' in line:
            first_line = line
        else:
            first_line = None
        map, available, me, ending = recv_map(level[0]-2, first_line=first_line)
        

loop([7, 1, 0])
loop([11, 3, 0])
loop([55, 80, 1])

con.interactive()