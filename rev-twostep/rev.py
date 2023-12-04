from pwn import *
from itertools import product
from string import ascii_uppercase, ascii_lowercase

context.log_level = 'debug'
CORE_LEN = 0x32

flag_frag = {}
flag_frag[4] = 'l3FT'
flag_frag[7] = 'b4cK'
flag_frag[2] = 'r1gh7'
flag_frag[0] = 'L3f7'
flag_frag[3] = 'rIghT'
flag_frag[6] = 'RigH7'
flag_frag[5] = '1n'
flag_frag[1] = 'f0rw4Rd'



short_list = [4,7,2,0,3,6,5,1,8]
short_len =  [4,4,]

ALPHABET = '0123456789' + ascii_uppercase + ascii_lowercase
# ALPHABET = [chr(c) for c in range(0x20, 0x7f) if chr(c) not in ' _']

for idx, i_chunk in enumerate(short_list):
    if idx in [i for i in range(len(flag_frag))]:
        continue


    for guess in product(*[ALPHABET for i in range(2)]):
        # print(guess)
        guess_str = ''.join(guess)
        flag_frag[i_chunk] = guess_str

        known_flag_list = []
        
        for i_frag in range(max(flag_frag) + 1):
            
            if i_frag not in flag_frag:
                known_flag_list += ['a']

            else:
                known_flag_list += [flag_frag[i_frag]]


        flag_core = '_'.join(known_flag_list).ljust(CORE_LEN, '_')
        flag = f'nbctf{{{flag_core}}}'.encode()

        conn = process('./twostep_patch')
        conn.recvuntil(b'> ')
        conn.sendline(flag)
        res = conn.recv(1)
        conn.close()
        
        print('\r', flag, idx, 'res', res[0], end='')

        if res[0] > idx + 1:
            print('correct', flag)
            exit(0)
            break
    exit(1)
# nbctf{L3f7_f0rw4Rd_r1gh7_rIghT_l3FT_1n_RigH7_b4cK_return}