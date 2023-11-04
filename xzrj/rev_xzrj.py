import re
from itertools import product

def is_fuyin(c):
    return re.match('[a-zA-Z]', c) and c.lower() not in 'aeiou'


A = 'nymeh1niwemflcir}echaet'
B = 'a3g7}kidgojernoetlsup?h' 
C = 'ulw!f5soadrhwnrsnstnoeq' 
D = 'ct{l-findiehaai{oveatas' 
E = 'ty9kxborszstguyd?!blm-p' 
keymap = [A,B,C,D,E]

ciph = [53, 41, 85, 109, 75, 1, 33, 48, 77, 90,
        17, 118, 36, 25, 13, 89, 90, 3, 63, 25,
        31, 77, 27, 60, 3, 118, 24, 62, 54, 61,
        25, 63, 77, 36, 5, 32, 60, 67, 113, 28]

def get_all_xzrj(s):
    split_locs = [0] + [m.span()[0]+1 for m in re.finditer('[^a-zA-Z]', s)]
    split_words = re.split('[^a-zA-Z]', s)
    
    possible = []
    for i_loc, word in zip(split_locs, split_words):
        if not word:
            continue

        fuyin_list = [(i, c) for i, c in enumerate(word) if is_fuyin(c)]
        possible += [('r', i_loc + i + 1, c.lower()) for i, c in fuyin_list]
        possible += [('r', i_loc + i + 1, c.upper()) for i, c in fuyin_list]
        if is_fuyin(word[-1]):
            possible += [('e', i_loc + len(word), e) for e in 'eE']

    # print(possible)
    return possible

def inverse_xzrj(s:str, p:tuple):
    ptn, ind, c = p
    return s[:ind] + c + s[ind:]



# B: 
# C: ll or ww

for i in [0,1,2,3,4,-1]:
    guess_c = keymap[ciph[i] // 24][ciph[i] % 24]
    print(ciph[i] // 24, ciph[i] % 24, guess_c)

# print(keymap[0],get_all_xzrj(keymap[0]))

# for xzrj in get_all_xzrj(keymap[0]):
#     print(inverse_xzrj(keymap[0], xzrj))

all_possible = [[inverse_xzrj(keymap[i], xzrj) for xzrj in get_all_xzrj(keymap[i])] for i in range(5)]
# print([s for s in  all_possible[1] if s[4]=='}' and s[17] == 'l'])


for i, corr in zip([0,1,2,3,4,-1], 'flag{}'):
    group_id, s_ind = ciph[i] // 24, ciph[i] % 24

    all_possible[group_id] = [d for d in all_possible[group_id] 
                              if corr == d[s_ind]]

# also no } before last one
for i in range(5, len(ciph) - 1):
    group_id, s_ind = ciph[i] // 24, ciph[i] % 24
    all_possible[group_id] = [d for d in all_possible[group_id] 
                              if '}' != d[s_ind]]

# print(all_possible)
print([len(d) for d in all_possible])
# there looks many, they are the same

for possible_comb in product(*all_possible):
    possible_flag = ''.join([''.join(possible_comb)[i] for i in ciph])
    print(possible_flag)