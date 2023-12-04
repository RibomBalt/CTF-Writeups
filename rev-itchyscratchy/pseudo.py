name='isaac newton'
# name = [int(s) for s in '29 26 7 7 6 0 10 32 4 3 21 10'.split(' ')]
alpha = 'zvtwrca57n49u2by1jdqo6g0ksxfi8pelmh3'

name_idx = [1 + (alpha.index(s) if s in alpha else -1) for s in name]

enc = [int(s) for s in '902 764 141 454 207 51 532 1013 496 181 562 342'.split(' ')]
# len == 19
# j = i*i + name[i] % len(name) + 1
print(name_idx, enc)

for i in range(1, 13):
    j = (i * i + name_idx[i - 1]) % 12 + 1
    tmp_ij = enc[i - 1] - name_idx[i - 1] * name_idx[j - 1]
    print(i, j, tmp_ij)

# too lazy to z3 :）
resind = {}

resind[11] = 11
resind[12] = 12

resind[5] = 3
resind[3] = 33
resind[8] = 5
resind[1] = 17
resind[7] = 612 // 17
resind[2] = 504 // resind[7]
resind[4] = 384 // resind[12]
resind[6] = 51 // resind[1]
resind[9] = 392 // resind[2]
resind[10]= 85 // resind[8]

print('nbctf{' + ''.join([alpha[resind[i] - 1] for i in range(1, 13)]) + '}')