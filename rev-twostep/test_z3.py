from z3 import *
# 0, 4, l3FT
flag1 = 'l3FT'
# 1, 7
l90 = [0x4808, 0xc40, 0x480c, 0x408c]

flag2 = ''
for l in l90:
    bit = 0
    for i in range(3, -1, -1):
        bit <<= 2
        mask = (3 << ((i << 2) + 2 & 0x1f))
        bit |= (l & mask) >> ((i << 2) + 2 & 0x1f)
    flag2 += chr(bit)
print(flag2)


# 2, 2

local_48 = {}
local_d8 = {}
local_a8 = {}
local_78 = {}

local_48[0] = 0xd4f3
local_48[1] = 0x3d49
local_48[2] = 0x107b
local_48[3] = 0xc479
local_48[4] = 0xaa84
local_48[5] = 0x9807
local_d8[0] = 0x394c
local_d8[1] = 0x5dff
local_d8[2] = 0x91e5
local_d8[3] = 0xc61c
local_d8[4] = 0xf07b
local_a8[0] = 0x1c1f75
local_a8[1] = 0x364d4
local_a8[2] = 0x4f1d2a
local_a8[3] = 0x460a19
local_a8[4] = 0x215405
local_e8 = 0
local_78[0] = 0x4000000a
local_78[1] = 0x90000006
local_78[2] = 0x38000003
local_78[3] = 0x20000001
local_78[4] = 0x6e000000

flag3 = ''
for i in range(5):
    c = local_a8[i] - local_48[i]
    assert c % local_48[i + 1] == 0
    c //= local_48[i + 1]
    flag3 += chr(c)
print(flag3)

# 3, 0; 4, 3
flag4, flag5 = '', ''

for i in range(4, -1, -1):
    local_e8 = local_d8[i]
    lastturn = local_d8[i - 1] if i > 0 else 0
    thisturn = (local_e8 - lastturn) & 0xffff
    f0, dat = thisturn // 0x80, thisturn % 0x80
    flag4 = chr(dat) + flag4
    flag5 = chr(f0) + flag5

print(flag4, flag5)


# 5, 6
flag6 = ''
for i in range(5):
    q = i + 3
    cip = local_78[i]
    lower = cip & 0xff
    higher = cip >> 4 << 4
    # print(hex(lower), hex(higher))
    c = 0
    c |= lower << q
    c |= higher >> (0x20 - q)

    flag6 += chr(c)
print(flag6)

# 6, 5
3.325947034342098e+151
local_88 = {}
local_88[0] = 0xb1
local_88[1] = 0xa6
local_88[2] = 0xb7
local_88[3] = 0xb6
local_88[4] = 0xb1
local_88[5] = 0xad

for guess_c in range(256):
    print([chr(c ^ 0xc3) for i,c in local_88.items()])