# import cv2
from PIL import Image
import matplotlib.pyplot as plt
import numpy as np
from itertools import product
from reedsolo import RSCodec, ReedSolomonError


def bytes2binstr(b, n=None):
    s = ''.join(f'{x:08b}' for x in b)
    return s if n is None else s[:n + n // 8 + (0 if n % 8 else -1)]

VERSION = 7
SZ = 45

# TODO: add quiet scan
def savepic(name, arr):
    im = Image.fromarray(arr)
    im.save(name)

# qr_raw = cv2.imread('qr.png')
im = Image.open('./qr.png')
qr_raw = np.array(im)

print(qr_raw.shape, np.unique(qr_raw[:]))
assert np.all(qr_raw[:,:,0] == qr_raw[:,:,1]) and np.all(qr_raw[:,:,0] == qr_raw[:,:,2])

pix, mask = qr_raw[:,:,0], qr_raw[:,:,3]

pix[mask == 0] = 128

# major pixel is 10 x 49
for ix, iy in product(range(0, 490, 10), range(0, 490, 10)):
    pix_chunk = pix[ix:ix+10, iy:iy+10]
    assert np.unique(pix_chunk[:]).shape[0] == 1
    mask_chunk = mask[ix:ix+10, iy:iy+10]
    assert np.unique(mask_chunk[:]).shape[0] == 1

# CODEQRCODE45X45

def reduce_qr(src):
    dst = np.zeros([45, 45], dtype=np.uint8)
    for (ix, iy), _ in np.ndenumerate(dst):
        dst[ix, iy] = src[20 + 10 * ix, 20 + 10 * iy]
    return dst

small_pix = reduce_qr(pix)
small_mask = reduce_qr(mask)

# some known pattern:
LARGE_SQ = np.zeros((7,7), dtype=np.uint8)
LARGE_SQ[1,1:6] = 255
LARGE_SQ[5,1:6] = 255
LARGE_SQ[1:6,1] = 255
LARGE_SQ[1:6,5] = 255

SMALL_SQ = np.zeros((5,5), dtype=np.uint8)
SMALL_SQ[1,1:4] = 255
SMALL_SQ[3,1:4] = 255
SMALL_SQ[1:4,1] = 255
SMALL_SQ[1:4,3] = 255

# len = 33 = 45 - 2*6
DOT = np.array([0,255]*16 + [0], dtype=np.uint8)

LONG_ONE = lambda l: 255 * np.ones((l,), dtype=np.uint8)

version7 = 255 * (1 - np.array([int(c) for c in '000111110010010100'[::-1]], np.uint8))
assert version7.shape[0] == 18
version7 = version7.reshape(3, 6, order='F')

# format
# W=0, B=1
def get_format_seq(group_num):
    ''
    if group_num == 1:
        X, Y = 8, 44, 
        for i in range(8):
            yield X, Y
            Y -= 1
        X, Y = 45 - 7, 8
        for i in range(7):
            yield X, Y
            X += 1
    else:
        X, Y = 0, 8
        for i in range(6):
            yield X, Y
            X += 1
        X += 1
        yield X, Y
        X += 1
        yield X, Y
        Y -= 1
        yield X, Y
        Y -= 2
        for i in range(6):
            yield X, Y
            Y -= 1

format0 = list(get_format_seq(0))
format1 = list(get_format_seq(1))
assert len(format0) == len(format1) == 15
print(format0, format1)
print(np.array([small_pix[i,j] for i, j in format0]))
print(np.array([small_pix[i,j] for i, j in format1]))
actual_format = np.ones((15,), dtype=np.uint8) * 128
actual_format[np.array([small_mask[i,j] for i, j in format0]) == 255] = \
    np.array([small_pix[i,j] for i, j in format0])[np.array([small_mask[i,j] for i, j in format0]) == 255]
actual_format[np.array([small_mask[i,j] for i, j in format1]) == 255] = \
    np.array([small_pix[i,j] for i, j in format1])[np.array([small_mask[i,j] for i, j in format1]) == 255]

# micro qr code symbols (after masking), 10000 1010011011
print(actual_format, ((255 - actual_format)//255)[::-1] ^ np.array([int(c) for c in '101010000010010']))
actual_format_wiki = np.array([int(c) for c in '100001010011011']) ^ np.array([int(c) for c in '101010000010010'])
actual_format_pix = 255 * (1 - actual_format_wiki[::-1])
print(actual_format_pix)

# 10000
ERR_TYPE = 'H' # 10, 
MASK_TYPE = 0

# 
def get_mask_type0(ix, iy):
    # black for True for 1
    if (ix + iy) % 2 == 0:
        return 1
    else:
        return 0



class qr_patch():
    def __init__(self, arr:np.ndarray, pos) -> None:
        self.arr = arr
        self.pos = pos
    
    def patch(self, pix, mask):
        xoff, yoff = self.pos
        xsz, ysz = self.arr.shape
        # all known pixel should have no conflict
        assert np.all((pix [xoff:xoff+xsz, yoff:yoff+ysz] == self.arr) | \
                    (mask[xoff:xoff+xsz, yoff:yoff+ysz] == 0))
        # 
        pix [xoff:xoff+xsz, yoff:yoff+ysz] = self.arr
        mask[xoff:xoff+xsz, yoff:yoff+ysz] = 255
    
    def gen_all_pos(self):
        xoff, yoff = self.pos
        xsz, ysz = self.arr.shape
        for ix in range(xoff, xoff + xsz):
            for iy in range(yoff, yoff + ysz):
                yield ix, iy
    
class qr_index_patch():
    def __init__(self, pix_seq, ind_seq) -> None:
        self.pix = pix_seq
        self.ind = ind_seq

    def patch(self, pix, mask):
        for iarr, (ix, iy) in enumerate(self.ind):
            if mask[ix, iy] == 255:
                assert self.pix[iarr] == pix[ix, iy], f"mismatch, {iarr, ix, iy}"
            else:
                pix[ix, iy] = self.pix[iarr]
                mask[ix, iy] = 255

    def gen_all_pos(self):
        for ix, iy in self.ind:
            yield ix, iy
        
FORMAT_PATCHES = [
    qr_patch(LARGE_SQ, (0,0)),
    qr_patch(LARGE_SQ, (38,0)),
    qr_patch(LARGE_SQ, (0, 38)),
    qr_patch(SMALL_SQ, (20, 4)),
    qr_patch(SMALL_SQ, (4, 20)),
    qr_patch(SMALL_SQ, (20,20)),
    qr_patch(SMALL_SQ, (20,36)),
    qr_patch(SMALL_SQ, (36,20)),
    qr_patch(SMALL_SQ, (36,36)),
    qr_patch(DOT.reshape(1, -1), (6, 6)),
    qr_patch(DOT.reshape(-1, 1), (6, 6)),
    qr_patch(LONG_ONE(8).reshape(1, -1), (7, 0)),
    qr_patch(LONG_ONE(8).reshape(1, -1), (37, 0)),
    qr_patch(LONG_ONE(8).reshape(1, -1), (7, 37)),
    qr_patch(LONG_ONE(8).reshape(-1, 1), (0, 7)),
    qr_patch(LONG_ONE(8).reshape(-1, 1), (0, 37)),
    qr_patch(LONG_ONE(8).reshape(-1, 1), (37, 7)),
    # version
    qr_patch(version7, (34, 0)),
    qr_patch(version7.transpose(), (0, 34)),

    # format
    qr_index_patch(actual_format_pix, format0),
    qr_index_patch(actual_format_pix, format1),
    # single dot format
    qr_patch(np.array([[0]],dtype=np.uint8), (44 - 7, 8)),
]

# test: all format regions
ALL_FORMAT_MASK = np.zeros((45,45), dtype=np.uint8)
for patch in FORMAT_PATCHES:
    for ix, iy in patch.gen_all_pos():
        ALL_FORMAT_MASK[ix, iy] = 255
savepic('format.png', ALL_FORMAT_MASK)

# get data region sequence
def get_visual_seq():
    # from bigendian (right bottom)
    # X is left right, Y is up down (so reversed lol)
    X, Y = 44, 44
    YDIR = -1
    while X >= 0:
        while (Y >= 0) and (Y <= 44):
            for col_off in range(2):
                if ALL_FORMAT_MASK[X, Y] != 255:
                    yield Y, X

                if col_off == 0:
                    X -= 1
                else:
                    X += 1
                    Y += YDIR
        # reset y, and fold
        Y -= YDIR
        YDIR *= -1
        # skip column 6
        X -= 2
        if X == 6:
            X -= 1

ALL_FORMAT_MASK_COLORED = np.zeros([*ALL_FORMAT_MASK.shape, 3], dtype=np.uint8)
ALL_FORMAT_MASK_COLORED[:,:,0] = ALL_FORMAT_MASK
for iseq, (ix, iy) in enumerate(get_visual_seq()):
    ALL_FORMAT_MASK_COLORED[ix, iy, 1] = (iseq * 16) % 256
    ALL_FORMAT_MASK_COLORED[ix, iy, 2] = (128 + iseq * 16) % 256

savepic('format_c.png', ALL_FORMAT_MASK_COLORED)
print('total bytes', len(list(get_visual_seq())) / 8)
# 7H 130 errorcode, 196 blocks in total

PURE_GUESS = 31

pos_seq = list(get_visual_seq())
assert pos_seq[0] == (44,44)
DATA_PATCHES  = []
DATA_PATCHES += [
    qr_patch( (((PURE_GUESS >> 0) & 1) ^ get_mask_type0(44, 44)) * 255 * np.ones((1,1),dtype=np.uint8), (44, 44)),
    qr_patch( (((PURE_GUESS >> 1) & 1) ^ get_mask_type0(*pos_seq[5 * 8 * 1 + 2])) * 255 * np.ones((1,1),dtype=np.uint8), pos_seq[5 * 8 * 1 + 2]),
    qr_patch( (((PURE_GUESS >> 2) & 1) ^ get_mask_type0(*pos_seq[5 * 8 * 2 + 5])) * 255 * np.ones((1,1),dtype=np.uint8), pos_seq[5 * 8 * 2 + 5]),
    qr_patch( (((PURE_GUESS >> 3) & 1) ^ get_mask_type0(*pos_seq[5 * 8 * 3 + 4])) * 255 * np.ones((1,1),dtype=np.uint8), pos_seq[5 * 8 * 3 + 4]),
    qr_patch( (((PURE_GUESS >> 4) & 1) ^ get_mask_type0(*pos_seq[5 * 8 * 4 + 6])) * 255 * np.ones((1,1),dtype=np.uint8), pos_seq[5 * 8 * 4 + 6]),

]
[p.patch(small_pix, small_mask) for p in DATA_PATCHES]


# from here on, 0=white, 1=black, 255=unknown
bit_seq = np.zeros((196 * 8,), dtype=np.uint8)
mask_seq = np.zeros((196 * 8,), dtype=np.uint8)
for iseq, (ix, iy) in enumerate(get_visual_seq()):
    # 1=known, 0=unknown
    mask_seq[iseq] = (small_mask[ix, iy]) // 255
    if mask_seq[iseq]:
        # known
        bit_seq[iseq] = ((255 - small_pix[ix, iy]) // 255) ^ get_mask_type0(ix, iy)
    else:
        bit_seq[iseq] = 255

# # ECI alphabetic?
# FIRST_END = 4 + 9 + 11 * 2 + 6
FIRST_END = 0
for i in range(FIRST_END, 256, 5*8):
    print(bit_seq[i:i+8])


print(bit_seq.shape[0] / 8)


# nBLOCKS = 5!!!
def bit2bytes(bitarray, unknown=0):
    # ignore unknown
    err_pos = np.where(bitarray[bitarray == 255])[0]
    bitarray[bitarray == 255] = unknown
    return eval('0b' + ''.join([str(c) for c in bitarray])), err_pos.shape[0] > 0


nBLOCKS = [13] * 4 + [14]
nERR = [26] * 5
assert sum(nBLOCKS) + sum(nERR) == 196

BLOCKS = [None] * 5
ERRCODE = [None] * 5
ERRPOS = [None] * 5

for i in range(5):
    block_off = 0
    BLOCKS[i] = []
    ERRPOS[i] = []
    for j in range(nBLOCKS[i]):
        bit_off = block_off + 5 * j + i
        if j == 13:
            bit_off = block_off + 5 * j + 0

        bytenum, errpos = bit2bytes(bit_seq[bit_off*8 : (bit_off + 1)*8])
        BLOCKS[i] += [bytenum]
        if errpos:
            ERRPOS[i] += [j]

for i in range(5):
    err_off = sum(nBLOCKS[:])
    ERRCODE[i] = []
    for j in range(nERR[i]):
        bit_off = err_off + j * 5 + i
        bytenum, errpos = bit2bytes(bit_seq[bit_off*8 : (bit_off + 1)*8])
        ERRCODE[i] += [bytenum]
        if errpos:
            ERRPOS[i] += [nBLOCKS[i] + j]


print(BLOCKS)
print(ERRCODE)
corrected_res = {}





for i in range(5):
    try:
        rsc = RSCodec(26)
        dec, errcor, _ = rsc.decode(bytearray(BLOCKS[i] + ERRCODE[i]), erase_pos=ERRPOS[i])
        corrected_res[i] = dec, errcor

        print(i, len(ERRPOS[i]))

    except Exception as e:
        print(f'block {i} failed, {e}, {len(ERRPOS[i])}')

print(corrected_res)

# play with first block
ALPHANUM = '0123456789abcdefghijklmnopqrstuvwxyz $%*+-./:'
assert len(ALPHANUM) == 45

# binstr = bytes2binstr(corrected_res[1])
# pad_st = (4 + 9 - (13 * 8))%11
# for i in range(pad_st, len(binstr), 11):
#     val = eval('0b' + binstr[i:i+11])
#     worda, wordb = ALPHANUM[val // 45], ALPHANUM[val % 45]
#     print(worda, wordb)




for group, (dec, errcor) in corrected_res.items():
    errcor = errcor[-26:]
    for ib, code in enumerate(dec):
        iseq = group + 5 * ib
        if ib == 13:
            iseq = 0 + 5 * ib

        code_bin = bin(code)[2:].rjust(8,'0')
        # print(code_bin, bit_seq[iseq*8 : (iseq + 1)*8], mask_seq[iseq*8 : (iseq + 1)*8])
        for i in range(8):
            known_bit = bit_seq[iseq*8 + i]
            known_bit_mask = mask_seq[iseq*8 + i]
            calc_bit = int(code_bin[i])

            if known_bit_mask:
                assert known_bit == calc_bit, f"{group}, {ib}, {i}"
                assert mask_seq[iseq*8 + i] == small_mask[*pos_seq[iseq*8 + i]] // 255, f"{mask_seq[iseq*8 + i]}, {small_mask[*pos_seq[iseq*8 + i]] // 255}"

        byte_seq = pos_seq[iseq*8 : (iseq + 1)*8]
        pix_seq = (1 - (np.array([int(c) for c in code_bin], dtype=np.uint8) ^ np.array([get_mask_type0(*pos_seq[iseq*8 + i]) for i in range(8)])) ) * 255
        # print(pix_seq, byte_seq)
        DATA_PATCHES += [qr_index_patch(pix_seq, byte_seq)]


    for ib, code in enumerate(errcor):

        iseq = sum(nBLOCKS) + group + 5 * ib

        code_bin = bin(code)[2:].rjust(8,'0')
        # print(code_bin, bit_seq[iseq*8 : (iseq + 1)*8], mask_seq[iseq*8 : (iseq + 1)*8])
        for i in range(8):
            known_bit = bit_seq[iseq*8 + i]
            known_bit_mask = mask_seq[iseq*8 + i]
            calc_bit = int(code_bin[i])

            if known_bit_mask:
                # assert known_bit == calc_bit, f"{group}, {ib}, {i}"
                assert mask_seq[iseq*8 + i] == small_mask[*pos_seq[iseq*8 + i]] // 255, f"{mask_seq[iseq*8 + i]}, {small_mask[*pos_seq[iseq*8 + i]] // 255}"

        byte_seq = pos_seq[iseq*8 : (iseq + 1)*8]
        pix_seq = (1 - (np.array([int(c) for c in code_bin], dtype=np.uint8) ^ np.array([get_mask_type0(*pos_seq[iseq*8 + i]) for i in range(8)])) ) * 255
        # print(pix_seq, byte_seq)
        DATA_PATCHES += [qr_index_patch(pix_seq, byte_seq)]


#  ======== just testing manually decode =======

# data_flow = b''.join([bytes(corrected_res[i][0]) for i in range(1, 5)])

# bin_flow = bytes2binstr(data_flow)

# remn_num = 6
# FIRST_SET = 4 + 9 + (0b11000 >> 1) * 11 + remn_num - 13 * 8

# first_remn = bin_flow[(FIRST_SET - remn_num) % 11 :  FIRST_SET]
# for i in range(0, len(first_remn), 11):
#     if len(first_remn) - i > 10:
#         val = eval('0b' + first_remn[i:i+11])
#         word_a, word_b = ALPHANUM[val // 45], ALPHANUM[val % 45]
#         print(word_a, word_b, sep='', end='')
#     else:
#         # assert len(first_remn[i:]) == 6
#         val = eval('0b' + first_remn[i:i+6])
#         word_a = ALPHANUM[val]
#         print(word_a, sep='', end='')

# print('')

# print(bin_flow[FIRST_SET:])

# ==================


# apply mask
KNOWN_PATCHES = FORMAT_PATCHES + DATA_PATCHES

[p.patch(small_pix, small_mask) for p in KNOWN_PATCHES]



larger_pix = np.zeros((49, 49), dtype=np.uint8) + 255
larger_pix[2:-2, 2:-2] = small_pix

savepic('pix.png', larger_pix)
savepic('mask.png', small_mask)

# print(small_pix)