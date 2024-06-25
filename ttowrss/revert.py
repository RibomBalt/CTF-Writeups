
# r8
with open('d4020.bin','rb') as f:
    r8 = f.read()
# r9
with open('u20a0.bin','rb') as f:
    r9 = f.read()
# r10
with open('u2040.bin','rb') as f:
    r10 = f.read()

i = 0
while True:
    try:
        rsi = int.from_bytes(r8[i*4:(i+1)*4],byteorder='little')
        edx = int(r9[rsi])
        x = edx ^ rsi
        edx2 = int.from_bytes(r10[x*2:(x+1)*2],byteorder='little')
        print(chr(edx2 & 0x7f),end='')

        i+=1
    except:
        break