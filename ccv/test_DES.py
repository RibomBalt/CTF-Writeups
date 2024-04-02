# https://en.wikipedia.org/wiki/Data_Encryption_Standard
# https://medium.com/@ruimin.yangnl/payment-101-series-card-verification-code-cvc-card-verification-value-cvv-explained-5f7205ae2b67
from Crypto.Cipher import DES
from Crypto.Util.strxor import strxor

key1 = (0xdae55498c4325458).to_bytes(8, 'big')
key2 = (0x26fb153885bcb06b).to_bytes(8, 'big')

def get_cvv(pan_date_code:str):
    blocks = pan_date_code.ljust(32, '0')
    block1, block2 = bytes.fromhex(blocks[:16]), bytes.fromhex(blocks[16:])

    ciph1 = DES.new(key1, mode=DES.MODE_ECB).encrypt(block1)
    ciph1_xor = strxor(block2, ciph1)
    ciph2 = DES.new(key1, mode=DES.MODE_ECB).encrypt(ciph1_xor)
    ciph2_d = DES.new(key2, mode=DES.MODE_ECB).decrypt(ciph2)
    ciph3 = DES.new(key1, mode=DES.MODE_ECB).encrypt(ciph2_d)

    ciph_hex = ciph3.hex()
    ciph_digits = [int(d) for d in ciph_hex if d in "0123456789"]
    ciph_alpha = [int(d, 16) - 10 for d in ciph_hex if d in "abcdef"]

    cvv = ''.join([str(d) for d in (ciph_digits + ciph_alpha)[:3]])
    return cvv


assert get_cvv('6685918046180810964563') == '464'
assert get_cvv('9633976379633402440675224') == '645'

from pwn import *

# context.log_level = 'debug'
conn = remote('puffer.utctf.live', 8625)

flag = ''
print(flag)
try:
    while True:
        line = conn.recvline_contains(b"PAN: ", timeout=5)
        if line:
            pan, date, code, cvv = re.findall(r'PAN: (\d+), date: (\d+), code: (\d+), cvv: (\d+)', line.decode())[0]
            calc_cvv = get_cvv(pan+date+code)
            # print(calc_cvv, cvv)
            if calc_cvv == cvv:
                conn.sendline(b'1')
                flag += '1'
            else:
                conn.sendline(b'0')
                flag += '0'
            print(f"\r{len(flag)}", end='')
        else:
            break
except EOFError:
    pass

print(flag)

# flag = '001111100111010101110100011001100110110001100001011001110111101101101000011011110111000001100101010111110110111001101111011011100110010101011111011011110110011001011111011101000110100001101111011100110110010101011111011101110110010101110010011001010101111101111001011011110111010101110010011100110101111101101100011011110110110001111101'

flag_bin = int(flag, 2)
print(flag_bin.to_bytes(len(flag) // 8, 'big').replace(b'\x00',b''))