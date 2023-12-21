from pwn import *
import tarfile
from Crypto.Cipher import ChaCha20
from hashlib import sha256
from itertools import product
import string

def proof(tail, hash, alphabet=string.ascii_letters + string.digits, ndigits=4):
    answer = hash.decode()
    for c in product(*([alphabet] * ndigits)):
        guess = sha256(''.join(c).encode() + tail).hexdigest()
        if guess == answer:
            return ''.join(c)


conn = remote('chall.ctf.0ops.sjtu.cn', 30001)
# conn = remote('127.0.0.1', 10001)

pof = conn.recvline(keepends=False)
print(pof)
if b'sha256' in pof:
    head, hash = pof.split(b' == ')
    tail = head.split(b'+')[1].split(b')')[0]
    pof_res = proof(tail, hash)
    conn.sendlineafter(b'Give me XXXX:', pof_res.encode())

# plan: get a cipher/plain/iv pairs
conn.sendlineafter(b'> ', b'4')
ok_res = conn.recvline_contains(b'OK')
content_res = conn.recvuntil(b'\n1. add', drop=True)
chacha_cipher = bytes.fromhex(content_res.decode())
iv, cipher = chacha_cipher[:8], chacha_cipher[8:]

print(iv.hex())

print(ok_res, len(content_res))

with tarfile.open("a.tar", 'w') as f:
    pass
with open('a.tar','rb') as f:
    orig_atar = f.read()
    
# print('local', len(local_atar))

conn.sendlineafter(b'> ', b'0')
flag_res = conn.recvline_contains(b'OK')
flag_name = flag_res.split(b' ')[1].decode()
print(flag_name)
assert len(flag_name) == 8

os.makedirs(flag_name)
os.unlink('b.tar')
os.system(f'tar cvf b.tar {flag_name}')
with open('b.tar','rb') as f:
    local_atar = f.read()

assert len(local_atar) == len(orig_atar)
assert len(local_atar) == len(cipher)
assert len(iv) == 8

# print('local_atar', local_atar.hex())

# #  test chacha20
# test_key = b'deadbeef'
# test_iv = b'12341234'



forge_cipher = bytearray(cipher)
for i, b in enumerate(forge_cipher):
    forge_cipher[i] = cipher[i] ^ orig_atar[i] ^ local_atar[i]

full_forge = iv + bytes(forge_cipher)

conn.sendlineafter(b'> ', b'2')
# context.log_level = 'debug'
conn.sendlineafter(b'size: ', f'{len(full_forge)}'.encode())
conn.sendlineafter(b'file(hex): ', f'{full_forge.hex()}'.encode())


conn.sendlineafter(b'> ', b'4')
ok_res = conn.recvline_contains(b'OK')
content_res = conn.recvuntil(b'\n1. add', drop=True)
chacha_cipher = bytes.fromhex(content_res.decode())
iv2, cipher2 = chacha_cipher[:8], chacha_cipher[8:]

# upload again get decrypt from error msg

alter_cipher2 = bytes(bytearray([b ^ 0xff for b in cipher2]))
full_alter_cipher2 = iv2 + alter_cipher2
conn.sendlineafter(b'> ', b'2')
conn.sendlineafter(b'size: ', f'{len(full_alter_cipher2)}'.encode())
conn.sendlineafter(b'file(hex): ', f'{full_alter_cipher2.hex()}'.encode())

conn.recvline_contains(b'[Error] not tar')
alter_decrypt = bytes.fromhex(conn.recvuntil(b'\n1. ', drop=True).decode())

alter_demasked = bytes(bytearray([b ^ 0xff for b in alter_decrypt]))

with open('flag.tar', 'wb') as fp:
    fp.write(alter_demasked)

# flag{s0_....___wHat_hApPeneD_w1Th_My_t4rfI1E?_:/}

conn.interactive()