from pwn import *
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor


key = 'fakekey'
print('abc {}'.format("flag"))
# exit(0)

# error leak: AES CBC
# Traceback (most recent call last):
#   File "/app/run", line 89, in <module>
#   File "/app/run", line 76, in main
#     cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
#              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#   File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/AES.py", line 228, in new
#     return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)
#            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#   File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/__init__.py", line 79, in _create_cipher
#     return modes[mode](factory, **kwargs)
#            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#   File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/_mode_cbc.py", line 287, in _create_cbc_cipher
#     raise ValueError("Incorrect IV length (it must be %d bytes long)" %
# ValueError: Incorrect IV length (it must be 16 bytes long)

test_fmt = b'{}'



def get_flag(fmt, iv):
    conn = remote('ctf.ritsec.club', 30148)
    
    conn.sendlineafter(b'Option >', b'1')
    conn.sendlineafter(b' > \n', fmt)
    resp = conn.recvline(keepends=False)

    if b'That format caused an error!' in resp:
        print(resp)
        raise ValueError(resp, fmt)
    
    conn.sendlineafter(b'Option >', b'2')
    conn.sendlineafter(b' >', iv.hex().encode())

    conn.sendlineafter(b'Option >', b'3')
    conn.recvuntil(b'Here is your flag, encoded as desired for your receiving server: ')

    conn.close()

    flag_b = bytes.fromhex(conn.recvline(keepends=False).decode())

    return flag_b

context.log_level = 'warning'

known_flag = b'RS{0n3_Ch4r4cT3R_@t_4_t1Me}'
bench = get_flag(b"\0" * 0x10 + b'{}', iv = b'\0' * 0x10)
print(bench)
for i_leak in range(len(known_flag), 0x10):
    ''
    for test_char_ord in range(0x20, 0x7f):
        test_char = chr(test_char_ord)
        # if test_char in '{}\\':
        #     test_char = test_char * 2
        fmt = b'\0' * (0x10 - 1 - i_leak) + b'{}'
        iv = b'\0' * (0x10 - 1 - i_leak) + known_flag + test_char.encode()
        res = get_flag(fmt, iv)

        print(i_leak, test_char)
        if res[:0x10] == bench[:0x10]:
            known_flag += test_char.encode()
            print(known_flag)
            break

print(known_flag)

for i_leak in range(len(known_flag) - 0x10, 0x10):

    fmt = b'\0' * (0x10 - i_leak - 1) + b'{}'
    iv = random.randbytes(16)
    res = get_flag(fmt, iv)
    
    for test_char_ord in range(0x20, 0x7f):
    # for test_char_ord in range(0x0, 0x10):
        test_char = chr(test_char_ord)
    # for test_char in '}O':

        iv1 = res[:0x10]
        p2 = known_flag[i_leak + 1:] + test_char.encode()
        assert len(p2) == 0x10

        check_iv = strxor(iv1, p2)
        res2 = get_flag(b'\0' * 0x20 + b'{}', check_iv)

        print(i_leak, test_char)
        if res2[:0x10] == res[0x10:0x20]:
            known_flag += test_char.encode()
            print(known_flag)
            break
    
    if known_flag[-1] == b'}':
        break

print(known_flag)