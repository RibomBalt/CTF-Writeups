one = 'id(id)//id(id)'
eight = 'len(__name__)'
fourteen = 'len(hex(id(id)))'

def get_const_int(n):
    q14, r14 = n//14, n % 14
    return f'({ "+".join([fourteen for i in range(q14)]) }+{ "+".join([one for i in range(r14)]) })'

def get_str(s):
    ord_list = [get_const_int(ord(c)) for c in s]
    return '('+'+'.join([f"chr({o})" for o in ord_list])+')'

o = (get_const_int(ord('o')))
s = (get_const_int(ord('s')))
os_str = f'chr({o})+chr({s})'
import_os = f'__import__({os_str})'
# print(import_os)
stdout = get_str('/dev/stdout')
test_print = f"getattr(open({stdout},{get_str('w')}),{get_str('write')})({eight})"
print(test_print, len(test_print))