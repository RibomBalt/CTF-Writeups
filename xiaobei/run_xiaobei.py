#!/usr/bin/python3
from pwn import *
from sympy import isprime
import random
import re
import time

token = '??:fake-token'

with open('qa.csv','r', encoding='utf-8') as fp:
    raw = fp.read()
qa = dict([item.split(',') for item in raw.split('\n')])

game_gold = lambda level: 300+int(level**1.5)*100

def answer_question(quest:str):
    ''
    match_answer = [qa[k] for k in qa if k in quest][0]
    if match_answer == '$prime':
        a, b = re.findall(r'(\d+) 到 (\d+)', quest)[0]
        match_answer = str(guess_prime(int(a), int(b)))
    elif match_answer == '$mac':
        match_answer = '{0:05d}'.format(random.randint(0,99999))
    elif match_answer == '$level':
        a = re.findall(r'第 (\d+) 级', quest)[0]
        match_answer = str(game_gold(int(a)))
    return match_answer

def guess_prime(a, b):
    ''
    pickable_prime = [p for p in range(a, b+1) if isprime(p)]
    picked = random.sample(pickable_prime, 1)[0]
    print(a,b,pickable_prime,picked)
    return picked

def main():
    # context.log_level='debug'
    con = remote('prob01.geekgame.pku.edu.cn', 10001)
    con.sendline(token.encode())
    con.recvline_startswith('准备好了吗'.encode('utf-8'),timeout=10)
    con.sendline('急急急'.encode('utf-8'))

    right_counter = 7
    for i in range(1,8):
        Question = con.recvline_startswith('第 {0} 题'.format(i).encode('utf-8')).decode('utf-8')
        Answer = answer_question(Question)
        con.sendline(Answer.encode('utf-8'))
        Result = con.recvline_contains('鉴定为'.encode('utf-8')).decode('utf-8')
        if '答案不正确' in Result:
            right_counter -= 1

        print(Answer,Result)

    print('#RA:=',right_counter,sep='')
    while True:
        try:
            l = con.recvline(timeout=10).decode('utf-8')
            if ('欢迎再来' in l) or ('flag{' in l):
                print(l)
        except EOFError:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(10)