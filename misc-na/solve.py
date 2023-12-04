nswi = int(input())
an = [int(s) for s in input().split(' ')]
onoff = [s == '1' for s in input()]

n_case = int(input())
for i in range(n_case):
    t,l,r = [int(s) for s in input().split(' ')]
    if t == 1:
        for j in range(l, r+1):
            onoff[j - 1] = not onoff[j - 1]
        # print(onoff)
    else:
        ok_switch = [an[j - 1] for j in range(l, r+1) if onoff[j - 1]]
        if ok_switch:
            print(min(ok_switch))
        else:
            print(0)