import requests

r = requests.get('https://raw.githubusercontent.com/torvalds/linux/v4.17/include/uapi/asm-generic/unistd.h').text
lines = r.split('\n')
table = {}
for x in lines:
    if x.startswith('#define') and '_NR' in x:
        y = x.split(' ')
        try:
            num = int(y[-1])
        except:
            continue
        name = '_'.join(y[1].split('_')[3:])
        table[num] = name
print(table)
