lines = []

with open('/Users/igor/dev/data/kagome-true-raw.log') as f:
    lines = f.readlines()

unique = set()

for line in lines:
    if 'args:' in line and 'ret:' not in line:
        pos = line.find('args:')
        x = line[:pos]
        pos = x.find('call')
        y = x[pos + 4:]
        unique.add(y)
        # print(line)

for e in unique:
    print(e)



