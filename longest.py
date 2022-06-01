lines = []
with open('substrate.log') as f:
    lines = f.readlines()

max_len = 0
for l in lines:
    len_line = len(l)
    if len_line > max_len:
        max_len = len_line

print(max_len)
