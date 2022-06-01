import constants

import hashlib


def post_process_kagome():
    raw_lines = []
    lines = []
    with open(constants.KAGOME_PROCESSED) as f:
        raw_lines = f.readlines()

    method = ''
    for line in raw_lines:
        line = line.strip()
        if line == 'ret 4e4f5f56414c5545':
            lines.append('ret None')
            continue
        if line == 'ret true' or line == 'ret OK':
            lines.append('ret')
            continue
        if line == 'ret void' and method == 'Storage::clear_prefix':
            lines.append('ret AllRemoved0')
            continue
        if line == 'ret 0' and method == 'Storage::exists':
            lines.append('ret false')
            continue
        if line == 'ret 1' and method == 'Storage::exists':
            lines.append('ret true')
            continue
        if line == 'ret: void' and method == 'Storage::start_transaction' or method == 'Storage::commit_transaction':
            lines.append('ret')
            continue
        if '::' in line:
            method = line
        if line.endswith(','):
            if method == 'Storage::set' or method == 'Storage::append':
                lines.append(line[:-1])
                lines.append('value')
            elif method == 'ChildStorage::get':
                lines.append(line[:-1])
                lines.append('key')
            else:
                lines.append(line)
        else:
            lines.append(line)
    
    raw_lines = lines
    lines = []
    skip = False
    for line in raw_lines:
        if '::' in line:
            method = line
        if method == 'Storage::clearPrefix':
            skip = True
        if skip and method != 'Storage::clearPrefix':
            skip = False
        if skip:
            continue
        lines.append(line)


    data = '\n'.join(lines)
    with open(constants.KAGOME_PROCESSED, 'w') as f:
        f.write(data)
        f.flush()


def shorten_values(filename):
    raw_lines = []
    lines = []
    with open(filename, 'r') as f:
        raw_lines = f.readlines()
        for line in raw_lines:
            line = line.strip()
            parts = line.split()

            if len(parts) > 1 and len(parts[1]) > 100:
                hashed = hashlib.sha256(parts[1].encode('utf-8')).hexdigest()
                parts[1] = 'hashed[' + str(hashed) + ']'
            
            line = ' '.join(parts)
            lines.append(line)


    data = '\n'.join(lines)
    with open(filename, 'w') as f:
        f.write(data)
        f.flush()
            


