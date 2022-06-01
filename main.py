#!/usr/bin/env python3


from asyncore import write
import re
import time

import constants
import postprocessor as pp

start_time = time.time()

def load(name):
    with open(name, 'r', encoding='UTF8') as f:
        return f.readlines()

def write_lines(filename, lines):
    with open(filename, 'w') as f:
        f.write('\n'.join(lines))
        f.flush()

def substrate_log():
    return load(constants.SUBSTRATE_RAW)

def kagome_log():
    return load(constants.KAGOME_RAW)

def tracer_log():
    return load(constants.TRACER)


def substrate_filter(method):
    if method.startswith('Default'):
        method = method[7:]
    return method

def kagome_filter(method):
    if 'ext_' in method:
        method = method[:-10]
    method = method.replace('ext_default_child_storage_', '')
    method = method.replace('ext_storage_', '')
    method = method.replace('ext_hashing_', '')
    return method

def get_quoted(line):
    pos = line.find("'") + 1
    line = line[pos:]
    pos = line.find("'")
    return line[:pos]




def substrate_methods():
    lines = substrate_log()
    # methods = set()
    methods = {}

    rex = re.compile(r" ([a-zA-Z0-9_]+::[a-zA-Z0-9_]+): ")
    for line in lines:
        found = rex.search(line)
        if found:
            raw_method = found.group(1)
            method = substrate_filter(raw_method)
            if method not in methods:
                methods[method] = 1
            else:
                methods[method] += 1
            # methods.add(substrate_filter(method))

    print('Substrate:')
    # methods = list(methods)
    # methods.sort()
    # for method in methods:
    #     print(method)
    for k, v in methods.items():
        print("{} : {}".format(k, v))

# def condense_rust_args(line):
    # only replaces ', ' to ''
    # rex = re.compile(r', (?=[^[\]]*\])')
    # res = rex.sub('', line).strip()
    # print(res)
    # exit(2)
    # return res

def condense_rust_args(line):
    out = []
    pieces = line.split('[')
    first = True
    many = len(pieces) > 1
    for piece in pieces:
        if first:
            first = False
            out.extend(piece)
            if many:
                out.append('[')
            continue
        parts = piece.split(']')
        digits = parts[0].split(', ')
        for digit in digits:
            if len(digit) == 1:
                out.append('0')
            out.append(digit)
        out.append(']')
        out.extend(parts[1])
        out.append('[')
    return ''.join(out)[:-1]



def process_substrate():
    lines = substrate_log()
    processed = []

    rex = re.compile(r" ([a-zA-Z0-9_]+::[a-zA-Z0-9_]+): ")
    skip = 2
    for line in lines:
        found = rex.search(line)
        if found:
            if skip > 0:
                skip -= 1
                continue
            line = line.replace('resomonoto', 'ret')
            raw_method = found.group(1)
            method = substrate_filter(raw_method)
            processed.append(method)

            pos = line.find(': ') + 2
            args = line[pos:]
            args = condense_rust_args(args).split(', ')
            for arg in args:
                if 'ret' in arg:
                    if 'Some' in arg:
                        arg = arg.replace('Some', '')
                    arg = arg.replace('(', '')
                    arg = arg.replace(')', '')
                arg = arg.replace('[', '')
                arg = arg.replace(']', '')
                processed.append(arg.strip())
        # if len(processed) > 1000:
        #     break
    write_lines(constants.SUBSTRATE_PROCESSED, processed)


def kagome_methods():
    lines = kagome_log()
    # methods = set()
    methods = {}

    for line in lines:
        line = line.strip()
        if line:
            if line.endswith('FIN'):
                continue
            method = None
            if 'StorageExtTracer' in line:
                method = 'Storage::{}'.format(get_quoted(line))
            if 'ChildStorageTracer' in line:
                method = 'ChildStorage::{}'.format(get_quoted(line))
            if 'CryptoExtension' in line:
                method = 'Hashing::{}'.format(get_quoted(line))
            if method:
                method = kagome_filter(method)
                if method not in methods:
                    methods[method] = 1
                else:
                    methods[method] += 1
                # methods.add(kagome_filter(method))

    print('Kagome:')
    # methods = list(methods)
    # methods.sort()
    # for method in methods:
    #     print(method)
    for k, v in methods.items():
        print("{} : {}".format(k, v))



def kagome_argument_name(method, index):
    names = {
        'Storage::get': ['key'],
        'Storage::set': ['key', 'value'],
        'Storage::clear': ['key'],
        'Storage::clear_prefix': ['prefix', 'limit'],
        'Storage::exists': ['key'],
        'Storage::append': ['key', 'value'],
        'Storage::next_key': ['key'],
        'Storage::start_transaction': [],
        'Storage::commit_transaction': [],
        'Storage::root': [],
        'Storage::clearPrefix': ['prefix', 'limit'],
        'ChildStorage::get': ['storage_key', 'key'],
        'ChildStorage::next_key': ['storage_key', 'key', '>>encoded'],
        'ChildStorage::clear': ['storage_key', 'key'],
        'Hashing::twox_64': ['data'],
        'Hashing::twox_128': ['data'],
    }
    if method in names:
        try:
            return names[method][index]
        except:
            print(method, index)
    else:
        return ''


def process_kagome():
    lines = kagome_log()
    # lines = tracer_log()
    processed = []

    for line in lines:
        line = line.strip()
        if line:
            if line.endswith('FIN'):
                continue
            method = None
            if 'StorageExtTracer' in line:
                method = 'Storage::{}'.format(get_quoted(line))
            if 'ChildStorageTracer' in line:
                method = 'ChildStorage::{}'.format(get_quoted(line))
            if 'CryptoExtensionT' in line:
                method = 'Hashing::{}'.format(get_quoted(line))
            if method:
                method = kagome_filter(method)
                processed.append(method)

                line = line.replace(', -> ret:', ' -> ret')
                ret_pos = line.find('-> ret')
                shift = len(line)
                ret = None
                if ret_pos != -1:
                    shift = ret_pos
                    ret = line[ret_pos + 3:]
                args = line[:shift].strip()
                has_args = 'args:' in args
                if has_args:
                    args_pos = args.find(', args:')
                    args = args[args_pos + 8:]
                    args = args.split(', ')
                    new_args = []
                    for arg in args:
                        arg = arg.strip()
                        if arg:
                            new_args.append(arg)
                    for idx, val in enumerate(new_args):
                        name = kagome_argument_name(method, idx)
                        if method and method=='Hashing::twox_128':
                            val = val.encode("utf-8").hex()
                        processed.append('{} {}'.format(name, val))
                if ret:
                    processed.append(ret)            
        # if len(processed) > 1000:
        #     break
    processed = remove_encoded(processed)
    write_lines(constants.KAGOME_PROCESSED, processed)



def remove_ret(lines):
    out = []
    for line in lines:
        if line.startswith('ret'):
            out.append('ret removed')
            continue
        out.append(line.strip())
    return out

def remove_encoded(lines):
    out = []
    for line in lines:
        if line.startswith('>>encoded'):
            continue
        out.append(line.strip())
    return out

def kagome_without_ret():
    lines = load(constants.KAGOME_PROCESSED)
    processed = remove_ret(lines)
    wo_encoded = remove_encoded(processed)
    write_lines(constants.KAGOME_WO_RET, wo_encoded)

def substrate_without_ret():
    lines = load(constants.SUBSTRATE_PROCESSED)
    processed = remove_ret(lines)
    write_lines(constants.SUBSTRATE_WO_RET, processed)

# kagome_methods()

process_substrate()
process_kagome()
# kagome_methods()
pp.post_process_kagome()

pp.shorten_values(constants.KAGOME_PROCESSED)
pp.shorten_values(constants.SUBSTRATE_PROCESSED)

kagome_without_ret()
substrate_without_ret()


print("--- %s seconds ---" % (time.time() - start_time))
