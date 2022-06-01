#
# Parses runtime interface traits from substrates' lib.rs and inserts debug prints
#

import constants

lines = []

with open(constants.SUBSTRATE_SOURCE) as f:
  lines = f.readlines()


def trait_name(line):
  line = line.strip()
  return line[10:-2]

def function_name(line):
  line = line.strip()
  pos = line.find('(')
  line2 = line[:pos]
  pos2 = line2.rfind(' ')
  return line2[pos2 + 1:]

def is_one_line_args(line):
  return ')' in line

def args_lines(trait, func, args):

  aa = []
  for arg in args:
    a = arg.strip()
    if a:
      aa.append(a)
  line = ''.join(aa).replace("\n", " ").replace("\t", " ").strip()
  # pos = line.find('->')
  # if pos != -1:
  #   line = line[:pos]
  return args_single_line(trait, func, line)


def sanitize_internal_parentheses(line):
  pos = line.find('->')
  if pos != -1:
    line = line[:pos]
  opened = 0
  out = []
  for c in line:
    if c in '([<':
      opened += 1;
    elif c in ')]>':
      opened -= 1;
    else:
      if opened == 1:
        out.append(c)
  return ''.join(out).replace("\n", " ").replace("\t", " ").strip()



def args_single_line(trait, func, line):
  args = sanitize_internal_parentheses(line)
  args = args.split(',')
  stripped = []
  first = True
  for arg in args:
    s = arg.strip()
    if first:
      first = False
      if s.endswith('self'):
        continue
    if arg:
      a = arg.split(':')[0]
      stripped.append(a.strip())

  stripped.append('resomonoto')
  if stripped:
    return ("\t\t};\n" + '\t\tlog::info!(target: "substrate", "{}::{}: {}", {});\n\t\tresomonoto\n'.format(
      trait, func, 
      ' {:x?}, '.join(stripped) + ' {:x?}',
      ', '.join(stripped)
    ))
  else:
    return ("\t\t};\n" + '\t\tlog::info!(target: "substrate", "{}::{} no_args");\n\t\tresomonoto\n'.format(trait, func))

out_lines = []
capturer = '\t\tlet resomonoto = {\n';


def runtime_interfaces(lines):
  marker = '#[runtime_interface'
  capture = False  # next line contains trait name
  trait = None
  func = None
  func2 = False
  args = []
  ending = None
  for line in lines:
    if func2:
      out_lines.append('\t' + line)
    else:
      out_lines.append(line)
    if trait and line.startswith('}'):
      trait = None
      continue

    if func and not is_one_line_args(line):
      args.append(line)
      continue
    if func and is_one_line_args(line):
      args.append(line)
      ending = args_lines(trait, func, args)
      out_lines.append(capturer)
      args = []
      func = None
      continue

    if trait and line.strip().startswith('fn'):
      func = function_name(line)
      func2 = True
      if is_one_line_args(line):
        out_lines.append(capturer)
        ending = args_single_line(trait, func, line)
        func = None
      else:
        args.append(line)
        continue

    if func2 and line.startswith('\t}') and line.strip() == '}':
      func2 = False
      if ending:
        out_lines[-1] = ending + line;
        ending = None

    if capture:
      capture = False
      trait = trait_name(line)
      continue

    if line.startswith(marker):
      capture = True

runtime_interfaces(lines)

with open(constants.SUBSTRATE_SOURCE_PROCESSED, 'w') as f:
  f.writelines(out_lines)
  f.flush()

print('done')
