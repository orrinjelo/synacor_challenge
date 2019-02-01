import os
import io
import sys
import numpy as np
import logging
import re
from collections import deque

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')))

log = logging.getLogger()


class Assembler(object):
    '''
    Assembles into the Synacor VM code
    '''
    def __init__(self, input_f, output_f):

        self.ops = {
            'halt': 0,
            'set':  1,
            'push': 2,
            'pop':  3,
            'eq':   4,
            'gt':   5,
            'jmp':  6,
            'jt':   7,
            'jf':   8,
            'add':  9,
            'mult': 10,
            'mod':  11,
            'andb': 12,
            'orb':  13,
            'notb': 14,
            'rmem': 15,
            'wmem': 16,
            'call': 17,
            'ret':  18,
            'out':  19,
            'inp':  20,
            'noop': 21,
        }
          
        self.opargs = {
            0:  0,
            1:  2,
            2:  1,
            3:  1,
            4:  3,
            5:  3,
            6:  1,
            7:  2,
            8:  2,
            9:  3,
            10: 3,
            11: 3,
            12: 3,
            13: 3,
            14: 2,
            15: 2,
            16: 2,
            17: 1,
            18: 0,
            19: 1,
            20: 1,
            21: 0,
        }

        with open(input_f, 'r') as f:
            lines = f.readlines()

        res = self.parse_lines(lines)

        try:
            with open(output_f, 'wb') as f:
                for line in res:
                    f.write(line[0].to_bytes(2, 'little'))
                    if line[1]:
                        for entry in line[1]:
                            f.write(entry.to_bytes(2, 'little'))
        except Exception as e:
            log.error(e)
            log.error(f'Invalid code? {res}')


    def decode_arg(self, r):
        if r[0] == 'R' or r[0] == 'r':
            if 0 <= int(r[1]) <= 7:
                return 32768 + int(r[1])
            else:
                raise Exception(f'Invalid register {r}')
        elif '0x' in r:
            return int(r, 0)
        elif r.isnumeric():
            return int(r)
        elif r.isalpha():
            if len(r) > 1:
                raise Exception(f'Invalid string for parameter: {r}')
            return ord(r)
        else: 
            raise Exception(f'Invalid argument: {r}')

    def parse_line(self, line):
        op = re.findall(r"[\w']+", line)
        try:
            opcode = self.ops[op[0]]
            if len(op) != self.opargs[opcode] + 1:
                  raise Exception('Wrong number of args')

            args = [self.decode_arg(x) for x in op[1:]]

            return opcode, args
        except Exception as e:
            log.error(e)

    def parse_lines(self, lines):
        return [self.parse_line(line) for line in lines]