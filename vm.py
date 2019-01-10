#!/usr/bin/env python3
import os
import io
import sys
import numpy as np
from argparse import ArgumentParser
import logging
from signal import signal, SIGINT
import getch
from utils.spiffyText import spiff
import re
from collections import deque

log = logging.getLogger()


class VirtualMachine(object):
    '''
    == architecture ==
    - three storage regions
      - memory with 15-bit address space storing 16-bit values
      - eight registers
      - an unbounded stack which holds individual 16-bit values
    - all numbers are unsigned integers 0..32767 (15-bit)
    - all math is modulo 32768; 32758 + 15 => 5


    == binary format ==
    - each number is stored as a 16-bit little-endian pair (low byte, high byte)
    - numbers 0..32767 mean a literal value
    - numbers 32768..32775 instead mean registers 0..7
    - numbers 32776..65535 are invalid
    - programs are loaded into memory starting at address 0
    - address 0 is the first 16-bit value, address 1 is the second 16-bit value, etc

    == execution ==
    - After an operation is executed, the next instruction to read is immediately 
       after the last argument of the current operation.  If a jump was performed,
       the next operation is instead the exact destination of the jump.
    - Encountering a register as an operation argument should be taken as reading
       from the register or setting into the register as appropriate.    
    '''
    def __init__(self, state_file=None, memsize=65536, n_registers=8):
        '''
        Args:
            state_file: file path to a saved state
            memsize: size of mem (defaults to 66536)
            n_registers: number of registers (defaults to 8)
        '''
        if state_file is None:
            self.__memory = np.zeros((memsize,), dtype=np.uint16)
            self.__registers = np.zeros((n_registers,), dtype=np.uint16)
            self.__stack = deque([])

            self.__pc = 0   # Program Counter

            self._running = False

            self.__buffer = ''
        else:
            self.load_state(state_file)

        self.opcodes = {
            0:  self.halt,
            1:  self.set,
            2:  self.push,
            3:  self.pop,
            4:  self.eq,
            5:  self.gt,
            6:  self.jmp,
            7:  self.jt,
            8:  self.jf,
            9:  self.add,
            10: self.mult,
            11: self.mod,
            12: self.andb,
            13: self.orb,
            14: self.notb,
            15: self.rmem,
            16: self.wmem,
            17: self.call,
            18: self.ret,
            19: self.out,
            20: self.inp,
            21: self.noop,
        }

        self.opstr = {
            0:  'halt',
            1:  'set',
            2:  'push',
            3:  'pop',
            4:  'eq',
            5:  'gt',
            6:  'jmp',
            7:  'jt',
            8:  'jf',
            9:  'add',
            10: 'mult',
            11: 'mod',
            12: 'andb',
            13: 'orb',
            14: 'notb',
            15: 'rmem',
            16: 'wmem',
            17: 'call',
            18: 'ret',
            19: 'out',
            20: 'inp',
            21: 'noop',
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

        self.commands = {
            'save': self.save_state,
            'load': self.load_state,
            'quit': self.quit,
            'prev': self.prev_state,
            'memdump': self.memdump,
            'reg': self.print_regs,
            'stack': self.print_stack,
            'mem': self.print_mem,
            'cmem': self.print_cmem,
            'pc': self.print_pc,
            'setpc': self.set_pc,
            'pinmem': self.pin_mem,
            'diffmem': self.diff_mem,
            'setmem': self.setmem,
            'setreg': self.setreg,
            'help': self.helpme
        }

    def reset(self):
        self.__pc = 0
        self.__memory[:] = 0
        self.__registers[:] = 0
        self.__stack = []

    @property
    def pc(self):
        return self.__pc
    
    @property
    def mem(self):
        return self.__memory

    @property
    def registers(self):
        return self.__registers
    
    @property
    def stack(self):
        return self.__stack
    

    def memset(self, addr, val):
        if 32768 <= addr <= 32775:
            reg = addr - 32768
            self.__registers[reg] = val % 32768
        else:
            self.__memory[addr] = val % 32768

    def memget(self, addr):
        if 32768 <= addr <= 32775:
            reg = addr - 32768
            return self.__registers[reg]
        else:
            return self.__memory[addr]

    def get(self, x):
        return x if x < 0x8000 else self.memget(x)
    
    def mget(self, x):
        return self.memget(x) if x < 0x8000 else self.memget(self.memget(x))
    
    def run(self, file=None, bytestr=None):
        '''
        Args:
            file: filename of binary file
            bytestr: bytes object of instructions
        '''
        if file is not None:
            if bytestr is not None:
                log.warning('run() called with both file and bytstr; bytestr ignored')
            with open(file, 'rb') as f:
                bytes_read = f.read()
                self.load(bytes_read)
            self._running = True
        elif bytestr is not None:
            self.load(bytestr)
            self._running = True

        self.execute()

    def load(self, exstr):
        for i in range(len(exstr)//2):
            self.__memory[i] = int.from_bytes(exstr[i*2:i*2+2], byteorder='little') 
            if i < 5:
                log.vomit(f'{i} {self.__memory[i]} {exstr[i]}')
        log.vomit(f'{self.__memory[:10]}')

    def execute(self):
        while self._running:
            if self.pc == self.mem.shape[0]:
                log.error('Encountered end of program without halt instruction!')
            try:
                pc = self.pc
                mem = self.mem[pc]
                log.vomit(f'pc:{pc:5} {self.opstr[mem]:6} {str(self.mem[pc+1:pc+self.opargs[mem]+1]):25} r={self.registers} s={self.stack}')
                self.opcodes[mem]()
            except KeyError as e:
                log.error(f'Failed instruction [{mem}@{pc}]: {e}')
                return
        log.debug('VM has terminated.')

    def check_instruction(self, n):
        assert(self.mem[self.pc] == n)
        self.__pc += 1

    def extract(self):
        a = self.mem[self.pc]
        self.__pc += 1
        return a        

    def halt(self):
        self.check_instruction(0)
        self._running = False

    def set(self):
        self.check_instruction(1)
        a = self.extract()
        b = self.extract()

        # bx = self.get(b) #b if b < 0x8000 else self.memget(b)
        self.memset(a, self.get(b))

    def push(self):
        self.check_instruction(2)
        a = self.extract()

        # self.__stack.append(self.memget(a))
        self.__stack.append(self.get(a))

    def pop(self):
        self.check_instruction(3)
        a = self.extract()

        self.memset(a, self.__stack[-1])
        self.__stack.pop()

    def eq(self):
        self.check_instruction(4)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        # bx = b if b < 0x8000 else self.memget(b)
        # cx = c if c < 0x8000 else self.memget(c)

        self.memset(a, 1 if self.get(b) == self.get(c) else 0)

    def gt(self):
        self.check_instruction(5)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, 1 if self.get(b) > self.get(c) else 0)

    def jmp(self):
        self.check_instruction(6)
        a = self.extract()

        self.__pc = self.get(a)

    def jt(self):
        self.check_instruction(7)
        a = self.extract()
        b = self.extract()

        if self.get(a) != 0:
            self.__pc = self.get(b)

    def jf(self):
        self.check_instruction(8)
        a = self.extract()
        b = self.extract()

        if self.get(a) == 0:
            self.__pc = self.get(b)

    def add(self):
        self.check_instruction(9)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, (int(self.get(b)) + int(self.get(c))) % 32768) 

    def mult(self):
        self.check_instruction(10)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, (int(self.get(b)) * int(self.get(c))) % 32768) 

    def mod(self):
        self.check_instruction(11)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.get(b) % self.get(c))

    def andb(self):
        self.check_instruction(12)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.get(b) & self.get(c))

    def orb(self):
        self.check_instruction(13)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.get(b) | self.get(c))

    def notb(self):
        self.check_instruction(14)
        a = self.extract()
        b = self.extract()

        # log.debug(f'{b}, {hex(b)}, {hex((~self.get(b)) & 0x7fff)}')

        self.memset(a, (~self.get(b)) & 0x7fff)

    def rmem(self):
        self.check_instruction(15)
        a = self.extract()
        b = self.extract()

        self.memset(a, self.mget(b))

    def wmem(self):
        self.check_instruction(16)
        a = self.extract()
        b = self.extract()

        # log.debug(f'addr : {self.get(a)}')
        # log.debug(f'val  : {self.get(b)}')
        # log.debug(f'{self.mem[843]}')
        self.memset(self.get(a), self.get(b))
        # log.debug(f'{self.mem[843]}')

    def call(self):
        self.check_instruction(17)
        a = self.extract()

        self.__stack.append(self.pc)
        self.__pc = self.get(a)

    def ret(self):
        self.check_instruction(18)

        if len(self.__stack) == 0:
            self._running = False
        self.__pc = self.__stack[-1]
        self.__stack.pop()

    def out(self):
        self.check_instruction(19)
        ch = self.memget(self.pc)
        if ch >= 0x8000:
            ch = self.memget(ch)
        self.__pc += 1

        print(chr(ch), end='')

    def inp(self):
        self.check_instruction(20)
        a = self.extract()
        
        ready = False
        if self.__buffer == '':
            while not ready:
                if not self._running:
                    return
                self.__buffer = input() + '\n'
                if self.__buffer[0] == '!':
                    ex = re.compile(r'!([a-z]*)\s(.*)')
                    r = ex.match(self.__buffer)
                    try:
                        self.commands[r.group(1)](r)
                    except Exception as e:
                        print(f'Invalid command. ({e})')
                    self.__buffer = ''
                else:
                    ready = True
            self.save_state('prev.dat')
        
        self.__buffer, c = self.__buffer[1:], self.__buffer[0]

        self.memset(a, ord(c))

    def noop(self):
        self.__pc += 1

    def save_state(self, args):
        import json
        def intify(x):
            return [int(y) for y in x]
        data = {
            'mem': intify(self.__memory.tolist()),
            'reg': intify(self.__registers.tolist()),
            'stack': intify(self.__stack),
            'pc': int(self.__pc),
            'running': self._running,
            'buf': self.__buffer
        }
        if type(args) == str:
            a = args
        else:
            a = args.group(2)
        if a == '':
            a = 'default.dat'
        a = os.path.join('.states',a)
        with open(a, 'w') as f:
            json.dump(data, f)
            if a != '.states/prev.dat':
                print(f'State saved to {a}')

    def load_state(self, args):
        import json
        if type(args) == str:
            a = args
        else:
            a = args.group(2)
        if a == '':
            a = 'default.dat'
        a = os.path.join('.states',a)
        with open(a, 'r') as f:
            data = json.load(f)
            print(f'State loaded from {a}')

            self.__memory = np.array(data['mem'], dtype=np.uint16)
            self.__registers = np.array(data['reg'], dtype=np.uint16)
            self.__stack = deque(data['stack'])
            self.__pc = data['pc']
            self._running = data['running']
            self.__buffer = data['buf'] + 'look\n'

    def prev_state(self, args):
        self.load_state('prev.dat')

    def quit(self, args):
        self._running = False

    def memdump(self, args):
        a = args.group(2)
        if a == '':
            a = 'memdump.bin'
        with open(a, 'wb') as f:
            f.write(self.mem.tobytes())
            print('Dumped memory.')

    def setmem(self, args):
        a, b = args.group(2).split(' ')

        if '0x' in a:
            a = int(a, 0)
        else:
            a = int(a)

        if '0x' in b:
            b = int(b, 0)
        else:
            b = int(b)

        self.__memory[a] = b
        print(f'Memory location {a} set to {b} ({chr(b)}).')

    def setreg(self, args):
        a, b = args.group(2).split(' ')

        a = int(a)

        if '0x' in b:
            b = int(b, 0)
        else:
            b = int(b)

        self.__registers[a] = b
        print(f'Register {a} set to {b} ({hex(b)})')

    def conjure(self, args):
        item = args.group(2)
        if item == 'lantern':
            self.__memory[2678] = 2377
            print('A lantern has been conjured!')

    def print_regs(self, args):
        print(self.registers)

    def print_stack(self, args):
        print(self.stack)

    def helpme(self, args):
        print('The following commands are available: ')
        for k in self.commands.keys():
            print(f' {k}')

    def print_mem(self, args):
        g = args.group(2).split(' ')
        a, b = int(g[0]), int(g[1])
        print(self.mem[a:b])

    def print_cmem(self, args):
        g = args.group(2).split(' ')
        if '0x' in g[0]:
            a, b = int(g[0], 0), int(g[1], 0)
        else:
            a, b = int(g[0]), int(g[1])
        mem = self.mem[a:b]
        c, w = 0, 16
        for entry in mem:
            if entry > 30:
                print(f'   {chr(entry)} ', end='')
            else:
                print(f'{entry:4} ', end='')
            c += 1
            if c == w:
                c = 0
                print()

    def pin_mem(self, args):
        self.__pinmem = np.copy(self.mem)
        print("Memory pinned.");

    def diff_mem(self, args):
        try:
            mem = self.__pinmem
        except:
            print('Please pin memory first (!pinmem)')

        if args.group(2) == 'c':
            c = 'c'
        elif args.group(2) == 'h':
            c = 'h'
        else:
            c = None

        print('Args: ', args.group(2))

        for i in range(self.__memory.shape[0]):
            if mem[i] != self.__memory[i]:
                if c == 'c':
                    print(f'   {i:5} {chr(mem[i]):5} {chr(self.__memory[i]):5}')
                elif c == 'h':
                    print(f'   {i:5} {hex(mem[i]):5} {hex(self.__memory[i]):5}')
                else:
                    print(f'   {i:5} {mem[i]:5} {self.__memory[i]:5}')

    def print_pc(self, args):
        print(self.pc)

    def set_pc(self, args):
        a = args.group(2)
        if '0x' in a:
            a = int(a, 0)
        else:
            a = int(a)
        self.__pc = a

def run(args):
    vm = VirtualMachine(state_file=args.load)
    vm.run(file=args.file)
    # print(vm.registers)

class Tests:

    def test_halt():
        # Test writing 5 A's with a halt 
        vm = VirtualMachine()

        sys.stdout = io.StringIO()
        vm.run(bytestr=b'\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x13\x00A\x00\x00\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == 'AAAAA')

    def test_out():
        # Test writing Abc with noops and a halt
        vm = VirtualMachine()

        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x13\x00A\x00\x13\x00b\x00\x13\x00c\x00\x15\x00\x15\x00\x15\x00\x00\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == 'Abc')

    def test_noop():
        # No halt test
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x15\x00\x15\x00')
        res = sys.stdout.getvalue()
        log.vomit(res)
        assert(res == '')

    def test_set():
        # Set registers
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x01\x00\x00\x80\x02\x00\x01\x00\x01\x80\x02\x00\x00\x00')
        log.vomit(vm.registers)
        assert(vm.registers[0] == 2)
        assert(vm.registers[1] == 2)

    def test_push():
        # Push
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x02\x00\x04\x00\x00\x00')
        log.vomit(vm.stack)
        assert(vm.stack[0] == 4)

    def test_pop():
        # Pop
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x02\x00\x04\x00\x02\x00\x05\x00\x03\x00')
        log.vomit(vm.stack)
        assert(vm.stack[0] == 4)
        assert(len(vm.stack) == 1)

    def test_eq():
        # Eq
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x04\x00\x04\x00\x05\x00\x06\x00\x00\x00\x00\x02\x00\x02')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 1)

    def test_gt():
        # greater than
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x05\x00\x04\x00\x05\x00\x06\x00\x00\x00\x01\x02\x00\x02')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 1)

    def test_jmp():
        # jump
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x06\x00\xcf\x00\x01\x00\x06\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[6] == 0)
        assert(vm.pc == 0xd0)

    def test_jt():
        # jump non-zero
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x07\x00\x01\x00\xcf\x00\x01\x00\x07\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0)
        assert(vm.pc == 0xd0)

    def test_jf():
        # jump zero
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x08\x00\x01\x00\xcf\x00\x01\x00\x07\x00\xff\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0xff)
        assert(vm.pc == 7)

    def test_add():
        # add
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x09\x00\x07\x00\x04\x00\x05\x00\xcf\x00\x01\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0xd0)

    def test_mult():
        # mult
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0a\x00\x07\x00\x04\x00\x05\x00\x05\x00\x05\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 0x19)

    def test_mod():
        # mod
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0b\x00\x07\x00\x04\x00\x05\x00\x10\x00\x05\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 1)

    def test_andb():
        # andb
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0c\x00\x07\x00\x04\x00\x05\x00\x01\x00\x03\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 1)

    def test_orb():
        # or bitwise
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0d\x00\x07\x00\x05\x00\x06\x00\x00\x00\x01\x00\x03\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[7] == 3)

    def test_not():
        # not
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0e\x00\x04\x00\x04\x00\x00\x00\xff\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 0x7f00)

    def test_rmem():
        #rmem
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x0f\x00\x04\x00\x05\x00\x00\x00\x00\x00\xef\xbe')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 0xbeef)

    def test_wmem():
        #wmem
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x10\x00\x04\x00\x05\x00\x00\x00\x05\x00\xef\xbe')
        log.vomit(vm.mem[:10])
        assert(vm.mem[4] == 5)

    def test_call():
        #call
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x11\x00\x20\x00')
        log.vomit(vm.pc)
        log.vomit(vm.stack)
        assert(vm.pc == 0x0021)
        assert(vm.stack == [3])

    def test_ret():
        #ret
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x15\x00\x11\x00\x05\x00\x00\x00\x00\x00\x12\x00')
        log.vomit(vm.pc)
        log.vomit(vm.stack)
        assert(vm.pc == 4)
        assert(vm.stack == [])

    def test_in():
        #in
        vm = VirtualMachine()
        sys.stdout = io.StringIO()

        vm.run(bytestr=b'\x14\x00\x07\x00\x14\x00\x08\x00\x14\x00\x09\x00\x00\x00')
        log.vomit(vm.mem[:10])
        assert(vm.mem[3] != 0)

    def run_all_tests():
        Tests.test_halt()
        Tests.test_set()
        Tests.test_push()
        Tests.test_pop()
        Tests.test_noop()
        Tests.test_eq()
        Tests.test_gt()
        Tests.test_jmp()
        Tests.test_jt()
        Tests.test_jf()
        Tests.test_add()
        Tests.test_mult()
        Tests.test_mod()
        Tests.test_andb()
        Tests.test_orb()
        Tests.test_not()
        Tests.test_rmem()
        Tests.test_wmem()
        Tests.test_call()
        Tests.test_ret()
        Tests.test_out()
        Tests.test_in()
        
def run_tests(args):
    Tests.run_all_tests()

    sys.stdout = sys.__stdout__

    log.info('All tests passed successfully.')

def main():
    # For command line use
    LEVELS = {'vomit': 5,
              'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

    # Set up the argument parser and parse the arguments
    parser = ArgumentParser(
        description='Synacor VM'
    )

    parser.add_argument('-t', '--test',
                        action='store_true',
                        default=False,
                        help='run tests')
    parser.add_argument('-o', '--logfile',
                        default='',
                        help='write to a log file')
    parser.add_argument('-v', '--verbose',
                        default=LEVELS['info'],
                        help='verbosity level of stdout log output')
    parser.add_argument('-l', '--log-verbose',
                        default=LEVELS['info'],
                        help='verbosity level of log file output')
    parser.add_argument('-r', '--rotate-log',
                        default=100000000,
                        help='byte size requirement for rotating logs')
    parser.add_argument('-n', '--rotate-count',
                        default=15,
                        help='number of backups to keep for rotating logs')
    parser.add_argument('-c', '--color-log',
                        action='store_true',
                        default=False,
                        help='colorize log output with ANSI color codes')
    parser.add_argument('-x', '--no-log-timestamps',
                        action='store_true',
                        help='for running on radar (rsyslog inserts timestamps')
    parser.add_argument('-f', '--file',
                        default=None,
                        help='input file of binary to execute')
    parser.add_argument('-L', '--load',
                        default=None,
                        help='load a save state')

    (args, extra) = parser.parse_known_args(sys.argv)

    # Finish setting up logger
    verbose = LEVELS.get(args.verbose, logging.INFO)

    log.setLevel(verbose)
    log.propagate = 1

    console = logging.StreamHandler()
    console.setLevel(verbose)

    logging.VOMIT = 5  # New level, used to spew hideous amounts of information

    if args.color_log:
        # For readability, colorize the logging output
        logging.addLevelName(
            logging.DEBUG,
            spiff(logging.getLevelName(logging.DEBUG), 'yellow')
        )
        logging.addLevelName(
            logging.INFO,
            spiff(logging.getLevelName(logging.INFO), 'cyan')
        )
        logging.addLevelName(
            logging.WARNING,
            spiff(logging.getLevelName(logging.WARNING), 'yellow', 'b')
        )
        logging.addLevelName(
            logging.ERROR,
            spiff(logging.getLevelName(logging.ERROR), 'red')
        )
        logging.addLevelName(
            logging.CRITICAL,
            spiff(logging.getLevelName(logging.CRITICAL), 'red', 'b')
        )
        logging.addLevelName(
            logging.VOMIT,
            spiff('VOMIT', 'green', 'b')
        )
    else:
        logging.addLevelName(logging.VOMIT, 'VOMIT')

    def _vomit(self, message, *args, **kwargs):
        if self.isEnabledFor(logging.VOMIT):
            self._log(logging.VOMIT, message, args, **kwargs)

    logging.Logger.vomit = _vomit

    if args.no_log_timestamps:
        logging_format = '%(levelname)s %(module)s::%(funcName)s():%(lineno)d: '
        logging_format += '%(message)s'
    else:
        logging_format = '[%(asctime)s] %(process)d-%(levelname)s '
        logging_format += '%(module)s::%(funcName)s():%(lineno)d: '
        logging_format += '%(message)s'

    color_formatter = logging.Formatter(logging_format)

    console.setFormatter(color_formatter)

    log.addHandler(console)

    # Conditionally set up a log file output
    if args.logfile:
        filehandler = logging.handlers.RotatingFileHandler(
            args.logfile,
            maxBytes=args.rotate_log,
            backupCount=args.rotate_count
        )
        filehandler.setLevel(LEVELS.get(args.log_verbose, logging.INFO))
        filehandler.setFormatter(color_formatter)
        log.addHandler(filehandler)
        log.vomit(f'Writing to log file: {args.logfile}')
        logging.basicConfig(
            filename=args.logfile,
            filemode='a',
            level=LEVELS.get(args.log_verbose, logging.INFO),
            format=logging_format
        )

    if args.test:
        run_tests(args)
    else:
        run(args)

if __name__ == '__main__':
    """Application entry point"""
    main()