import os
import io
import sys
import numpy as np
import logging
import re
from collections import deque

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')))

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
            'conjure': self.conjure,
            'tp': self.teleport,
            'asm': self.export_asm,
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
                log.vomit(f'pc:{pc:5} {self.opstr[mem]:6} {str(self.mem[pc+1:pc+self.opargs[mem]+1]):25} r={self.registers} s={list(self.stack)}')
                self.opcodes[mem]()
            except KeyError as e:
                log.error(f'Failed instruction [{mem}@{pc}]: {e}')
                return
        log.debug('VM has terminated.')

    def check_instruction(self, n):
        if self.mem[self.pc] != n:
            log.warning('Instruction mismatch')
        else:
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
        
        self.ready = False
        if self.__buffer == '':
            while not self.ready:
                self.get_input()
            self.save_state('prev.dat')
        
        self.__buffer, c = self.__buffer[1:], self.__buffer[0]

        self.memset(a, ord(c))

    def noop(self):
        self.__pc += 1

    def get_input(self):
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
            self.ready = True

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

    def teleport(self, args):
        item = args.group(2)
        if item == 'beach':
            self.__memory[2732] = 0x9c2
            self.__memory[2733] = 0x9c2
            print('You\'ve been teleported to a beach!')

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
        if '0x' in g[0]:
            a = int(g[0], 0)
        else:
            a = int(g[0])
        if len(g) == 2:
            if '0x' in g[1]:
                b = int(g[1], 0)
            else:
                b = int(g[1])
            print(self.mem[a:b])
        else:
            print(self.mem[a])


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

    def export_asm(self, args):
        g = args.group(2)
        stripped = True
        if g == 'all':
            stripped = False
            g = None
        if not g:
            g = 'dump.asm'
        with open(g, 'w') as f:
            ip = 0
            while ip != self.mem.shape[0]:
                try:
                    oip = ip
                    op = self.opstr[self.mem[ip]]
                    opargs = self.opargs[self.mem[ip]]
                    ip += 1
                    args = []
                    for i in range(opargs):
                        args.append(self.mem[ip])
                        ip += 1
                    arghex = [f'{hex(x):6}' if x < 0x8000 and op != 'out' else f'R{x-0x8000}    ' if op != 'out' else chr(x).replace('\n','\\n') for x in args]
                    hexstr = ' '.join(arghex)
                    f.write(f'{hex(oip):6} {op:6} {hexstr}\n')
                    if op == 'halt' or op == 'ret':
                        f.write('\n')
                except Exception as e:
                    ip = oip
                    # log.warning(e)
                    if not stripped:
                        f.write(f'{hex(ip):6} {hex(self.mem[ip])} ???\n')
                    ip += 1

            print(f'Assmebly dump at {g}.')


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