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

log = logging.getLogger()

# class OpcodeError(Exception):
#     def __init__(self, op):
#         self.op = op
#     def __str__(self):
#         return f'Failed op code: {self.op}'

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
    def __init__(self, memsize=65536, n_registers=8):
        '''
        Args:
            memsize: size of mem (defaults to 66536)
            n_registers: number of registers (defaults to 8)
        '''
        self.__memory = np.zeros((memsize,), dtype=np.uint16)
        self.__registers = np.zeros((n_registers,), dtype=np.uint16)
        self.__stack = []

        self.__pc = 0   # Program Counter

        self._running = False

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
            self.__registers[reg] = val
        else:
            self.__memory[addr] = val 

    def memget(self, addr):
        if 32768 <= addr <= 32775:
            reg = addr - 32768
            return self.__registers[reg]
        else:
            return self.__memory[addr]
    

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
        elif bytestr is not None:
            self.load(bytestr)
        else:
            log.error('run() called, but no arguments')
            return
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
                log.vomit(f'pc:{pc} {mem}')
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

        self.memset(a, b)

    def push(self):
        self.check_instruction(2)
        a = self.extract()

        # self.__stack.append(self.memget(a))
        self.__stack.append(a)

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

        self.memset(a, 1 if self.memget(b) == self.memget(c) else 0)

    def gt(self):
        self.check_instruction(5)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, 1 if self.memget(b) > self.memget(c) else 0)

    def jmp(self):
        self.check_instruction(6)
        a = self.extract()

        self.__pc = a

    def jt(self):
        self.check_instruction(7)
        a = self.extract()
        b = self.extract()

        # if self.__memory[a] != 0:
        if a != 0:
            self.__pc = b

    def jf(self):
        self.check_instruction(8)
        a = self.extract()
        b = self.extract()

        # if self.__memory[a] == 0:
        if a == 0:
            self.__pc = b

    def add(self):
        self.check_instruction(9)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, (self.memget(b) + self.memget(c)) % 32768) 

    def mult(self):
        self.check_instruction(10)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, (self.memget(b) * self.memget(c)) % 32768) 

    def mod(self):
        self.check_instruction(11)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.memget(b) % self.memget(c))

    def andb(self):
        self.check_instruction(12)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.memget(b) & self.memget(c))

    def orb(self):
        self.check_instruction(13)
        a = self.extract()
        b = self.extract()
        c = self.extract()

        self.memset(a, self.memget(b) | self.memget(c))

    def notb(self):
        self.check_instruction(14)
        a = self.extract()
        b = self.extract()

        log.debug(self.memget(b))

        self.memset(a, (~self.memget(b)) & 0x7fff)

    def rmem(self):
        self.check_instruction(15)
        a = self.extract()
        b = self.extract()

        self.memset(a, self.memget(b))

    def wmem(self):
        self.check_instruction(16)
        a = self.extract()
        b = self.extract()

        self.memset(b, self.memget(a))

    def call(self):
        self.check_instruction(17)
        a = self.extract()

        self.__stack.append(self.pc)
        self.__pc = self.memget(a)

    def ret(self):
        self.check_instruction(18)

        if len(self.__stack) == 0:
            self._running = False
        self.__pc = self.__stack[-1]
        self.__stack

    def out(self):
        self.check_instruction(19)
        ch = self.mem[self.pc]
        self.__pc += 1

        print(chr(ch), end='')

    def inp(self):
        self.check_instruction(20)
        a = self.extract()
        
        c = ' '
        while True:
            c = getch.getche()
            if c == '\n':
                break
            self.memset(a, ord(c))

    def noop(self):
        self.__pc += 1


def run(args):
    vm = VirtualMachine()
    vm.run(file=args.file)
    print(vm.registers)

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

        vm.run(bytestr=b'\x01\x00\x00\x80\x02\x00\x10\x00\x00\x80\x01\x80')
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

    def run_all_tests():
        Tests.test_halt()
        Tests.test_set()
        Tests.test_push()
        Tests.test_pop()
        Tests.test_noop()
        Tests.test_out()
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