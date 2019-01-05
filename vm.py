#!/usr/bin/env python3
import os
import sys
import numpy as np
from argparse import ArgumentParser
import logging
from signal import signal, SIGINT
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
        self.__stack = np.array([], dtype=np.uint16)

        self.__pc = 0   # Program Counter

        self._running = False

        self.opcodes = {
            0:  self.halt,
            19: self.out,
            21: self.noop,
        }

    def reset(self):
        self.__pc = 0

    @property
    def pc(self):
        return self.__pc
    
    @property
    def mem(self):
        return self.__memory
    

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
        for i in range(len(exstr)):
            self.__memory[i] = exstr[i]

    def execute(self):
        while self._running:
            if self.pc == self.__memory.shape[0]:
                log.error('Encountered end of program without halt instruction!')
            try:
                pc = self.pc
                mem = self.mem[pc]
                self.opcodes[mem]()
            except KeyError as e:
                log.error(f'Failed instruction [{mem}@{pc}]: {e}')
                return
        log.info('VM has terminated.')

    def halt(self):
        assert(self.mem[self.pc] == 0)
        self.__pc += 1
        self._running = False

    def out(self):
        assert(self.mem[self.pc] == 19)
        self.__pc += 1
        ch = self.mem[self.pc]
        self.__pc += 1

        print(chr(ch), end='')

    def noop(self):
        self.__pc += 1


def run(args):
    log.debug('run()')
    pass

def run_tests(args):
    import io
    sys.stdout = io.StringIO()

    vm = VirtualMachine()

    # Test writing 5 A's with a halt 
    vm.run(bytestr=b'\x13A\x13A\x13A\x13A\x13A\x00')
    res = sys.stdout.getvalue()
    log.vomit(res)
    assert(res == 'AAAAA')
    
    # Test writing Abc with noops and a halt
    vm.reset()
    sys.stdout = io.StringIO()

    vm.run(bytestr=b'\x13A\x13b\x13c\x15\x15\x15\x00')
    res = sys.stdout.getvalue()
    log.vomit(res)
    assert(res == 'Abc')
    
    # No halt test
    vm.reset()
    sys.stdout = io.StringIO()

    vm.run(bytestr=b'\x15\x15\x15')
    res = sys.stdout.getvalue()
    log.vomit(res)
    assert(res == '')

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