#!/usr/bin/env python3
import os
import io
import sys
import logging
import logging.handlers

from argparse import ArgumentParser
from signal import signal, SIGINT
from utils.spiffyText import spiff

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')))

from assembler.Assembler import Assembler

log = logging.getLogger()

def run(args):
    Assembler(args.file, 'output.asm')

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
        description='Synacor Assembler'
    )

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
                        help='input file assembly to assemble')

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
        log.debug(f'Writing to log file: {args.logfile}')
        logging.basicConfig(
            filename=args.logfile,
            filemode='a',
            level=5, #LEVELS.get(args.log_verbose, logging.INFO),
            format=logging_format
        )

    run(args)

if __name__ == '__main__':
    """Application entry point"""
    main()