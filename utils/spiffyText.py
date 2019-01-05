#!/usr/bin/python
'''
Display text with ascii formatting escape codes
'''

import re

def spiff(text, *formats):
    if len(formats) == 0:
        return text

    codeDict = {'gray':'30', 'red':'31', 'green':'32',
            'yellow':'33', 'blue':'34', 'magenta':'35',
            'cyan':'36', 'white':'37',
            'hgray':'40', 'hred':'41', 'hgreen':'42',
            'hyellow':'43', 'hblue':'44', 'hmagenta':'45',
            'hcyan':'46', 'hwhite':'47',
            'b':'1', 'i':'3', 'u':'4'}

    codes = []
    for format in formats:
        if format in codeDict:
            format = codeDict[format]
        codes += [format]

    text.replace('{', '{{')
    text.replace('}', '}}')

    return '\033[{0}m{1}\033[0m'.format(';'.join(codes), text)

def despiff(text):
    return re.sub(r'\x1B\[[0-?]*[@-~]', '', text)

WARNING_STR = spiff('WARNING:', 'yellow')
ERROR_STR   = spiff('  ERROR:', 'red')
INFO_STR    = spiff('   INFO:', 'cyan')
