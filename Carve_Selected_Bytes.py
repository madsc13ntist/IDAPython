#!/usr/bin/env python
__version__    = "0.0.1"
__date__       = "07.02.2013"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython to extract a piece of a binary."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

from idautils import *

def carveSelectedBytes(outfile="", start=SelStart(), end=SelEnd()):
    """
    Carve specified bytes out to a file.
    """
    if outfile == "":
        outfile = AskFile(1, hex(start)+".bin", "Save As")
    try:
        with open(outfile, "wb") as fp:
            for ea in range(start, end+1):
                fp.write(chr(GetOriginalByte(ea)))
        print("\n%x-%x saved to: %s" % (start, end, outfile))
    except Exception as e:
        return str(e)

########################### MAIN ###########################
if __name__ == '__main__':
    carveSelectedBytes()
