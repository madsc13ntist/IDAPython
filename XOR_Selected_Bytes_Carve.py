#!/usr/bin/env python
__version__    = "0.0.1"
__date__       = "07.03.2013"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython to perform an XOR operation on each selected byte in IDA Pro. and dump bytes to a file."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

import os
from time import strftime

########################### MAIN ###########################
if __name__ == '__main__':
    xor_key = AskLong(0xf3, "Please enter a number to XOR with. \n(prefix hex with '0x')")
    if 0 < xor_key <= 255:
        outfile = AskFile(1, GetInputFileMD5().lower() + "_" + hex(SelStart())+".bin", "Save As")
        if outfile != None:
            with open(outfile, 'wb') as dump:
                print("\n[%s]" % (strftime("%Y-%m-%d %H:%M:%S")))
                print("Decoder:  %s" % (os.path.basename(__file__)))
                print("XOR key: 0x%x (%d)" % (xor_key, xor_key))
                print("Offsets:  0x%x-0x%x  (%d bytes)" % (SelStart(), SelEnd(), SelEnd() - SelStart()))
                print("Saved As: %s " % (outfile))

                for b in range(SelStart(), SelEnd()+1):
                    dump.write(chr(GetOriginalByte(b) ^ xor_key))
    else:
        Warning("%d is greater than 255." % (xor_key))
