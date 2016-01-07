#!/usr/bin/env python
__version__    = "0.0.1"
__date__       = "07.01.2013"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython to create hashes for all subroutines that aren't imported."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################


from idautils import *
import hashlib
import os
import time
from time import strftime


IMPORTED = []

def carveSelectedBytes(outfile="", start=SelStart(), end=SelEnd()):
    if outfile == "":
        outfile = AskFile(1, hex(SelStart())+".bin", "Save As")
    try:
        with open(outfile, "wb") as fp:
            for ea in range(start, end+1):
                fp.write(chr(GetOriginalByte(ea)))
        print("\n%x-%x saved to: %s" % (SelStart(), SelEnd(), outfile))
    except Exception as e:
        return str(e)

def imp_cb(ea, name, ord):
    if name:
        #print "%08x: %s (ord#%d)" % (ea, name, ord)
        IMPORTED.append(name)
    return True

def ImportedFuncs():
    nimps = idaapi.get_import_module_qty()
    #print "Found %d import(s)..." % nimps
    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            #print "Failed to get import module name for #%d" % i
            continue
        #print "Walking-> %s" % name
        idaapi.enum_import_names(i, imp_cb)
    return sorted(IMPORTED)

def FuncHashes(funcea):
    # carve out func
    tmpfile = os.getenv("TEMP") + os.sep + "func_" + hex(funcea) + ".tmp"
    carveSelectedBytes(tmpfile, funcea, FindFuncEnd(funcea))
    func_md5 = hashlib.md5(open(tmpfile, 'rb').read()).hexdigest()

    # delete tmp file
    os.path.remove(tmpfile)



########################### MAIN ###########################
if __name__ == '__main__':
    print("NOTE:  Addresses and names (\"sub_403D50\", \"loc_4022EA\", \"4022ec\", etc) are (double) clickable.")
    print("                       %s" % (strftime("%Y-%m-%d %H:%M:%S")))
    print("-------------------- Functions  ------------------------------")

    imp = ImportedFuncs()
    ea = SegByBase(SegByName(".text"))
    for funcea in Functions(SegStart(ea), SegEnd(ea)):
        if GetFunctionName(funcea) not in imp:
            print(GetFunctionName(funcea))


    """
        xor_loops = funcContainsXORLoop(funcea)
        if xor_loops:
            func_type = GetType(funcea)
            if func_type == None:
                func_type = ""
            print("XOR Loop in %s %s" % (Name(funcea), func_type))
            for item in xor_loops:
                print("    [%x]: %s" % (item, GetDisasm(item)))

            data_refs = dataRefsInFunc(funcea)
            if data_refs:
                for dref in data_refs:
                    print("--> Data Ref: %s (%d bytes)" % (Name(dref), ItemSize(dref)))

            for xref in XrefsTo(funcea, 0):
                if GetMnem(xref.frm) == "call":
                    func_type = GetType(xref.frm)
                    if func_type == None:
                        func_type = ""
                    print("--> Called By: %s (%x) %s" % (GetFunctionName(xref.frm), xref.frm, func_type))

                    '''
                    data_refs = dataRefsInFunc(xref.frm)
                    if data_refs:
                        for dref in data_refs:
                            print("------> Data Ref: %s (%d bytes)" % (Name(dref), ItemSize(dref)))#'''

                    args = argsForCall(xref.frm)
                    if args:
                        arg_count = 0
                        for arg_ea, arg in args:
                            arg_count += 1
                            arg_str = GetString(LocByName(arg))
                            if arg_str != None:
                                print("               Arg #%d = %s %s" % (arg_count, arg, arg_str))
                            elif ItemSize(LocByName(arg.split()[-1])) > 1:
                                print("               Arg #%d = %s (%d bytes)" % (arg_count, arg, ItemSize(LocByName(arg.split()[-1]))))
                            else:
                                print("               Arg #%d = %s" % (arg_count, arg, ))
            print("")
"""
