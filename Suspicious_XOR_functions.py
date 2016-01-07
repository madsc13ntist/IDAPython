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
__description__= "Use IDAPython to search through a PE for suspicious calls to xor loops."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################


from idautils import *
import time
from time import strftime


def locationsInFunc(funcea):
    locations = []
    func_name = GetFunctionName(funcea)
    for item in FuncItems(funcea):
        loc = Name(item)
        if loc != func_name and loc != "BADADDR" and loc != "":
            locations.append(loc)
    return locations

def loopsInFunc(funcea):
    loops = []
    func_end = FindFuncEnd(funcea)
    for item in FuncItems(funcea):
        for xref in XrefsTo(item, 0):
            if xref.type not in [1,21]:
                if funcea <= xref.to <= xref.frm <= func_end:
                    if GetMnem(xref.frm) not in ['call', 'retn']:
                        loops.append((xref.frm, xref.to))
    if len(loops) > 0:
        return loops
    else:
        return False

def funcContainsXORLoop(funcea):
    loops = loopsInFunc(funcea)
    if loops:
        xor_loops = []
        for xref_from, xref_to in loops:
            for head in Heads(xref_to, xref_from):
                if GetMnem(head) == "xor":
                    if GetOpnd(head, 0) != GetOpnd(head, 1):
                        xor_loops.append(head)
        return xor_loops
    return False

def dataRefsInFunc(funcea):
    data = []
    func_end = FindFuncEnd(funcea)
    for head in Heads(funcea, func_end):
        for xref in DataRefsFrom(head):
            if xref not in [None, False]:
                #if SegName(xref) == ".data":
                data.append(xref)
    if len(data) > 0:
        return data
    else:
        return False

def argsForCall(call_ea):
    args = []
    current_ea = PrevHead(call_ea)
    func_head = LocByName(GetFunctionName(call_ea))
    while current_ea > func_head and GetMnem(current_ea)[0] != "j" and GetMnem(current_ea) not in ["call"]:
        if GetMnem(current_ea) == "push":
            args.append((current_ea, GetOpnd(current_ea, 0)))
        current_ea = PrevHead(current_ea)
    args.sort()
    args.reverse()
    if len(args) > 0:
        return args
    else:
        return False


########################### MAIN ###########################
if __name__ == '__main__':
    ea = SegByBase(SegByName(".text"))
    print("NOTE:  Addresses and names (\"sub_403D50\", \"loc_4022EA\", \"4022ec\", etc) are (double) clickable.")
    print("                       %s" % (strftime("%Y-%m-%d %H:%M:%S")))
    print("-------------------- Functions with XOR loops ------------------------------")
    for funcea in Functions(SegStart(ea), SegEnd(ea)):
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
