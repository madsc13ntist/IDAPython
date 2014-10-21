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
__description__= "Use IDAPython to search through a PE for specific instructions"

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

from idautils import *
import time
from time import strftime
import re


########################### MAIN ###########################
if __name__ == '__main__':
	ea = SegByBase(SegByName(".text"))
	s = AskStr(GetDisasm(ItemHead(SelStart())), "Please enter a string (regex) for the instruction to search for.")
	if s in ["", None, False]:
		Warning("You must enter an instruction/regex to search for.")
	else:
		inst = re.compile(s.strip().replace(" ", "\s+"))
		
		
		print("NOTE:  Addresses and names (\"sub_403D50\", \"loc_4022EA\", \"4022ec\", etc) are (double) clickable.")
		print("                       %s" % (strftime("%Y-%m-%d %H:%M:%S")))
		print("-------------------- Instruction Search: " + s + " ------------------------------")
		for funcea in Functions(SegStart(ea), SegEnd(ea)):
			results = []
			for item in FuncItems(funcea):
				for match in inst.findall(GetDisasm(item)):
					results.append(item)
				if GetMnem(item) in ['xor', 'or', 'and', 'rol', 'ror', 'shr', 'shl']:
					if GetOpType(item, 0) == 4 and GetOpType(item, 1) == 5:
						if GetOperandValue(item, 1) not in [0x0, 0x0FFFFFFFF]:
							print(GetDisasm(item))
			
			if len(results) > 0:
				func_name = Demangle(GetFunctionName(funcea), INF_SHORT_DN)
				if func_name:
					print("%s:" % (func_name))
				else:
					print("%s:" % (GetFunctionName(funcea)))
				for offset in results:
					print("\t[%x]: %s" % (offset, GetDisasm(offset)))
					print("%d, %d" % (GetOpType(offset, 0), GetOpType(offset, 1)))
				print("")
