#!/usr/bin/env python
__version__    = "0.0.1"
__date__       = ""
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython to search through a PE for suspicious data/objects."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

"""
 look for calls to functions that contain xor operations (that don't clear registers) that have .data offsets pushed just prior to the call. 
"""

from idautils import *
import time	#Only imported for the Jump() call in MAIN
import operator

"""
items = the address of the first byte of an instruction.
heads = the address for the first byte in an instruction ("xor"  in "xor eax, eax")
frame = the id of an entire function.
chunk = the pieces of a function in ida. 
"""


def dataObjects(threshold=0):
	seg = SegByBase(SegByName(".data"))
	objects = {}
	for head in Heads(SegStart(seg), SegEnd(seg)):
		if ItemSize(head) > threshold:
			#print("%s (%d bytes)\t" % (Name(head), ItemSize(head), GetString(head)))
			objects[head] = ItemSize(head)
	
		#Jump(head)
		#Sleep(1000)
	return objects

########################### MAIN ###########################
if __name__ == '__main__':
	data_objects = dataObjects()	# parse initialized data objects
	data_objects_by_size = sorted(data_objects.iteritems(), key=operator.itemgetter(1))
	print("%d objects found in .data" % (len(data_objects)))
	for ea, size in data_objects_by_size:
		if GetString(ea):
			print("%x: (%d bytes) %s" % (ea, size, GetString(ea)))
		else:
			print("%x: (%d bytes)" % (ea, size))
			xored_stream = []
			xor_keys = []
			for n in range(1,256):
				for b in [ GetOriginalByte(x) for x in range(ea, ea+size+1) ]:
					xored_stream.append(b ^ n)
				try:
					print("%x: (%d bytes) [XOR: 0x%x] %s" % (ea, size, n, ''.join(xored_stream)))
					xor_keys.append(n)
				except:
					pass
	print("")
	

"""
ea = SegByBase(SegByName(".text"))
print("-------------------- Functions with XOR loops ------------------------------")
for funcea in Functions(SegStart(ea), SegEnd(ea)):
	for ref in DataRefsFrom(funcea):
		if isData(ref):
			print Name(ref), hex(ref)
	
	
	
	
	if xor_loops:
		print("%x: %s" % (funcea, Name(funcea)))
		for item in xor_loops:
			print("%x: %s" % (item, GetDisasm(item)))
		for xref in XrefsTo(funcea, 0):
			if GetMnem(xref.frm) == "call":
				print("--> Called By: %x" % (xref.frm))
		#Jump(item)
		#time.sleep(1)
		print("")
"""
