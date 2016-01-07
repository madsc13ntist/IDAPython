#!/usr/bin/env python
__version__    = "0.0.1"
__date__       = "07.08.2013"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist gmail.com"
__copyright__  = "Copyright 2013, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython to search for interesting Api Calls."

####################### MIT License ####################### 
# Copyright (c) 2013 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

from idautils import *
from time import strftime

### these are matched as substrings that will be matched as *PART* of an Api name.  Some are intentionally more complete to reduce noise.
INTERESTING_SUBSTRINGS = [\
                            ### Filesystem Manipulation
                            ("CreateFile",    "File Creation/Drop"),\
                            ("CopyFile",      "Filesystem Manipulation"),\
                            ("DeleteFile",    "Filesystem Manipulation"),\
                            ("CFile::Write",  "File Creation/Drop"),\
                            ("CFile::Open",   "File Creation/Drop"),\
                            ### Filesystem Recognaisance
#							("CFile::Open",   "File Creation/Drop"),\
                            ("CFileFind::",   "Filesystem Crawling"),\
                            ("CFile::Read",   "File Access"),\
                            ###### Network Activity ######
                            ("Http",          "Potential Network Activity"),\
                            ("Socket",        "Potential Network Activity"),\
                            ("Internet",      "Potential Network Activity"),\
                            ("Inet",          "Potential Network Activity"),\
                            ###### Process Creation ######
                            ("CreateProcess", "Spawns a new process"),\
                            ("Mutex",         "Mutex Creation/Manipulation"),\
                            ###### Process Injection ######
                            ("ProcessMemory", "Potential Process injection"),\
                            ###### Service Manipulation ######
                            ("Service",       "Potential Service Manipulation"),\
                            ###### String manipulation / C2 Creation ######
#							("CString::",      "String Manipulation. Common in C2 creation"),\
                            ###### Anti-Analytics ######
                            ("Debugger",       "Anti-Analytics"),\
                        ]


########################### MAIN ###########################
if __name__ == '__main__':
    print("\n-------------------- Interesting Api Calls ------------------------------")
    print("NOTE:  Addresses and names (\"sub_403D50\", \"loc_4022EA\", \"4022ec\", etc) are (double) clickable.")
    print("Run at: %s" % (strftime("%Y-%m-%d %H:%M:%S")))
    for call_ea, name in sorted(Names()):
        demangled_name = Demangle(name, INF_SHORT_DN)
        if demangled_name != None:
            name = demangled_name

        for keyword, note in sorted(INTERESTING_SUBSTRINGS):
            if keyword.lower() in name.lower():
                xrefs = sorted([ x for x in CodeRefsTo(call_ea, 0) if SegName(call_ea) != ".data" ])
                if len(xrefs) > 0:
                    print("\nCalls To: (%x) %s (%s)" % (call_ea, name, note))
                    #print("          (%s)" % (note))
                    for xref in xrefs:
                        print("          [%x] %s" % (xref, GetFunctionName(xref)))

