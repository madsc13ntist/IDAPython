'''
********************************************************************************
Name:		CreateYaraSignature.py
Author:		case b <cbarnes@accuvant.com>
Version:	1

[Description]

This Python script for use in IDA allows the user to display information about
the code and data currently selected and optionally save the information to 
disk.

The following configurable data items may be displayed and or saved:
- Header including length and VA range
- Bytes representing the selection
- Text of the disassembly selected
- Bytes organized by lines of disassembly
- Bytes representing the selection with all but the first byte per line
  wildcarded if either of the operands represent memory addresses or relative
  locations
- A basic YARA signature with the wildcarded byte string as the test signature


[Notes]
This script has only been tested in IDA 6.3 on MacOS X with PySide installed
analysing x86 code. YMMV.

PySide must be installed for save functionality to work.

Happy hunting. If you have any questions, comments, rants, etc. please send
them my way.

********************************************************************************
'''
import idaapi

IMPORTED = []

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

def sanitize(rulename):
    sanitized_name = ""
    for c in rulename:
        if 58 > ord(c) > 47 or 91 > ord(c) > 64 or 123 > ord(c) > 96:
            sanitized_name += c
        else:
            sanitized_name += "_"
    return sanitized_name

class SignatureCreator( object):
    '''Creates signature information for a selection'''
    def __init__( self):
        self.__ERRORS = {
            'SUCCESS' 	: 0, # Everything's great
            'BADADDR' 	: 1, # A selection wasn't made
            'BADFILE'	: 2, # Something bad happend whilst writing the signature file
        }

        self.__CONFIG = {
            'SHOW_IN_OUTPUT_WINDOW'		: True,
            'PROMPT_TO_SAVE'		: True,
            'SHOW_HEADER'			: False,
            'SHOW_DISASSEMBLY_TEXT'		: False,
            'SHOW_RAW_BYTES'		: False,
            'SHOW_WILD_CARDED_BYTES'	: False,
            'SHOW_BYTES_PER_LINE'		: False,
            'SHOW_YARA_SIGNATURE'		: True,
            'OP_TYPES_TO_WILDCARD'		: [o_mem,o_phrase, o_displ,o_far,o_near]
        }
        self.__SignatureHeader	= []
        self.__RawBytes		= []
        self.__DisassemblyText	= []
        self.__LinesOfBytes	= []
        self.__WildCardedBytes	= []
        self.__YaraSignature	= []
        self.__Signature	= []

        ##### Added
        self.saveFilePath = GetInputFileMD5().lower() + "_subs.yar"

    def __CheckBounds( self):
        '''Check to see if a selection was made.'''
        if self.__startAddress is BADADDR or self.__endAddress is BADADDR:
            sys.stderr.write( "Please select the section you would like to create a signature on.")
            return self.__ERRORS['BADADDR']
        else:
            return self.__ERRORS['SUCCESS']
    def GetSignatureHeader( self):
        '''Returns signature header information.'''
        if not self.__SignatureHeader:
            self.__SignatureHeader.append( "\n\n[SIGNATURE FOR {0}]\n".format( GetInputFilePath()))
            self.__SignatureHeader.append( "\nLENGTH:\t{0:#x}\n".format( self.__endAddress-self.__startAddress))
            self.__SignatureHeader.append( "RANGE:\t{0:#08x}-{1:#08x}\n".format( self.__startAddress, self.__endAddress))
        return self.__SignatureHeader
    def GetRawBytes( self):
        '''Return bytes representing the selection.'''
        if not self.__RawBytes:
            self.__RawBytes.append( "\nBYTES:\n{0}\n".format( ''.join( [ "{0:02x} ".format( ord( byte)) \
                for byte in GetManyBytes( self.__startAddress, self.__endAddress-self.__startAddress, 0)]).strip()))
        return self.__RawBytes
    def GetDisassemblyText( self):
        '''Return lines of disassembly representing the selection.'''
        if not self.__DisassemblyText:
            self.__DisassemblyText = ["\nDISASSEMBLY:\n"]
            currea = self.__startAddress
            while currea < self.__endAddress:
                nextea = NextNotTail( currea)
                self.__DisassemblyText.append( "{0}\n".format( GetDisasm( currea)))
                currea = nextea
        return self.__DisassemblyText
    def GetLinesOfBytes( self):
        '''Return lines of bytes representing lines of disassembly of the selection.'''
        if not self.__LinesOfBytes:
            self.__LinesOfBytes = ["\nBYTES PER LINE:\n"]
            currea = self.__startAddress
            while currea < self.__endAddress:
                nextea = NextNotTail( currea)
                lineLength = ItemSize( currea)
                self.__LinesOfBytes.append( "{0}\n".format( ''.join( [ "{0:02x} ".format( ord( byte)) \
                    for byte in GetManyBytes( currea, lineLength, 0)])))
                currea = nextea
        return self.__LinesOfBytes
    def GetWildCardedBytes( self):
        '''Get bytes of selection and wildcard any IDA 'tails' if either operand represents a memory location.'''
        if not self.__WildCardedBytes:
            self.__WildCardedBytes = ["\nWILD-CARDED MEMORY BYTES:\n"]
            currea = self.__startAddress
            while currea < self.__endAddress:
                nextea = NextNotTail( currea)
                lineLength = ItemSize( currea)
                currFlags = GetFlags( currea)
                if isCode( currFlags):
                    self.__WildCardedBytes.append( "{0:02x} ".format( Byte( currea)))
                    op1Type = GetOpType( currea, 0)
                    op2Type = GetOpType( currea, 1)
                    varTypes = self.__CONFIG['OP_TYPES_TO_WILDCARD']
                    if op1Type in varTypes or op2Type in varTypes:
                        self.__WildCardedBytes.append('?? ' * int(lineLength-1))
                    elif lineLength > 1:
                        self.__WildCardedBytes.append( ''.join( [ "{0:02x} ".format( ord( byte)) \
                            for byte in GetManyBytes( currea+1, lineLength-1, 0)]))
                elif isData( currFlags):
                    self.__WildCardedBytes.append( format( ''.join( [ "{0:02x} ".format( ord( byte)) \
                        for byte in GetManyBytes( currea, lineLength, 0)])))
                currea = nextea
            self.__WildCardedBytes.append( '\n')
        return self.__WildCardedBytes
    def GetYaraSignature( self):
        '''Create a dummy yara signature containing the wildcarded byte string'''
        if not self.__YaraSignature:
            self.__YaraSignature = []#['\nYARA SIGNATURE:\n']
            self.__YaraSignature.append( "rule %s\n{\n\tstrings:\n\t\t$hex_string = { " % (sanitize(GetFunctionName(funcea))))
            self.__YaraSignature.append( "{0}}}\n\tcondition:\n\t\t$hex_string\n}}\n\n".format( ''.join( [ line \
                for line in self.GetWildCardedBytes()[1:]]).strip()))
        return self.__YaraSignature
    def GetSignature( self):
        '''Returns signature text per self.__CONFIG'''
        if not self.__Signature:
            if self.__CONFIG['SHOW_HEADER']:
                self.__Signature.extend( self.GetSignatureHeader())
            if self.__CONFIG['SHOW_DISASSEMBLY_TEXT']:
                self.__Signature.extend( self.GetDisassemblyText())
            if self.__CONFIG['SHOW_RAW_BYTES']:
                self.__Signature.extend( self.GetRawBytes())
            if self.__CONFIG['SHOW_BYTES_PER_LINE']:
                self.__Signature.extend( self.GetLinesOfBytes())
            if self.__CONFIG['SHOW_WILD_CARDED_BYTES']:
                self.__Signature.extend( self.GetWildCardedBytes())
            if self.__CONFIG['SHOW_YARA_SIGNATURE']:
                self.__Signature.extend( self.GetYaraSignature())
        return ''.join( [ line for line in self.__Signature])
    def Run( self, fea):
        self.__startAddress = fea
        self.__endAddress = FindFuncEnd(funcea)
        boundCheck = self.__CheckBounds()
        if boundCheck is not self.__ERRORS['SUCCESS']:
            return boundCheck
        signature = self.GetSignature()
        if self.__CONFIG['SHOW_IN_OUTPUT_WINDOW']:
            sys.stdout.write( signature)
        if self.__CONFIG['PROMPT_TO_SAVE']:
            #from PySide import QtGui
            #saveFilePath = QtGui.QFileDialog.getSaveFileName( None,"Save YARA Signature To:")[0]
            if self.saveFilePath:
                try:
                    fp = open( self.saveFilePath, 'a')
                    fp.write( signature)
                    fp.close()
                except Exception, ex:
                    sys.stderr.write( str( ex))
                    return self.__ERRORS['BADFILE']
            else:
                sys.stderr.write('No file selected.\n')
        return self.__ERRORS['SUCCESS']

if __name__ == "__main__":
    imp = ImportedFuncs()
    ea = SegByBase(SegByName(".text"))

    for funcea in Functions(SegStart(ea), SegEnd(ea)):
        if GetFunctionName(funcea) not in imp:
            #print("Adding: %s" % (GetFunctionName(funcea)))
            script = SignatureCreator()
            script.Run(funcea)
