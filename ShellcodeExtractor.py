#! /usr/bin/env python

from pwn import *

ShellcodeFile = open("b64_extract.bin","r+") 
Extracted = ShellcodeFile.readline();

print(disasm(unhex(Extracted), byte=0, arch='amd64', offset = 0))
print "[+] Hex value: "+ Extracted
