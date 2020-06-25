#! /usr/bin/env python

from pwn import *

ShellcodeFile = open("extract.bin","r+") 
Extracted = ShellcodeFile.readline();

print "[+] Extracted shellcode:"

print(disasm(unhex(Extracted), byte=0, arch='amd64', offset = 0))
