; compilated using : nasm -f elf shellcode_asm.asm &&  ld -o shellcode_asm shellcode_asm.o
 ; kmkz simple "key_printer"  Shellcode (root-me prog.  shellcoding challenge)   
  ; July 2010

BITS 32
         

 SECTION .data
         _key db "W0O7&x0n0p",0x0a       



 SECTION .bss
        alignb 4
        modified_code: resb 0x2000




 SECTION .text
   
        GLOBAL _asm_main 
        _asm_main:
  	  

        mov al,0x04
	add ecx,.hexastring; 
        mov dl,28
        int 0x80

        xor eax,eax
        mov al,0x01
        int 0x80
        xor ebx,ebx
        leave
        ret
		  
       .hexastring db "0xy0u_'v 3_f0unD_thE_k3y_n",0x0a
	 
	 
	 
;	 char shellcode[]=("\xb0\x04\x81\xc1\x30\x78\x79\x30\x75\x5f\x27\x76\x20\x33\x5f\x66\x30\x75\x6e\x44"
;	    "\x5f\x74\x68\x45\x5f\x6b\x33\x79\x5f\x6e\x0a\xb2\x1c\xcd\x80\x31\xc0\xb0\x01\xcd\x80\x31\xdb"
;	    "\xc9\xc3\x30\x78\x79\x30\x75\x5f\x27\x76\x20\x33\x5f\x66\x30\x75\x6e\x44\x5f\x74\x68\x45\x5f\x6b\x33\x79\x5f\x6e\x0a");
			
			
