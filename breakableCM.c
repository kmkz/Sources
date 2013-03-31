# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <assert.h>
# include <errno.h>
# include <sys/ptrace.h>
# include <unistd.h>

#define LOL 0x14
#define genkey "DapAswd"
#define LIMIT 244

/*
 * [+] Breakable need to be patched first to
 *      could be debbugged
 * 
 * root@kmkz-3lrvs/home/kmkz/Breakable# ./breakable
[+] Enter your name : pouetapwal
[+] Enter serial : kikoo
- Username: pouetapwal- Key: kikoo
 
flag 6D651617373776F736565656D616D6F7375717569757165-2852
* */


 struct data{
   char usr[80];
   char ki[90];
} _data;



int main(int argc, char **argv[]){

/* Routine anti débugg  obfusquée 1 */
char usr[LIMIT]={0};
short int dbg=(0);
char z[LIMIT]=("0x0804924");
char key[26]={0};
char serializ[57]={0x8c ,0x75 ,0x70 ,0x61 ,0x73 ,0x74 ,0x77 ,0x6e ,0x72,
                   0x64 ,0x64 ,0x65 ,0x6c ,0xb1 ,0x6a ,0x6f ,0x52 ,0x64,
                   0x71 ,0x75 ,0x99 ,0x74 ,0x75 ,0x65 ,0x00 ,0x80 ,0x90,
                   0x6f ,0x52};

int byte_ =(0);
  
  __asm__(
		"xor %eax,%eax \012"
		"xor %ebx,%ebx \012"
		"xor %ecx,%ecx \012"
		"xor %edx,%edx \012"
		"mov %ebx,%ecx \012"
		"inc %ecx \012"
		"mov $0x1A, %eax \012"
		"int $0x80 \012"
	);

if (byte_  <= 0 ){
	printf("Program exited normally. \012");
	return(1);
}


/* Routine anti débugg  obfusquée 2 */
int good=(ptrace(ptrace(PTRACE_TRACEME,0,1,0) < 0));


if(good == -1 ){
	printf("Program exited normally. \012");
	return(1);
}
	

       /* Saisies utilisateur */
memset( _data.ki, 0 ,sizeof _data.ki);
memset( _data.usr, 0 ,sizeof _data.usr);
       
fprintf(stdout,"[+] Enter your name : ");
fgets(_data.usr,sizeof (_data.usr)-1,stdin);

fprintf(stdout,"[+] Enter serial : ");
fgets(_data.ki,sizeof (_data.ki)-1,stdin);
/* Fin saisies utilisateur */

    
    
_data.usr[10]=( (_data.usr[8]) << 1 && _data.ki[3] ==(LOL) );


/* Routine anti débugg  obfusquée 3 */
long int fget_=(ptrace(ptrace(PTRACE_TRACEME,0,1,0) < 0));

if(fget_ == -1 ){
	printf("Program exited normally. \012");
	return(1);
}

sprintf(key,"%s", _data.usr);
 
 
 
char keyz[27]={0x6c ,0x65 ,0x70 ,0x61 ,0x73 ,0x73 ,0x77 ,0x6f ,0x72 ,
                0x64 ,0x64 ,0x65 ,0x6c ,0x61 ,0x6d ,0x6f ,0x72 ,0x74 ,
                0x71 ,0x75 ,0x69 ,0x74 ,0x75 ,0x65 ,0x00 ,0x00 ,0x90};
                
                /* assertion anti debug */ 
assert(fget_ == -1 || !fget_ || byte_ <= 0);
_data.usr[2]=( (_data.usr[3]) ^2);

keyz[22]=(_data.usr[6] + 1 );
keyz[2]=(_data.usr[2] >> 2 + 4);
fprintf(stdout,"- Username: %s- Key: %s \012",_data.usr,_data.ki);


   /* --------------------------------------
    * Routine de generation du Serial Final
    * 
    * TODO : Prendre en compte le username 
    * pour le serial final ! DONE ?
    * 
    * STRIPPING  
    * ------------------------------------ */

 
 
short cpt=(0);
assert(fget_ == -1|| !fget_ || byte_ <= 0);
printf("flag ",_data.usr);

for(cpt;cpt < 24;cpt++){

	printf("%X",keyz[cpt] | 1); // on peux jouer sur la valeur pour obtenir un autre output
	if(keyz[cpt] ==('\00')){
	    break;
	}
}
int wol=strlen(_data.usr)*286;
assert(fget_ == -1|| !fget_ || byte_ <= 0);
fprintf(stdout,"-%d ",wol-8);
printf("\012");

/* ----------------------------
 * Fin de la routine du Serial 
 * ---------------------------*/			
/* fake password verification */
int serial=strcmp(_data.ki,genkey);
                 if(serial ==0){ 
                   	printf("%s",serializ);
                    printf("Program exited normally . \012");
                    return(1);
                 }
                 if(serial != 0){
	                   goto WINNER;
                 }
                                                                                 
WINNER:
return(0);
}
