
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char buffer[65536];

int
main(int argc, char *argv[])
{
    unsigned int sum = 0;
    int          bytenum = 0;

    while (fgets(buffer, sizeof(buffer), stdin)) {
	char *s;

	s = strtok(buffer, " \n\t");
	while (s) {
	    unsigned char val;
	    char          *eos;

	    if (*s == '\\')
		goto next_byte;
	    bytenum++;
	    if (*s == '\'') {
		val = *(s+1);
		sum += val;
		goto next_byte;
	    }
	    val = strtoul(s, &eos, 16);
	    if (*eos != '\0') {
		fprintf(stderr, "Invalid byte %d\n", bytenum);
		return 1;
	    }
	    sum += val;
	next_byte:
	    s = strtok(NULL, " \n\t");
	}
    }

    sum &= 0xff;
    printf("Checksum of %d (%x) bytes is %x, to make zero is %x\n",
	   bytenum, bytenum, 
	   sum, (0x100-sum) & 0xff);
    return 0;
}
