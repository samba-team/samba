#include <stdio.h>
#include "crc.h"

static u_long table[256];

void
crc_init_table( )
{
    unsigned long crc, poly;
    int     i, j;
    
    poly = 0xEDB88320L;
    for (i = 0; i < 256; i++) {
	crc = i;
	for (j = 8; j > 0; j--) {
	    if (crc & 1) {
		crc = (crc >> 1) ^ poly;
	    } else {
		crc >>= 1;
	    }
	}
	table[i] = crc;
    }
}

u_long
crc_update (char *p, size_t len, u_long res)
{
    while (len--)
	res = table[(res ^ *p++) & 0xFF] ^ (res >> 8);
    return res & 0xFFFFFFFF;
}
