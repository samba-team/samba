#include "krb5_locl.h"

RCSID("$Id$");

#include <stdio.h>
#include "crc.h"

static u_long table[256];

#define CRC_GEN 0xEDB88320L

void
crc_init_table(void)
{
    unsigned long crc, poly;
    int     i, j;
    
    poly = CRC_GEN;
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

u_int32_t
crc_update (char *p, size_t len, u_int32_t res)
{
    while (len--)
	res = table[(res ^ *p++) & 0xFF] ^ (res >> 8);
    return res & 0xFFFFFFFF;
}
