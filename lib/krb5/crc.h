#include <sys/types.h>

#define CRC_GEN 0xEDB88320L

void crc_init_table ();
u_long crc_update (char *p, size_t len, u_long res);
