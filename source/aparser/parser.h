#include <ctype.h>
#include "../include/byteorder.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
/* Maximum PDU fragment size. */
#define MAX_PDU_FRAG_LEN 0x1630

#define DEBUG(lvl, str) printf str;

#define MARSHALL 0
#define UNMARSHALL 1

#define MARSHALLING(ps) (!(ps)->io)
#define UNMARSHALLING(ps) ((ps)->io)

typedef int BOOL;
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned uint32;

#define False 0
#define True 1

typedef char pstring[1024];

/* zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); }

#define MAX_UNISTRLEN 256
#define MAX_STRINGLEN 256
#define MAX_BUFFERLEN 512

typedef struct _prs_struct 
{
	BOOL io; /* parsing in or out of data stream */
	/* 
	 * If the (incoming) data is big-endian. On output we are
	 * always little-endian.
	 */ 
	BOOL bigendian_data;
	uint8 align; /* data alignment */
	BOOL is_dynamic; /* Do we own this memory or not ? */
	uint32 data_offset; /* Current working offset into data. */
	uint32 buffer_size; /* Current size of the buffer. */
	char *data_p; /* The buffer itself. */
} prs_struct;


char *prs_mem_get(prs_struct *ps, uint32 extra_size);
BOOL prs_uint32(char *name, prs_struct *ps, int depth, uint32 *data32);
BOOL prs_init(prs_struct *ps, uint32 size, uint8 align, BOOL io);
void prs_debug(prs_struct *ps, int depth, char *desc, char *fn_name);
BOOL prs_align(prs_struct *ps);
void print_asc(int level, unsigned char *buf,int len);
BOOL prs_read(prs_struct *ps, int fd, size_t len, int timeout);
void dump_data(int level,char *buf1,int len);
BOOL prs_uint16s(BOOL charmode, char *name, prs_struct *ps, int depth, uint16 *data16s, int len);
BOOL prs_uint32s(BOOL charmode, char *name, prs_struct *ps, int depth, uint32 *data32s, int len);
BOOL prs_pointer(char *desc, prs_struct *ps, int depth, void **p);
BOOL prs_uint16(char *name, prs_struct *ps, int depth, uint16 *data16);

