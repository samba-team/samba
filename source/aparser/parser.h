#include <ctype.h>
#include "../include/byteorder.h"

#define PARSE_SCALARS (1<<0)
#define PARSE_BUFFERS (1<<1)

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
typedef unsigned short wchar;
typedef unsigned uint32;

#ifndef _PSTRING

#define PSTRING_LEN 1024
#define FSTRING_LEN 128

typedef char pstring[PSTRING_LEN];
typedef char fstring[FSTRING_LEN];

#define _PSTRING

#endif
#define False 0
#define True 1

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
	BOOL is_dynamic; /* Do we own this memory or not ? */
	uint32 data_offset; /* Current working offset into data. */
	uint32 buffer_size; /* Current size of the buffer. */
	uint32 grow_size; /* size requested via prs_grow() calls */
	char *data_p; /* The buffer itself. */
} prs_struct;


char *prs_mem_get(prs_struct *ps, uint32 extra_size);
BOOL prs_init(prs_struct *ps, uint32 size, BOOL io);
void prs_debug(prs_struct *ps, int depth, char *desc, char *fn_name);
BOOL prs_align(prs_struct *ps, int align);
void print_asc(int level, unsigned char *buf,int len);
BOOL prs_read(prs_struct *ps, int fd, size_t len, int timeout);
void dump_data(int level,char *buf1,int len);
BOOL io_alloc(char *name, prs_struct *ps, void **ptr, unsigned size);
BOOL io_uint32(char *name, prs_struct *ps, int depth, uint32 *data32, unsigned flags);
BOOL io_uint16(char *name, prs_struct *ps, int depth, uint16 *data16, unsigned flags);
BOOL io_uint8(char *name, prs_struct *ps, int depth, uint8 *data8, unsigned flags);
BOOL io_pointer(char *desc, prs_struct *ps, int depth, void **p, unsigned flags);
BOOL io_fstring(char *name, prs_struct *ps, int depth, fstring *str, unsigned flags);
BOOL io_wstring(char *name, prs_struct *ps, int depth, uint16 *data16s, int len, unsigned flags);
BOOL io_uint8s(char *name, prs_struct *ps, int depth, uint8 *data8s, int len, unsigned flags);

