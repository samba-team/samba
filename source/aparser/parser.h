#include <ctype.h>
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../include/byteorder.h"

#define PARSE_SCALARS (1<<0)
#define PARSE_BUFFERS (1<<1)

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define DEBUG(lvl, str) printf str;
#define DEBUGADD(lvl, str) printf str;

#define MARSHALL 0
#define UNMARSHALL 1

#define MARSHALLING(ps) (!(ps)->io)
#define UNMARSHALLING(ps) ((ps)->io)

typedef int BOOL;
typedef unsigned char uint8;
typedef unsigned char uchar;
typedef unsigned short uint16;
typedef unsigned short wchar;
typedef unsigned uint32;
typedef char *SMBSTR;

/* a null terminated unicode string */
typedef uint16 ZUSTRING;

#ifndef _PSTRING

#define PSTRING_LEN 1024
#define FSTRING_LEN 256

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

typedef struct _io_struct 
{
	BOOL io; /* parsing in or out of data stream */
	/* 
	 * If the (incoming) data is big-endian. On output we are
	 * always little-endian.
	 */ 
	BOOL bigendian_data;
	BOOL is_dynamic; /* Do we own this memory or not ? */
	BOOL autoalign; /* should we auto-align all elements? */
	uint32 data_offset; /* Current working offset into data. */
	uint32 buffer_size; /* Current size of the buffer. */
	uint32 grow_size; /* size requested via io_grow() calls */
	char *data_p; /* The buffer itself. */
} io_struct;


char *io_mem_get(io_struct *ps, uint32 extra_size);
BOOL io_init(io_struct *ps, uint32 size, BOOL io);
void io_debug(io_struct *ps, int depth, char *desc, char *fn_name);
BOOL io_align(io_struct *ps, int align);
BOOL io_align4(io_struct *ps, int align);
BOOL io_align2(io_struct *ps, int align);
BOOL io_read(io_struct *ps, int fd, size_t len, int timeout);
void dump_data(int level,char *buf1,int len);
BOOL io_alloc(char *name, io_struct *ps, void **ptr, unsigned size);
BOOL io_uint32(char *name, io_struct *ps, int depth, uint32 *data32, unsigned flags);
BOOL io_uint16(char *name, io_struct *ps, int depth, uint16 *data16, unsigned flags);
BOOL io_uint8(char *name, io_struct *ps, int depth, uint8 *data8, unsigned flags);
BOOL io_pointer(char *desc, io_struct *ps, int depth, void **p, unsigned flags);
BOOL io_SMBSTR(char *name, io_struct *ps, int depth, char **str, unsigned flags);
BOOL io_io_struct(char *name, io_struct *ps, int depth, io_struct *io, unsigned flags);
BOOL io_wstring(char *name, io_struct *ps, int depth, uint16 *data16s, int len, unsigned flags);
BOOL io_uint8s_fixed(char *name, io_struct *ps, int depth, uint8 *data8s, int len, unsigned flags);
BOOL io_uint8s(char *name, io_struct *ps, int depth, uint8 **data8s, int len, unsigned flags);

char *tab_depth(int depth);
void *Realloc(void *p,size_t size);
void dump_data(int level,char *buf1,int len);
void print_asc(int level, uchar const *buf, int len);
BOOL io_ZUSTRING(char *name, io_struct *ps, int depth, uint16 **ustr, unsigned flags);
size_t strlen_w(void *src);

