#include <stdio.h>
#include <stdlib.h>
#include <malloc.h> 
#include <unistd.h>
#include "parser.h"

char *tab_depth(int depth)
{
	static pstring spaces;
	memset(spaces, ' ', depth * 4);
	spaces[depth * 4] = 0;
	return spaces;
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,size_t size)
{
  void *ret=NULL;

  if (size == 0) {
    if (p) free(p);
    DEBUG(5,("Realloc asked for 0 bytes\n"));
    return NULL;
  }

  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",(int)size));

  return(ret);
}

/*******************************************************************
 Attempt, if needed, to grow a data buffer.
 Also depends on the data stream mode (io).
 ********************************************************************/

BOOL prs_grow(prs_struct *ps, uint32 extra_space)
{
	uint32 new_size;
	char *new_data;

	ps->grow_size = MAX(ps->grow_size, ps->data_offset + extra_space);

	if(ps->data_offset + extra_space <= ps->buffer_size)
		return True;

	/*
	 * We cannot grow the buffer if we're not reading
	 * into the prs_struct, or if we don't own the memory.
	 */

	if(UNMARSHALLING(ps) || !ps->is_dynamic) {
		DEBUG(0,("prs_grow: Buffer overflow - unable to expand buffer by %u bytes.\n",
				(unsigned int)extra_space));
		return False;
	}
	
	/*
	 * Decide how much extra space we really need.
	 */

	extra_space -= (ps->buffer_size - ps->data_offset);
	if(ps->buffer_size == 0) {
		/*
		 * Ensure we have at least a PDU's length, or extra_space, whichever
		 * is greater.
		 */

		new_size = MAX(MAX_PDU_FRAG_LEN,extra_space);

		if((new_data = malloc(new_size)) == NULL) {
			DEBUG(0,("prs_grow: Malloc failure for size %u.\n", (unsigned int)new_size));
			return False;
		}
		memset(new_data, '\0', new_size );
	} else {
		/*
		 * If the current buffer size is bigger than the space needed, just 
		 * double it, else add extra_space.
		 */
		new_size = MAX(ps->buffer_size*2, ps->buffer_size + extra_space);		

		if ((new_data = Realloc(ps->data_p, new_size)) == NULL) {
			DEBUG(0,("prs_grow: Realloc failure for size %u.\n",
				(unsigned int)new_size));
			return False;
		}
	}
	ps->buffer_size = new_size;
	ps->data_p = new_data;

	return True;
}


/*******************************************************************
 Ensure we can read/write to a given offset.
 ********************************************************************/

char *prs_mem_get(prs_struct *ps, uint32 extra_size)
{
	if(UNMARSHALLING(ps)) {
		/*
		 * If reading, ensure that we can read the requested size item.
		 */
		if (ps->data_offset + extra_size > ps->buffer_size) {
			DEBUG(0,("prs_mem_get: reading data of size %u would overrun buffer.\n",
					(unsigned int)extra_size ));
			return NULL;
		}
	} else {
		/*
		 * Writing - grow the buffer if needed.
		 */
		if(!prs_grow(ps, extra_size))
			return False;
	}
	return &ps->data_p[ps->data_offset];
}

/*******************************************************************
 Initialise a parse structure - malloc the data if requested.
 ********************************************************************/

BOOL prs_init(prs_struct *ps, uint32 size, uint8 align, BOOL io)
{
	ZERO_STRUCTP(ps);
	ps->io = io;
	ps->bigendian_data = False;
	ps->align = align;
	ps->is_dynamic = False;
	ps->data_offset = 0;
	ps->buffer_size = 0;
	ps->data_p = NULL;

	if (size != 0) {
		ps->buffer_size = size;
		if((ps->data_p = (char *)malloc((size_t)size)) == NULL) {
			DEBUG(0,("prs_init: malloc fail for %u bytes.\n", (unsigned int)size));
			return False;
		}
		ps->is_dynamic = True; /* We own this memory. */
	}

	return True;
}

/*******************************************************************
 debug output for parsing info.

 XXXX side-effect of this function is to increase the debug depth XXXX

 ********************************************************************/
void prs_debug(prs_struct *ps, int depth, char *desc, char *fn_name)
{
	DEBUG(5+depth, ("%s%06x %s %s\n", tab_depth(depth), ps->data_offset, fn_name, desc));
}

/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/

BOOL prs_align(prs_struct *ps)
{
	uint32 mod = ps->data_offset & (ps->align-1);

	if (ps->align != 0 && mod != 0) {
		uint32 extra_space = (ps->align - mod);
		if(!prs_grow(ps, extra_space))
			return False;
		memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
		ps->data_offset += extra_space;
	}

	return True;
}


void print_asc(int level, unsigned char *buf,int len)
{
	int i;
	for (i=0;i<len;i++)
		DEBUG(level,("%c", isprint(buf[i])?buf[i]:'.'));
}

/*******************************************************************
 read from a socket into memory.
 ********************************************************************/
BOOL prs_read(prs_struct *ps, int fd, size_t len, int timeout)
{
	BOOL ok;
	size_t prev_size = ps->buffer_size;
	if (!prs_grow(ps, len))
	{
		return False;
	}

	if (timeout > 0)
	{
		ok = (read(fd, &ps->data_p[prev_size], len) == len);
	}
	else 
	{
		ok = (read(fd, &ps->data_p[prev_size], len) == len);
	}
	return ok;
}

void dump_data(int level,char *buf1,int len)
{
  unsigned char *buf = (unsigned char *)buf1;
  int i=0;
  if (len<=0) return;

  DEBUG(level,("[%03X] ",i));
  for (i=0;i<len;) {
    DEBUG(level,("%02X ",(int)buf[i]));
    i++;
    if (i%8 == 0) DEBUG(level,(" "));
    if (i%16 == 0) {      
      print_asc(level,&buf[i-16],8); DEBUG(level,(" "));
      print_asc(level,&buf[i-8],8); DEBUG(level,("\n"));
      if (i<len) DEBUG(level,("[%03X] ",i));
    }
  }
  if (i%16) {
    int n;

    n = 16 - (i%16);
    DEBUG(level,(" "));
    if (n>8) DEBUG(level,(" "));
    while (n--) DEBUG(level,("   "));

    n = MIN(8,i%16);
    print_asc(level,&buf[i-(i%16)],n); DEBUG(level,(" "));
    n = (i%16) - n;
    if (n>0) print_asc(level,&buf[i-n],n); 
    DEBUG(level,("\n"));    
  }
}


/*******************************************************************
 do IO on a uint32.
 ********************************************************************/
BOOL io_uint32(char *name, prs_struct *ps, int depth, uint32 *data32, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	q = prs_mem_get(ps, sizeof(uint32));
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data32)
	ps->data_offset += sizeof(uint32);

	return True;
}

/*******************************************************************
 do IO on a uint16.
 ********************************************************************/
BOOL io_uint16(char *name, prs_struct *ps, int depth, uint16 *data16, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	q = prs_mem_get(ps, sizeof(uint16));
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data16)
	ps->data_offset += sizeof(uint16);

	return True;
}

/*******************************************************************
 do IO on a uint8.
 ********************************************************************/
BOOL io_uint8(char *name, prs_struct *ps, int depth, uint8 *data8, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	q = prs_mem_get(ps, sizeof(uint8));
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data8)
	ps->data_offset += sizeof(uint8);

	return True;
}

/*******************************************************************
 do IO on a pointer
 ********************************************************************/
BOOL io_pointer(char *desc, prs_struct *ps, int depth, void **p, unsigned flags)
{
	uint32 v;

	if (!(flags & PARSE_SCALARS)) return True;

	v = (*p) ? 0xdeadbeef : 0;
	if (!io_uint32(desc, ps, depth, &v, flags)) return False;
	*p = (void *) (v ? 0xdeadbeef : 0);
	return True;
}

/******************************************************************
 do IO on a unicode array
 ********************************************************************/
BOOL io_wstring(char *name, prs_struct *ps, int depth, uint16 *data16s, int len, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	q = prs_mem_get(ps, len * sizeof(uint16));
	if (q == NULL) return False;

	DBG_RW_PSVAL(True, name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, data16s, len)
	ps->data_offset += (len * sizeof(uint16));

	return True;
}


/******************************************************************
allocate some memory for a parse structure
 ********************************************************************/
BOOL io_alloc(char *name, prs_struct *ps, void **ptr, unsigned size)
{
	(*ptr) = (void *)malloc(size);
	if (*ptr) return True;
	return False;
}

