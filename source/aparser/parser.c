#include "parser.h"

/*******************************************************************
 Attempt, if needed, to grow a data buffer.
 Also depends on the data stream mode (io).
 ********************************************************************/

BOOL io_grow(io_struct *ps, uint32 extra_space)
{
	uint32 new_size;
	char *new_data;

	ps->grow_size = MAX(ps->grow_size, ps->data_offset + extra_space);

	if(ps->data_offset + extra_space <= ps->buffer_size)
		return True;

	/*
	 * We cannot grow the buffer if we're not reading
	 * into the io_struct, or if we don't own the memory.
	 */

	if(UNMARSHALLING(ps) || !ps->is_dynamic) {
		DEBUG(0,("io_grow: Buffer overflow - unable to expand buffer by %u bytes.\n",
				(unsigned int)extra_space));
		return False;
	}
	
	/*
	 * Decide how much extra space we really need.
	 */

	extra_space -= (ps->buffer_size - ps->data_offset);
	if(ps->buffer_size == 0) {
		new_size = extra_space;

		if((new_data = malloc(new_size)) == NULL) {
			DEBUG(0,("io_grow: Malloc failure for size %u.\n", (unsigned int)new_size));
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
			DEBUG(0,("io_grow: Realloc failure for size %u.\n",
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

char *io_mem_get(io_struct *ps, uint32 extra_size)
{
	if(UNMARSHALLING(ps)) {
		/*
		 * If reading, ensure that we can read the requested size item.
		 */
		if (ps->data_offset + extra_size > ps->buffer_size) {
			DEBUG(0,("io_mem_get: reading data of size %u would overrun buffer.\n",
					(unsigned int)extra_size ));
			return NULL;
		}
	} else {
		/*
		 * Writing - grow the buffer if needed.
		 */
		if(!io_grow(ps, extra_size))
			return False;
	}
	return &ps->data_p[ps->data_offset];
}

/*******************************************************************
 Initialise a parse structure - malloc the data if requested.
 ********************************************************************/

BOOL io_init(io_struct *ps, uint32 size, BOOL io)
{
	ZERO_STRUCTP(ps);
	ps->io = io;
	ps->bigendian_data = False;
	ps->is_dynamic = False;
	ps->data_offset = 0;
	ps->buffer_size = 0;
	ps->data_p = NULL;

	if (size != 0) {
		ps->buffer_size = size;
		if((ps->data_p = (char *)malloc((size_t)size)) == NULL) {
			DEBUG(0,("io_init: malloc fail for %u bytes.\n", (unsigned int)size));
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
void io_debug(io_struct *ps, int depth, char *desc, char *fn_name)
{
	DEBUG(5+depth, ("%s%06x %s %s\n", tab_depth(depth), ps->data_offset, fn_name, desc));
}

/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/

BOOL io_align2(io_struct *ps, int offset)
{
	uint32 mod = (ps->data_offset + offset) & (2-1);

	if (mod != 0) {
		uint32 extra_space = (2 - mod);
		if(!io_grow(ps, extra_space))
			return False;
		memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
		ps->data_offset += extra_space;
	}

	return True;
}

BOOL io_align4(io_struct *ps, int offset)
{
	uint32 mod = (ps->data_offset + offset) & (4-1);

	if (mod != 0) {
		uint32 extra_space = (4 - mod);
		if(!io_grow(ps, extra_space))
			return False;
		memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
		ps->data_offset += extra_space;
	}

	return True;
}

/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/

BOOL io_align(io_struct *ps, int align)
{
	uint32 mod;

	if (!ps->autoalign) return True;

	mod = ps->data_offset & (align-1);

	if (align != 0 && mod != 0) {
		uint32 extra_space = (align - mod);
		if(!io_grow(ps, extra_space))
			return False;
		memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
		ps->data_offset += extra_space;
	}

	return True;
}


/*******************************************************************
 read from a socket into memory.
 ********************************************************************/
BOOL io_read(io_struct *ps, int fd, size_t len, int timeout)
{
	BOOL ok;
	size_t prev_size = ps->buffer_size;
	if (!io_grow(ps, len))
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


/*******************************************************************
 do IO on a uint32.
 ********************************************************************/
BOOL io_uint32(char *name, io_struct *ps, int depth, uint32 *data32, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	if (!io_align(ps, 4)) return False;

	q = io_mem_get(ps, sizeof(uint32));
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data32)
	ps->data_offset += sizeof(uint32);

	return True;
}

/*******************************************************************
 do IO on a uint16.
 ********************************************************************/
BOOL io_uint16(char *name, io_struct *ps, int depth, uint16 *data16, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	if (!io_align(ps, 2)) return False;

	q = io_mem_get(ps, sizeof(uint16));
	if (q == NULL) return False;

	DBG_RW_SVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data16)
	ps->data_offset += sizeof(uint16);

	return True;
}

/*******************************************************************
 do IO on a uint8.
 ********************************************************************/
BOOL io_uint8(char *name, io_struct *ps, int depth, uint8 *data8, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	q = io_mem_get(ps, sizeof(uint8));
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, *data8)
	ps->data_offset += sizeof(uint8);

	return True;
}

/*******************************************************************
 do IO on a pointer
 ********************************************************************/
BOOL io_pointer(char *desc, io_struct *ps, int depth, void **p, unsigned flags)
{
	uint32 v;

	if (!(flags & PARSE_SCALARS)) return True;

	v = (*p) ? 0xdeadbeef : 0;
	if (!io_uint32(desc, ps, depth, &v, flags)) return False;
	*p = (void *) (v ? 0xdeadbeef : 0);
	return True;
}

/*******************************************************************
 Stream a null-terminated string.  
 ********************************************************************/
BOOL io_SMBSTR(char *name, io_struct *ps, int depth, char **str, unsigned flags)
{
	char *q;
	uint8 *start;
	int i;
	size_t len;
	int start_offset = ps->data_offset;

	if (!(flags & PARSE_SCALARS)) return True;
	
	if (UNMARSHALLING(ps)) {
		*str = io_mem_get(ps, 0);
		if (*str == NULL)
			return False;
		len = strlen(*str);
		ps->data_offset += len + 1;
	}
	else
	{
		len = strlen(*str)+1;
		start = (uint8*)q;

		for(i = 0; i < len; i++) {
			q = io_mem_get(ps, 1);
			if (q == NULL)
				return False;

			RW_CVAL(ps->io, q, (*str)[i],0);
			ps->data_offset++;
		}
	}

	DEBUG(5,("%s%04x %s: %s\n", tab_depth(depth),
				start_offset, name, *str));
	return True;
}

/******************************************************************
 do IO on a byte array
 ********************************************************************/
BOOL io_uint8s(char *name, io_struct *ps, int depth, uint8 **data8s, int len, unsigned flags)
{
	char *q;
	size_t num_bytes = len * sizeof(uint8);

	if (!(flags & PARSE_SCALARS)) return True;

	q = io_mem_get(ps, num_bytes);
	if (q == NULL) return False;

	if (MARSHALLING(ps))
	{
		DBG_RW_PCVAL(True, name, depth, ps->data_offset, ps->io, q, *data8s, len)
	}
	else
	{
		*data8s = q;
		dump_data(depth+5, *data8s, num_bytes);
	}
	ps->data_offset += num_bytes;

	return True;
}
/******************************************************************
 do IO on a fixed-size byte array
 ********************************************************************/
BOOL io_uint8s_fixed(char *name, io_struct *ps, int depth, uint8 *data8s, int len, unsigned flags)
{
	char *q;
	size_t num_bytes = len * sizeof(uint8);

	if (!(flags & PARSE_SCALARS)) return True;

	q = io_mem_get(ps, num_bytes);
	if (q == NULL) return False;

	DBG_RW_PCVAL(True, name, depth, ps->data_offset, ps->io, q, data8s, len)
	ps->data_offset += num_bytes;

	return True;
}


/******************************************************************
 do IO on an io (eh?? :)
 ********************************************************************/
BOOL io_io_struct(char *name, io_struct *ps, int depth, io_struct *io, unsigned flags)
{
	char *q;
	uint16 len;

	if (!(flags & PARSE_SCALARS)) return True;

	q = io_mem_get(ps, sizeof(uint16));
	if (q == NULL) return False;

	/* length first */
	if (MARSHALLING(ps))
	{
		len = io->data_offset;
	}
	if (!io_uint16("len", ps, depth+1, &len, flags))
	{
		return False;
	}
	if (UNMARSHALLING(ps))
	{
		if (!io_init(io, len, UNMARSHALL))
		{
			return False;
		}
	}

	/* now data */
	q = io_mem_get(ps, len * sizeof(uint8));
	if (q == NULL) return False;

	if (MARSHALLING(ps))
	{
		DBG_RW_PCVAL(False, name, depth+1, ps->data_offset, ps->io, q, io->data_p, len)
	}
	else
	{
		io->data_p = q;
		dump_data(depth+5, q, len);
	}
	ps->data_offset += len;

	return True;
}

/******************************************************************
 do IO on a unicode array
 ********************************************************************/
BOOL io_wstring(char *name, io_struct *ps, int depth, uint16 *data16s, int len, unsigned flags)
{
	char *q;

	if (!(flags & PARSE_SCALARS)) return True;

	if (!io_align(ps, 2)) return False;

	q = io_mem_get(ps, len * sizeof(uint16));
	if (q == NULL) return False;

	DBG_RW_PSVAL(True, name, depth, ps->data_offset, ps->io, ps->bigendian_data, q, data16s, len)
	ps->data_offset += (len * sizeof(uint16));

	return True;
}


/******************************************************************
allocate some memory for a parse structure
 ********************************************************************/
void io_free(io_struct *ps)
{
	if (ps->is_dynamic && ps->data_p)
	{
		free(ps->data_p);
		ps->data_p = NULL;
	}
}

/******************************************************************
allocate some memory for a parse structure
 ********************************************************************/
BOOL io_alloc(char *name, io_struct *ps, void **ptr, unsigned size)
{
	(*ptr) = (void *)malloc(size);
	if (*ptr) return True;
	return False;
}

/******************************************************************
realloc some memory for a parse structure
 ********************************************************************/
BOOL io_realloc(char *name, io_struct *ps, void **ptr, unsigned size)
{
	(*ptr) = (void *)Realloc(*ptr, size);
	if (*ptr) return True;
	return False;
}

