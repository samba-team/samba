/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba memory buffer functions
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "sma.h"

/*******************************************************************
 SMA stuff
 ********************************************************************/

static SMA_REGION *prs_sma_region = NULL;

static void prs_sma_init(void)
{
	if (prs_sma_region)
		return;

	/* waste about 400k for sma... */
	prs_sma_region = sma_alloc_region(16384, 24);
}

/*******************************************************************
dump a prs to a file
 ********************************************************************/
void prs_dump(char *name, int v, prs_struct *ps)
{
	int fd, i;
	pstring fname;
	if (DEBUGLEVEL < 50) return;
	for (i=1;i<100;i++) {
		if (v != -1) {
			slprintf(fname,sizeof(fname), "/tmp/%s_%d.%d.prs", name, v, i);
		} else {
			slprintf(fname,sizeof(fname), "/tmp/%s.%d.prs", name, i);
		}
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
	}
	if (fd != -1) {
		write(fd, ps->data, ps->data_size);
		close(fd);
		DEBUG(0,("created %s\n", fname));
	}
}

/*******************************************************************
 debug output for parsing info.
 ********************************************************************/
void prs_debug(prs_struct *ps, int depth, const char *desc,
	       const char *fn_name)
{
	CHECK_STRUCT(ps);
	DEBUG(5 + depth, ("%s%06x %s %s\n",
			  tab_depth(depth), ps->offset, fn_name, desc));
}

/*******************************************************************
 debug a parse structure
 ********************************************************************/
void prs_debug_out(const prs_struct *ps, char *msg, int level)
{
	CHECK_STRUCT(ps);

	if (DEBUGLEVEL < level) return;

	DEBUG(level, ("%s ps: io %s align %d offset %d err %d data %p\n",
		      msg, BOOLSTR(ps->io), ps->align, ps->offset, ps->error,
		      ps->data));

	if (ps->data != NULL)
	{
		dump_data(level, ps->data, prs_buf_len(ps));
	}
}

/*******************************************************************
 initialise a parse structure
 ********************************************************************/
BOOL prs_init(prs_struct *ps, uint32 size, uint8 align, BOOL io)
{
	ps->struct_start = 0xfefefefe;
	ps->io = io;
	ps->align = align;
	ps->offset = 0;
	ps->error = False;
	ps->bigendian = False;

	ps->data = NULL;
	ps->data_size = 0;

	ps->start = 0;
	ps->end = 0;

	ps->next = NULL;

	ps->struct_end = 0xdcdcdcdc;

	if (size != 0)
	{
		prs_realloc_data(ps, size);
		ps->end = 0xffffffff;
	}

	CHECK_STRUCT(ps);
	return True;
}

/*******************************************************************
 set the packed data representation type in a parse structure
 ********************************************************************/
void prs_set_packtype(prs_struct *ps, const uint8 *pack_type)
{
	CHECK_STRUCT(ps);
	ps->bigendian = pack_type[0] == 0x0;
	DEBUG(10, ("prs_set_packtype: bigendian: %s\n",
		   BOOLSTR(ps->bigendian)));
}

/*******************************************************************
 create a parse structure
 ********************************************************************/
void prs_create(prs_struct *ps, char *data, uint32 size, uint8 align, BOOL io)
{
	DEBUG(200, ("prs_create: data:%p size:%d align:%d io:%s\n",
		    data, size, align, BOOLSTR(io)));

	prs_init(ps, 0, align, io);
	prs_append_data(ps, data, size);
	if (MARSHALLING(ps))
	{
		DEBUG(1, ("WARNING: prs_create initialised a buffer "
			  "in marshalling-mode\n"));
	}

	/* *arg* */
	/* safe_free(data); */

	CHECK_STRUCT(ps);
}

/*******************************************************************
 copy a parse structure
 ********************************************************************/
BOOL prs_copy(prs_struct *ps, const prs_struct *from)
{
	int len = prs_buf_len(from);
	CHECK_STRUCT(ps);
	CHECK_STRUCT(from);
	prs_init(ps, len, from->align, from->io);
	ps->bigendian = from->bigendian;
	if (len != 0)
	{
		if (ps->data == NULL)
		{
			return False;
		}
		if (!prs_buf_copy(ps->data, from, 0, len))
		{
			return False;
		}
	}
	ps->offset = len;
	prs_link(NULL, ps, NULL);
	return True;
}

/*******************************************************************
 allocate a memory buffer.  assume it's empty
 ********************************************************************/
static BOOL prs_alloc_data(prs_struct *buf, int size)
{
	prs_sma_init();

	CHECK_STRUCT(buf);

	buf->data_size = size;
	buf->data = sma_alloc(prs_sma_region, buf->data_size);

	if (buf->data == NULL && size != 0)
	{
		DEBUG(3, ("prs_alloc: could not malloc size %d\n",
			  buf->data_size));
		buf->data_size = 0;

		return False;
	}

	memset(buf->data, 0, buf->data_size);
	buf->end = buf->start + size;

	CHECK_STRUCT(buf);
	return True;
}

/*******************************************************************
 search for a memory buffer that falls within the specified offset
 ********************************************************************/
static const prs_struct *prs_find(const prs_struct *buf, uint32 offset)
{
	const prs_struct *f;
	if (buf == NULL)
		return False;

	f = buf;

	CHECK_STRUCT(f);
	DEBUG(200, ("prs_find: data[%d..%d] offset: %d\n",
		    f->start, f->end, offset));

	while (f != NULL && offset >= f->end)
	{
		DEBUG(200, ("prs_find: next[%d..%d]\n", f->start, f->end));

		f = f->next;
	}

	if (f != NULL)
	{
		DEBUG(200, ("prs_find: found [%d..%d]\n", f->start, f->end));
	}

	return f;
}

/*******************************************************************
 allocates a memory buffer structure
 ********************************************************************/
BOOL prs_buf_copy(char *copy_into, const prs_struct *buf,
		  uint32 offset, uint32 len)
{
	uint32 end = offset + len;
	char *q = NULL;
	uint32 start_offset = offset;
	const prs_struct *bcp = buf;

	if (buf == NULL || copy_into == NULL)
		return False;

	CHECK_STRUCT(buf);
	if (DEBUGLVL(200))
	{
		DEBUG(200, ("prs_struct_copy: data[%d..%d] "
			"offset %d len %d\n",
		       buf->start, prs_buf_len(buf), offset, len));
	}

	prs_debug_out(bcp, "prs_struct_copy", 200);

	while (offset < end && ((q = prs_data(bcp, offset)) != NULL))
	{
		uint32 copy_len;
		bcp = prs_find(bcp, offset);
		copy_len = bcp->end - offset;

		DEBUG(200, ("\tdata[%d..%d] - offset %d len %d\n",
			    bcp->start, bcp->end, offset, copy_len));

		memcpy(copy_into, q, copy_len);

		offset += copy_len;
		copy_into += copy_len;
	}

	if (bcp != NULL)
	{
		DEBUG(200, ("prs_struct_copy: copied %d bytes\n",
			    offset - start_offset));
	}
	else
	{
		DEBUG(200, ("prs_struct_copy: failed\n"));
	}

	return buf != NULL;
}

/*******************************************************************
 frees up a memory buffer.
 ********************************************************************/
void prs_struct_free(prs_struct **buf)
{
	if (buf == NULL)
		return;
	if ((*buf) == NULL)
		return;

	CHECK_STRUCT(*buf);
	prs_free_data(*buf);	/* delete memory data */
	safe_free(*buf);		/* delete item */
	(*buf) = NULL;
}

/*******************************************************************
 frees a memory buffer chain.  assumes that all items are malloced.
 ********************************************************************/
static void prs_free_chain(prs_struct **buf)
{
	if (buf == NULL)
		return;
	if ((*buf) == NULL)
		return;

	CHECK_STRUCT(*buf);
	if ((*buf)->next != NULL)
	{
		/* delete all other items in chain */
		prs_free_chain(&((*buf)->next));
	}
	prs_struct_free(buf);
}

/*******************************************************************
 frees a memory buffer.
 ********************************************************************/
void prs_free_data(prs_struct *buf)
{
	if (buf == NULL)
		return;

	if (buf->data != NULL)
	{
		CHECK_STRUCT(buf);
		/* delete data in this structure */
		/* prs_sma_region should realy already be initialised */
		sma_free(prs_sma_region, buf->data);
		buf->data = NULL;
	}
	buf->data_size = 0;
}

/*******************************************************************
 reallocate a memory buffer
********************************************************************/
BOOL prs_realloc_data(prs_struct *buf, size_t new_size)
{
	char *new_data;

	prs_sma_init();

	CHECK_STRUCT(buf);

	prs_debug_out(buf, "prs_realloc_data - before", 200);

	SMB_ASSERT(((ssize_t) new_size) >= 0);

	if (new_size == 0)
	{
		prs_free_data(buf);
		return True;
	}

	new_data = sma_realloc(prs_sma_region, buf->data, new_size);

	if (new_data != NULL)
	{
		if (new_size > buf->data_size)
		{
			memset(&new_data[buf->data_size], 0,
			       new_size - buf->data_size);
		}
		buf->data = new_data;
		buf->data_size = new_size;
	}
	else if (buf->data_size >= new_size)
	{
		DEBUG(3, ("prs_realloc_data: warning - "
			  "could not realloc to %d\n", new_size));
	}
	else
	{
		DEBUG(3, ("prs_realloc_data: error - "
			  "could not realloc to %d\n", new_size));

		prs_free_data(buf);
		buf->error = True;
		return False;
	}

	buf->end = buf->start + new_size;

	prs_debug_out(buf, "prs_realloc_data - after", 200);
	return True;
}

/*******************************************************************
 reallocate a memory buffer, retrospectively :-)
 ********************************************************************/
BOOL prs_grow_data(prs_struct *buf, BOOL io, int new_size, BOOL force_grow)
{
	if (buf == NULL)
	{
		return False;
	}

	CHECK_STRUCT(buf);

	if (new_size > buf->data_size)
	{
		if (!io || force_grow)
		{
			/* writing or forge realloc */
			return prs_realloc_data(buf, new_size);
		}
		else
		{
			/*
			 * reading, there is just not that much
			 * data in the buffer
			 */
			DEBUG(1, ("prs_grow_data: %d > %d\n",
				  new_size, buf->data_size));
			return False;
		}
	}
	return True;
}


/*******************************************************************
 add up the lengths of all sections.
 ********************************************************************/
uint32 prs_buf_len(const prs_struct *buf)
{
	int len = 0;
	CHECK_STRUCT(buf);
	while (buf != NULL)
	{
		len += buf->end - buf->start;
		buf = buf->next;
	}
	return len;
}

/*******************************************************************
 return the memory location specified by   may return NULL.
 ********************************************************************/
char *prs_data(const prs_struct *buf, uint32 offset)
{
	CHECK_STRUCT(buf);
	buf = prs_find(buf, offset);
	if (buf != NULL)
	{
		return &(buf->data[offset - buf->start]);
	}
	return NULL;
}


/*******************************************************************
 link one parsing structure to another
 ********************************************************************/
void prs_link(prs_struct *prev, prs_struct *ps, prs_struct *next)
{
	CHECK_STRUCT(ps);
	if (next != NULL)
	{
		CHECK_STRUCT(next);
	}
	if (prev != NULL)
	{
		CHECK_STRUCT(prev);
	}
	ps->start = prev != NULL ? prev->end : 0;
	ps->end = ps->start + ps->offset;

	ps->next = next;

	DEBUG(150, ("prs_link: start %d end %d\n", ps->start, ps->end));
}

/*******************************************************************
 align a pointer to a multiple of align_offset bytes.  looks like it
 will work for offsets of 0, 2 and 4...
 ********************************************************************/
BOOL prs_align(prs_struct *ps)
{
	int mod;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	mod = ps->offset & (ps->align - 1);
	if (ps->align != 0 && mod != 0)
	{
		ps->offset += ps->align - mod;
		if (!prs_grow(ps, ps->offset))
		{
			return False;
		}
	}
	return True;
}

/*******************************************************************
 attempt, if appropriate, to grow a data buffer.

 depends on the data stream mode (io)
 ********************************************************************/
BOOL prs_grow(prs_struct *ps, uint32 new_size)
{
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	return prs_grow_data(ps, ps->io, new_size, False);
}

/*******************************************************************
 lengthens a buffer by len bytes and copies data into it.
 ********************************************************************/
BOOL prs_append_data(prs_struct *ps, const char *data, int len)
{
	int prev_size = ps->data_size;
	int new_size = prev_size + len;
	char *to;

	DEBUG(200, ("prs_append_data: prev_size: %d new_size: %d\n",
		    prev_size, new_size));

	CHECK_STRUCT(ps);
	prs_realloc_data(ps, new_size);
	to = prs_data(ps, prev_size);

	if (to == NULL || ps->data_size != new_size)
	{
		return False;
	}
	memcpy(to, data, len);

	return True;
}

BOOL prs_add_data(prs_struct *ps, const char *data, int len)
{
	int prev_size;
	int new_size;
	char *to = NULL;

	ps->offset = 0;

	if (ps->data == NULL)
	{
		DEBUG(10, ("prs_add_data: new_size: %d\n", len));
		prs_init(ps, len, 4, True);
		prev_size = 0;
		new_size = len;
		if (ps->data == NULL)
		{
			return False;
		}
	}
	else
	{
		prev_size = ps->data_size;
		new_size = prev_size + len;
		DEBUG(10, ("prs_add_data: prev_size: %d new_size: %d\n",
			   prev_size, new_size));
		if (!prs_realloc_data(ps, new_size))
		{
			return False;
		}
	}

	DEBUG(10, ("ps->start: %d\n", ps->start));
	ps->start = 0x0;

	to = prs_data(ps, prev_size);
	if (to == NULL)
	{
		DEBUG(10, ("prs_add_data: data could not be found\n"));
		return False;
	}
	if (ps->data_size != new_size)
	{
		DEBUG(10, ("prs_add_data: ERROR: data used %d new_size %d\n",
			   ps->data_size, new_size));
		return False;
	}
	memcpy_zero(to, data, len);
	return True;
}

/*******************************************************************
 Change the struct type.
 ********************************************************************/

void prs_switch_type(prs_struct *ps, BOOL io)
{
	if ((ps->io ^ io) == True)
		ps->io = io;
}

/*******************************************************************
 Force a prs_struct to be dynamic even when its size is 0.
 ********************************************************************/

void prs_force_dynamic(prs_struct *ps)
{
}

/*******************************************************************
 Fetch the current offset (external interface).
 ********************************************************************/
uint32 prs_data_size(prs_struct *ps)
{
	return ps->data_size;
}

/*******************************************************************
 Fetch the current offset (external interface).
 ********************************************************************/
uint32 prs_offset(prs_struct *ps)
{
	return ps->offset;
}

/*******************************************************************
 Set the current offset (external interface).
 ********************************************************************/
BOOL prs_set_offset(prs_struct *ps, uint32 offset)
{
	if (offset <= ps->offset)
	{
		ps->offset = offset;
		return True;
	}

	if (!prs_grow(ps, offset))
	{
		return False;
	}

	ps->offset = offset;
	return True;
}

/*******************************************************************
 Delete the memory in a parse structure - if we own it.
 ********************************************************************/

void prs_mem_free(prs_struct *ps)
{
	prs_free_data(ps);
	ps->offset = 0;
}


/*******************************************************************
 Append some data from one parse_struct into another.
 ********************************************************************/

BOOL prs_append_some_prs_data(prs_struct *dst, prs_struct *src, int32 start,
			      uint32 len)
{
	char *src_data;

	/* 
	 * JFM:
	 * ok, it looks like shit. It smells like shit.
	 * summary: it's shit.
	 *
	 * I'm not proud of that code. I mae that ugly hack to
	 * a) not change luke's prs memory managment
	 * b) not change the spoolss parsing code
	 *
	 * mail me, call me, hit me before changing that piece of code.
	 */

	src_data = prs_data(src, start);
	if (start == 0)
	{
		prs_add_data(dst, src_data, len);
	}
	else
	{
		dst->data_size = 0;
		prs_add_data(dst, src_data, len);
	}

	dst->offset = dst->data_size;
	return True;
}

/*******************************************************************
 stream a uint8
 ********************************************************************/
BOOL _prs_uint8(char *name, prs_struct *ps, int depth, uint8 *data8)
{
	char *q;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	if (!prs_grow(ps, ps->offset + 1))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_uint8 error", 5);
		return False;
	}

	DBG_RW_CVAL(name, depth, ps->offset, ps->io, q, *data8);
	ps->offset += 1;

	return True;
}

/*******************************************************************
 stream a uint16
 ********************************************************************/
BOOL _prs_uint16(char *name, prs_struct *ps, int depth, uint16 *data16)
{
	char *q;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	if (!prs_grow(ps, ps->offset + 2))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_uint16 error", 5);
		return False;
	}

	DBG_RW_SVAL(name, depth, ps->offset, ps->io, ps->bigendian, q,
		    *data16);
	ps->offset += 2;

	return True;
}

/*******************************************************************
 hash a stream.
 ********************************************************************/
BOOL _prs_hash1(prs_struct *ps, uint32 offset, uint8 sess_key[16])
{
	char *q;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	q = prs_data(ps, ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_hash1 error", 5);
		return False;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("prs_hash1\n"));
	dump_data(100, sess_key, 16);
	dump_data(100, q, 68);
#endif
	SamOEMhash((uchar *) q, sess_key, 2);
#ifdef DEBUG_PASSWORD
	dump_data(100, q, 68);
#endif

	return True;
}

/*******************************************************************
 stream a uint32
 ********************************************************************/
BOOL _prs_uint32(char *name, prs_struct *ps, int depth, uint32 *data32)
{
	char *q;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	if (!prs_grow(ps, ps->offset + 4))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	if (q == NULL)
	{
		fstring str;
		slprintf(str, sizeof(str) - 1, "_prs_uint32 error (%s)",
			 name);
		ps->error = True;
		prs_debug_out(ps, str, 5);
		return False;
	}

	DBG_RW_IVAL(name, depth, ps->offset, ps->io, ps->bigendian, q,
		    *data32);
	ps->offset += 4;

	return True;
}


/******************************************************************
 stream an array of uint8s.  length is number of uint8s
 ********************************************************************/
BOOL _prs_uint8s(BOOL charmode, char *name, prs_struct *ps, int depth,
		 uint8 *data8s, int len)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);

	if (len == 0)
	{
		return True;
	}

	if (ps->error)
		return False;
	end_offset = ps->offset + len * sizeof(uint8);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_uint8s error", 5);
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, data8s,
		     len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream an array of uint16s.  length is number of uint16s
 ********************************************************************/
BOOL _prs_uint16s(BOOL charmode, char *name, prs_struct *ps, int depth,
		  uint16 *data16s, int len)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (len == 0)
	{
		return True;
	}

	end_offset = ps->offset + len * sizeof(uint16);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_uint16s error", 5);
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, ps->bigendian,
		     q, data16s, len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream an array of uint32s.  length is number of uint32s
 ********************************************************************/
BOOL _prs_uint32s(BOOL charmode, char *name, prs_struct *ps, int depth,
		  uint32 *data32s, int len)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (len == 0)
	{
		return True;
	}

	end_offset = ps->offset + len * sizeof(uint32);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_uint32s error", 5);
		return False;
	}

	DBG_RW_PIVAL(charmode, name, depth, ps->offset, ps->io, ps->bigendian,
		     q, data32s, len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a "not" unicode string, length/buffer specified separately,
 in byte chars
 ********************************************************************/
BOOL _prs_buffer2(BOOL charmode, char *name, prs_struct *ps, int depth,
		  BUFFER2 * str)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (str->buf_len == 0)
	{
		return True;
	}

	end_offset = ps->offset + str->buf_len * sizeof(uint8);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_buffer2 error", 5);
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q,
		     str->buffer, str->buf_len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a string, length/buffer specified separately,
 in uint8 chars.
 ********************************************************************/
BOOL _prs_string2(BOOL charmode, char *name, prs_struct *ps, int depth,
		  STRING2 * str)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (str->str_str_len == 0)
	{
		return True;
	}

	end_offset = ps->offset + str->str_str_len * sizeof(uint8);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_string2 error", 5);
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q,
		     str->buffer, str->str_str_len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL _prs_unistr2(BOOL charmode, char *name, prs_struct *ps, int depth,
		  UNISTR2 *str)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (str->uni_str_len == 0)
	{
		return True;
	}

	end_offset = ps->offset + str->uni_str_len * sizeof(uint16);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_unistr2 error", 5);
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, ps->bigendian,
		     q, str->buffer, str->uni_str_len);
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL _prs_unistr3(BOOL charmode, char *name, UNISTR3 * str, prs_struct *ps,
		  int depth)
{
	char *q;
	int end_offset;
	char *e;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	if (str->uni_str_len == 0)
	{
		return True;
	}

	end_offset = ps->offset + str->uni_str_len * sizeof(uint16);
	if (!prs_grow(ps, end_offset))
	{
		return False;
	}
	q = prs_data(ps, ps->offset);
	e = prs_data(ps, end_offset - 1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		prs_debug_out(ps, "_prs_unistr3 error", 5);
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, ps->bigendian,
		     q, str->str.buffer, str->uni_str_len);
	ps->offset = end_offset;

	return True;
}

/*******************************************************************
 stream a unicode  null-terminated string
 ********************************************************************/
BOOL _prs_unistr(char *name, prs_struct *ps, int depth, UNISTR * str)
{
	int i = -1;
	uint8 *start;
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	start = (uint8 *)prs_data(ps, ps->offset);

	do
	{
		char *q;
		i++;
		if (!prs_grow(ps, ps->offset + (i + 1) * 2))
		{
			return False;
		}
		q = prs_data(ps, ps->offset + i * 2);
		if (q == NULL)
		{
			ps->error = True;
			prs_debug_out(ps, "_prs_unistr error", 5);
			return False;
		}
		RW_SVAL(ps->io, ps->bigendian, q, str->buffer[i], 0);
	}
	while ((((size_t) i) < sizeof(str->buffer) / sizeof(str->buffer[0]))
	       && (str->buffer[i] != 0));


	ps->offset += (i + 1) * 2;

	dump_data(5 + depth, (char *)start, i * 2);

	return True;
}

/*******************************************************************
 stream a null-terminated string.  len is strlen, and therefore does
 not include the null-termination character.

 len == 0 indicates variable length string
 (up to max size of pstring - 1024 chars).

 ********************************************************************/
BOOL _prs_string(char *name, prs_struct *ps, int depth, char *str,
		 uint16 len, uint16 max_buf_size)
{
	int i = -1;		/* start off at zero after 1st i++ */
	BOOL len_limited;

	CHECK_STRUCT(ps);
	if (ps->error)
		return False;

	len_limited = len == 0 || !ps->io;

	DEBUG(200, ("_prs_string: string %s len %d max %d\n",
		    str, len, max_buf_size));

	DEBUG(5 + depth,
	      ("%s%04x %s: ", tab_depth(depth), ps->offset,
	       name != NULL ? name : ""));
	do
	{
		char *q;
		i++;

		if (!prs_grow(ps, ps->offset + i + 1))
		{
			return False;
		}
		q = prs_data(ps, ps->offset + i);
		if (q == NULL)
		{
			ps->error = True;
			DEBUG(5 + depth, ("%s\n", str));
			prs_debug_out(ps, "_prs_string error", 5);
			return False;
		}

		if (i < len || len_limited)
		{
			RW_CVAL(ps->io, q, str[i], 0);
		}
		else
		{
			uint8 dummy = 0;
			RW_CVAL(ps->io, q, dummy, 0);
		}

	}
	while (i < max_buf_size && (len_limited ? str[i] != 0 : i < len));

	ps->offset += i + 1;

	DEBUG(5 + depth, ("%s\n", str));

	return True;
}

/*******************************************************************
 prs_uint16 wrapper.  call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading
 ********************************************************************/
BOOL _prs_uint16_pre(char *name, prs_struct *ps, int depth, uint16 *data16,
		     uint32 *offset)
{
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	(*offset) = ps->offset;
	if (ps->io)
	{
		/* reading. */
		return _prs_uint16(name, ps, depth, data16);
	}
	else
	{
		ps->offset += sizeof(uint16);
	}
	return True;
}

/*******************************************************************
 prs_uint16 wrapper.  call this and it retrospectively stores the size.
 does nothing on reading, as that is already handled by ...._pre()
 ********************************************************************/
BOOL _prs_uint16_post(char *name, prs_struct *ps, int depth, uint16 *data16,
		      uint32 ptr_uint16, uint32 start_offset)
{
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	if (!ps->io)
	{
		/* storing: go back and do a retrospective job.  i hate this */
		uint16 data_size = ps->offset - start_offset;
		uint32 old_offset = ps->offset;

		ps->offset = ptr_uint16;
		prs_uint16(name, ps, depth, &data_size);
		ps->offset = old_offset;
	}
	else
	{
		ps->offset = start_offset + (*data16);
	}
	return True;
}

/*******************************************************************
 prs_uint32 wrapper.  call this and it sets up a pointer to where the
 uint32 should be stored, or gets the size if reading
 ********************************************************************/
BOOL _prs_uint32_pre(char *name, prs_struct *ps, int depth, uint32 *data32,
		     uint32 *offset)
{
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	(*offset) = ps->offset;
	if (ps->io)
	{
		/* reading. */
		return _prs_uint32(name, ps, depth, data32);
	}
	else
	{
		ps->offset += sizeof(uint32);
	}
	return True;
}

/*******************************************************************
 prs_uint32 wrapper.  call this and it retrospectively stores the size.
 does nothing on reading, as that is already handled by ...._pre()
 ********************************************************************/
BOOL _prs_uint32_post(char *name, prs_struct *ps, int depth, uint32 *data32,
		      uint32 ptr_uint32, uint32 data_size)
{
	CHECK_STRUCT(ps);
	if (ps->error)
		return False;
	if (!ps->io)
	{
		/* storing: go back and do a retrospective job.  i hate this */
		uint32 old_offset = ps->offset;
		ps->offset = ptr_uint32;
		prs_uint32(name, ps, depth, &data_size);
		ps->offset = old_offset;
	}
	else
	{
		ps->offset = data_size + (*data32);
	}
	return True;
}

/*******************************************************************
 prs_tdb_store.  stores prs_struct data by prs_struct key 
 ********************************************************************/
int prs_tdb_delete(TDB_CONTEXT * tdb, prs_struct *pk)
{
	TDB_DATA key;

	key.dptr = (char *)prs_data(pk, 0);
	key.dsize = prs_buf_len(pk);

	return tdb_delete(tdb, key);
}

/*******************************************************************
 prs_tdb_store.  stores prs_struct data by prs_struct key 
 ********************************************************************/
int prs_tdb_store(TDB_CONTEXT * tdb, int flgs, prs_struct *pk, prs_struct *pd)
{
	TDB_DATA key;
	TDB_DATA data;

	key.dptr = (char *)prs_data(pk, 0);
	key.dsize = prs_buf_len(pk);

	data.dptr = prs_data(pd, 0);
	data.dsize = prs_buf_len(pd);

	return tdb_store(tdb, key, data, flgs);
}

/*******************************************************************
 prs_tdb_fetch.  fetches prs_struct data by prs_struct key 
 ********************************************************************/
void prs_tdb_fetch(TDB_CONTEXT * tdb, prs_struct *pk, prs_struct *pd)
{
	TDB_DATA key;
	TDB_DATA data;

	key.dptr = (char *)prs_data(pk, 0);
	key.dsize = prs_buf_len(pk);

	data = tdb_fetch(tdb, key);

	prs_create(pd, data.dptr, data.dsize, 4, True);
}


/* useful function to store a structure in rpc wire format */
int tdb_prs_store(TDB_CONTEXT *tdb, char *keystr, prs_struct *ps)
{
	TDB_DATA kbuf, dbuf;
	kbuf.dptr = keystr;
	kbuf.dsize = strlen(keystr)+1;
	dbuf.dptr = (char *)prs_data(ps, 0);
	dbuf.dsize = prs_buf_len(ps);

	return tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
}

/* useful function to fetch a structure into rpc wire format */
int tdb_prs_fetch(TDB_CONTEXT *tdb, char *keystr, prs_struct *ps)
{
	TDB_DATA kbuf, dbuf;
	kbuf.dptr = keystr;
	kbuf.dsize = strlen(keystr)+1;

	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr) return -1;

	ZERO_STRUCTP(ps);
	prs_create(ps, dbuf.dptr, dbuf.dsize, 4, UNMARSHALL);

	return 0;
}

