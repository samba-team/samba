/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba memory buffer functions
   Copyright (C) Andrew Tridgell              1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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

/*******************************************************************
 *
 * Description: memory buffer / stream management.
 * Author     : Luke K C Leighton
 * Created    : Dec 1997
 *

 * this module is intended for use in streaming data in and out of
 * buffers.  it is intended that a single data stream be subdivided
 * into manageable sections.

 * for example, an rpc header contains a length field, but until the
 * data has been created, the length is unknown.  using this module,
 * the header section can be tacked onto the front of the data memory
 * list once the size of the data section preceding it is known.
 
 * the "margin" can be used to over-run and retrospectively lengthen
 * the buffer.  this is to save time in some of the loops, where it is
 * not particularly desirable to realloc data by 1, 2 or 4 bytes
 * repetitively...

 * each memory buffer contains a start and end offset.  the end of
 * one buffer should equal to the start of the next in the chain.
 * (end - start = len, instead of end - start + 1 = len)

 * the debug log levels are very high in some of the routines: you
 * have no idea how boring it gets staring at debug output from these

 ********************************************************************/


#include "includes.h"

extern int DEBUGLEVEL;

/*******************************************************************
 initialise a memory buffer.
 ********************************************************************/
void mem_init(struct mem_buf *buf, int margin)
{
	buf->struct_start = 0xfefefefe;
	buf->dynamic   = True;
	buf->data      = NULL;
	buf->data_size = 0;
	buf->data_used = 0;

	buf->margin    = margin;

	buf->next      = NULL;

	buf->offset.start = 0;
	buf->offset.end   = 0x0;
	buf->struct_end = 0xdcdcdcdc;
	CHECK_STRUCT(buf);
}

/*******************************************************************
 initialise a memory buffer.

 dynamic indicates memory has been dynamically allocated.
 if mem_free is called, the memory will be freed.
 ********************************************************************/
void mem_create(struct mem_buf *buf, char *data, int offset, int size, int margin, BOOL dynamic)
{
	buf->struct_start = 0xfefefefe;
	buf->dynamic   = dynamic;
	buf->data      = data;
	buf->data_size = size;
	buf->data_used = size;

	buf->margin    = margin;

	buf->next      = NULL;

	buf->offset.start = offset;
	buf->offset.end   = offset + size;
	buf->struct_end = 0xdcdcdcdc;
	CHECK_STRUCT(buf);
}

/*******************************************************************
 allocate a memory buffer.  assume it's empty
 ********************************************************************/
BOOL mem_alloc_data(struct mem_buf *buf, int size)
{
	CHECK_STRUCT(buf);
	if (!buf->dynamic)
	{
		DEBUG(3,("mem_alloc_data: warning - memory buffer type is set to static\n"));
	}

	buf->data_size = size + buf->margin;
	buf->data_used = size;

	buf->data = (char*)malloc(buf->data_size);

	if (buf->data == NULL && size != 0)
	{
		DEBUG(3,("mem_alloc: could not malloc size %d\n",
					  buf->data_size));
		mem_init(buf, buf->margin);

		return False;
	}

	bzero(buf->data, buf->data_size);
	buf->offset.end   = buf->offset.start + size;

	CHECK_STRUCT(buf);
	return True;
}

/*******************************************************************
 search for a memory buffer that falls within the specified offset
 ********************************************************************/
static struct mem_buf *mem_find(struct mem_buf *buf, uint32 offset)
{
	struct mem_buf *f;
	if (buf == NULL) return False;

	f = buf;

	CHECK_STRUCT(f);
	DEBUG(200,("mem_find: data[%d..%d] offset: %d\n",
	      f->offset.start, f->offset.end, offset));

	while (f != NULL && offset >= f->offset.end)
	{
		DEBUG(200,("mem_find: next[%d..%d]\n",
	      		f->offset.start, f->offset.end));

		f = f->next;
	}

	if (f != NULL)
	{
		DEBUG(200,("mem_find: found data[%d..%d]\n",
		      f->offset.start, f->offset.end));
	}

	return f;
}

/*******************************************************************
 allocates a memory buffer structure
 ********************************************************************/
BOOL mem_buf_copy(char *copy_into, struct mem_buf *buf,
				uint32 offset, uint32 len)
{
	uint32 end = offset + len;
	char *q = NULL;
	uint32 data_len = mem_buf_len(buf);
	uint32 start_offset = offset;
	struct mem_buf *bcp = buf;
	
	if (buf == NULL || copy_into == NULL) return False;

	CHECK_STRUCT(buf);
	DEBUG(200,("mem_buf_copy: data[%d..%d] offset %d len %d\n",
	            buf->offset.start, data_len, offset, len));

	/* there's probably an off-by-one bug, here, and i haven't even tested the code :-) */
	while (offset < end && ((q = mem_data(bcp, offset)) != NULL))
	{
		uint32 copy_len;
		bcp = mem_find(bcp, offset);
		copy_len = bcp->offset.end - offset;

		DEBUG(200,("\tdata[%d..%d] - offset %d len %d\n",
		        bcp->offset.start, bcp->offset.end,
		        offset, copy_len));

		memcpy(copy_into, q, copy_len);
	
		offset    += copy_len;
		copy_into += copy_len;
	}

	if (bcp != NULL)
	{
		DEBUG(200,("mem_buf_copy: copied %d bytes\n", offset - start_offset));
	}
	else
	{
		DEBUG(200,("mem_buf_copy: failed\n"));
	}

	return buf != NULL;
}

/*******************************************************************
 allocates a memory buffer structure
 ********************************************************************/
BOOL mem_buf_init(struct mem_buf **buf, uint32 margin)
{
	if (buf == NULL) return False;

	if ((*buf) == NULL)
	{
		(*buf) = (struct mem_buf*)malloc(sizeof(**buf));
		if ((*buf) != NULL) 
		{
			mem_init((*buf), margin);
			return True;
		}
	}
	else
	{
		CHECK_STRUCT(*buf);
		(*buf)->margin = margin;
		return True;
	}
	return False;
}

/*******************************************************************
 frees up a memory buffer.
 ********************************************************************/
void mem_buf_free(struct mem_buf **buf)
{
	if (buf == NULL) return;
	if ((*buf) == NULL) return;

	CHECK_STRUCT(*buf);
	mem_free_data(*buf);            /* delete memory data */
	free(*buf);                     /* delete item */
	(*buf) = NULL;
}

/*******************************************************************
 frees a memory buffer chain.  assumes that all items are malloced.
 ********************************************************************/
static void mem_free_chain(struct mem_buf **buf)
{
	if (buf == NULL) return;
	if ((*buf) == NULL) return;

	CHECK_STRUCT(*buf);
	if ((*buf)->next != NULL)
	{
		mem_free_chain(&((*buf)->next)); /* delete all other items in chain */
	}
	mem_buf_free(buf);
}

/*******************************************************************
 frees a memory buffer.
 ********************************************************************/
void mem_free_data(struct mem_buf *buf)
{
	if (buf == NULL) return;

	if (buf->data != NULL && buf->dynamic)
	{
		CHECK_STRUCT(buf);
		free(buf->data);     /* delete data in this structure */
		buf->data = NULL;
	}
	mem_init(buf, buf->margin);
}

/*******************************************************************
 reallocate a memory buffer, including a safety margin
 ********************************************************************/
BOOL mem_realloc_data(struct mem_buf *buf, size_t new_size)
{
	char *new_data;

	CHECK_STRUCT(buf);
	if (!buf->dynamic)
	{
		DEBUG(3,("mem_realloc_data: memory buffer has not been dynamically allocated!\n"));
		sleep(30);
		return False;
	}

	if (new_size == 0)
	{
		mem_free_data(buf);
		return True;
	}

	new_data = (char*)Realloc(buf->data, new_size + buf->margin);

	if (new_data != NULL)
	{
		buf->data = new_data;
		buf->data_size = new_size + buf->margin;
		buf->data_used = new_size;
	}
	else if (buf->data_size <= new_size)
	{
		DEBUG(3,("mem_realloc: warning - could not realloc to %d(+%d)\n",
				  new_size, buf->margin));

		buf->data_used = new_size;
	}
	else 
	{
		DEBUG(3,("mem_realloc: error - could not realloc to %d\n",
				  new_size));

		mem_free_data(buf);
		return False;
	}

	buf->offset.end   = buf->offset.start + new_size;

	DEBUG(150,("mem_realloc_data: size: %d start: %d end: %d\n",
				new_size, buf->offset.start, buf->offset.end));
	return True;
}

/*******************************************************************
 reallocate a memory buffer, retrospectively :-)
 ********************************************************************/
BOOL mem_grow_data(struct mem_buf **buf, BOOL io, int new_size, BOOL force_grow)
{
	if (buf == NULL || ((*buf) == NULL))
	{
		return False;
	}

	CHECK_STRUCT(*buf);

	if (new_size + (*buf)->margin >= (*buf)->data_size)
	{
		if (!io || force_grow)
		{
			/* writing or forge realloc */
			return mem_realloc_data((*buf), new_size);
		}
		else
		{
		}
	}
	return True;
}


/*******************************************************************
 add up the lengths of all sections.
 ********************************************************************/
uint32 mem_buf_len(struct mem_buf *buf)
{
	int len = 0;
	CHECK_STRUCT(buf);
	while (buf != NULL)
	{
		len += buf->offset.end - buf->offset.start;
		buf = buf->next;
	}
	return len;
}


/*******************************************************************
 return the memory location specified by offset.  may return NULL.
 ********************************************************************/
char *mem_data(struct mem_buf *buf, uint32 offset)
{
	CHECK_STRUCT(buf);
	buf = mem_find(buf, offset);
	if (buf != NULL)
	{
		return &(buf->data[offset - buf->offset.start]);
	}
	return NULL;
}


