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

#include "includes.h"

extern int DEBUGLEVEL;

/*******************************************************************
 initialise a memory buffer.
 ********************************************************************/
void buf_init(struct mem_buffer *buf, int align, int margin)
{
	buf->data      = NULL;
	buf->data_size = 0;
	buf->data_used = 0;
	buf->align     = align;
	buf->margin    = margin;
}

/*******************************************************************
 initialise a memory buffer.
 ********************************************************************/
void buf_create(struct mem_buffer *buf, char *data, int size, int align, int margin)
{
	buf->data      = data;
	buf->data_size = size;
	buf->data_used = size;
	buf->align     = align;
	buf->margin    = margin;
}

/*******************************************************************
 allocate a memory buffer.  assume it's empty
 ********************************************************************/
BOOL buf_alloc(struct mem_buffer *buf, int size)
{
	buf->data_size = size + buf->margin;
	buf->data_used = size;

	buf->data = malloc(buf->data_size);

	if (buf->data == NULL)
	{
		DEBUG(3,("buf_alloc: could not malloc size %d\n",
					  buf->data_size));
		buf->data_size = 0;
		buf->data_used = 0;

		return False;
	}

	bzero(buf->data, buf->data_size);

	return True;
}

/*******************************************************************
 takes a memory buffer out of one structure: puts it in the other.
 NULLs the one that the buffer is being stolen from.
 ********************************************************************/
void buf_take(struct mem_buffer *buf_to, struct mem_buffer *buf_from)
{
	buf_to  ->data      = buf_from->data     ;
	buf_to  ->data_size = buf_from->data_size;
	buf_to  ->data_used = buf_from->data_used;

	buf_init(buf_from, buf_from->align, buf_from->margin);
}

/*******************************************************************
 frees a memory buffer.
 ********************************************************************/
void buf_free(struct mem_buffer *buf)
{
	if (buf->data != NULL)
	{
		free(buf->data);
	}
	buf_init(buf, buf->align, buf->margin);
}

/*******************************************************************
 reallocate a memory buffer, including a safety margin
 ********************************************************************/
BOOL buf_realloc(struct mem_buffer *buf, int new_size)
{
	/* hm.  maybe we want to align the data size here... */
	char *new_data = realloc(buf->data, new_size + buf->margin);

	if (new_data != NULL)
	{
		buf->data = new_data;
		buf->data_size = new_size + buf->margin;
		buf->data_used = new_size;
	}
	else if (buf->data_size <= new_size)
	{
		DEBUG(3,("buf_realloc: warning - could not realloc to %d(+%d)\n",
				  new_size, buf->margin));

		buf->data_used = new_size;
	}
	else 
	{
		DEBUG(3,("buf_realloc: error - could not realloc to %d\n",
				  new_size));

		buf_free(buf);
		return False;
	}

	return True;
}

/*******************************************************************
 reallocate a memory buffer, retrospectively :-)
 ********************************************************************/
void buf_grow(struct mem_buffer *buf, int new_size)
{
	if (new_size + buf->margin >= buf->data_size)
	{
		buf_realloc(buf, new_size);
	}
}

/*******************************************************************
align a pointer to a multiple of align_offset bytes.  looks like it
will work for offsets of 0, 2 and 4...
********************************************************************/
void buf_align(struct mem_buffer *buf, int *data_off)
{
	int mod = ((*data_off) & (buf->align-1));
	if (buf->align != 0 && mod != 0)
	{
		(*data_off) += buf->align - mod;
	}
}

/*******************************************************************
 stream a uint8
 ********************************************************************/
void buf_uint8(char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint8 *data)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_CVAL(name, depth, buf->data, io, q, *data)
	(*data_off) += 1;
}

/*******************************************************************
 stream a uint16
 ********************************************************************/
void buf_uint16(char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint16 *data)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_SVAL(name, depth, buf->data, io, q, *data)
	(*data_off) += 2;
}

/*******************************************************************
 stream a uint32
 ********************************************************************/
void buf_uint32(char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint32 *data)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_IVAL(name, depth, buf->data, io, q, *data)
	(*data_off) += 4;
}


/******************************************************************
 stream an array of uint8s.  length is number of uint8s
 ********************************************************************/
void buf_uint8s(BOOL charmode, char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint8 *data, int len)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_PCVAL(charmode, name, depth, buf->data, io, q, data, len)
	(*data_off) += len;
}

/******************************************************************
 stream an array of uint16s.  length is number of uint16s
 ********************************************************************/
void buf_uint16s(BOOL charmode, char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint16 *data, int len)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_PSVAL(charmode, name, depth, buf->data, io, q, data, len)
	(*data_off) += len * sizeof(uint16);
}

/******************************************************************
 stream an array of uint32s.  length is number of uint32s
 ********************************************************************/
void buf_uint32s(BOOL charmode, char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, uint32 *data, int len)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_PIVAL(charmode, name, depth, buf->data, io, q, data, len)
	(*data_off) += len * sizeof(uint32);
}

/******************************************************************
 stream a "not" unicode string, length/buffer specified separately,
 in byte chars
 ********************************************************************/
void buf_uninotstr2(BOOL charmode, char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, UNINOTSTR2 *str)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_PSVAL(charmode, name, depth, buf->data, io, q, str->buffer, str->uni_max_len)
	(*data_off) += str->uni_buf_len;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 int uint16 chars.
 ********************************************************************/
void buf_unistr2(BOOL charmode, char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, UNISTR2 *str)
{
	char *q = &(buf->data[(*data_off)]);
	DBG_RW_PSVAL(charmode, name, depth, buf->data, io, q, str->buffer, str->uni_max_len)
	(*data_off) += str->uni_str_len * sizeof(uint16);
}

/*******************************************************************
 stream a unicode  null-terminated string
 ********************************************************************/
void buf_unistr(char *name, int depth, struct mem_buffer *buf, int *data_off, BOOL io, UNISTR *str)
{
	int i = 0;
	char *ptr = buf->data;
	char *start = ptr;

	do 
	{
		RW_SVAL(io, ptr, str->buffer[i], 0);
		ptr += 2;
		i++;

	} while ((i < sizeof(str->buffer) / sizeof(str->buffer[0])) &&
		     (str->buffer[i] != 0));

	(*data_off) += i*2;

	dump_data(5+depth, start, (*data_off));
}
