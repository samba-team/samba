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

extern int DEBUGLEVEL;

#include "includes.h"


/*******************************************************************
 debug output for parsing info.

 XXXX side-effect of this function is to increase the debug depth XXXX

 ********************************************************************/
void prs_debug(prs_struct *ps, int depth, char *desc, char *fn_name)
{
	DEBUG(5+depth, ("%s%06x %s %s\n", tab_depth(depth), ps->offset, fn_name, desc));
}

/*******************************************************************
 initialise a parse structure
 ********************************************************************/
void prs_init(prs_struct *ps, uint32 size,
				uint8 align, uint32 margin,
				BOOL io)
{
	ps->io = io;
	ps->align = align;
	ps->offset = 0;

	ps->data = NULL;
	mem_buf_init(&(ps->data), margin);

	if (size != 0)
	{
		mem_alloc_data(ps->data, size);
		ps->data->offset.start = 0;
		ps->data->offset.end   = 0xffffffff;
	}
}

/*******************************************************************
 initialise a parse structure
 ********************************************************************/
void prs_mem_free(prs_struct *ps)
{
	mem_buf_free(&(ps->data));
}

/*******************************************************************
 link one parsing structure to another
 ********************************************************************/
void prs_link(prs_struct *prev, prs_struct *ps, prs_struct *next)
{
	ps->data->offset.start = prev != NULL ? prev->data->offset.end : 0;
	ps->data->offset.end   = ps->data->offset.start + ps->offset;
	ps->data->next         = next != NULL ? next->data : NULL;
}

/*******************************************************************
 align a pointer to a multiple of align_offset bytes.  looks like it
 will work for offsets of 0, 2 and 4...
 ********************************************************************/
void prs_align(prs_struct *ps)
{
	int mod = ps->offset & (ps->align-1);
	if (ps->align != 0 && mod != 0)
	{
		ps->offset += ps->align - mod;
	}
}

/*******************************************************************
 attempt, if appropriate, to grow a data buffer.

 depends on the data stream mode (io)
 ********************************************************************/
BOOL prs_grow(prs_struct *ps)
{
	return mem_grow_data(&(ps->data), ps->io, ps->offset, False);
}


/*******************************************************************
 stream a uint8
 ********************************************************************/
BOOL prs_uint8(char *name, prs_struct *ps, int depth, uint8 *data8)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_CVAL(name, depth, ps->offset, ps->io, q, *data8)
	ps->offset += 1;

	return True;
}

/*******************************************************************
 stream a uint16
 ********************************************************************/
BOOL prs_uint16(char *name, prs_struct *ps, int depth, uint16 *data16)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_SVAL(name, depth, ps->offset, ps->io, q, *data16)
	ps->offset += 2;

	return True;
}

/*******************************************************************
 stream a uint32
 ********************************************************************/
BOOL prs_uint32(char *name, prs_struct *ps, int depth, uint32 *data32)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_IVAL(name, depth, ps->offset, ps->io, q, *data32)
	ps->offset += 4;

	return True;
}


/******************************************************************
 stream an array of uint8s.  length is number of uint8s
 ********************************************************************/
BOOL prs_uint8s(BOOL charmode, char *name, prs_struct *ps, int depth, uint8 *data8s, int len)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, data8s, len)
	ps->offset += len;

	return True;
}

/******************************************************************
 stream an array of uint16s.  length is number of uint16s
 ********************************************************************/
BOOL prs_uint16s(BOOL charmode, char *name, prs_struct *ps, int depth, uint16 *data16s, int len)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, data16s, len)
	ps->offset += len * sizeof(uint16);

	return True;
}

/******************************************************************
 stream an array of uint32s.  length is number of uint32s
 ********************************************************************/
BOOL prs_uint32s(BOOL charmode, char *name, prs_struct *ps, int depth, uint32 *data32s, int len)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PIVAL(charmode, name, depth, ps->offset, ps->io, q, data32s, len)
	ps->offset += len * sizeof(uint32);

	return True;
}

/******************************************************************
 stream a "not" unicode string, length/buffer specified separately,
 in byte chars
 ********************************************************************/
BOOL prs_buffer2(BOOL charmode, char *name, prs_struct *ps, int depth, BUFFER2 *str)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->buf_len)
	ps->offset += str->buf_len;

	return True;
}

/******************************************************************
 stream a string, length/buffer specified separately,
 in uint8 chars.
 ********************************************************************/
BOOL prs_string2(BOOL charmode, char *name, prs_struct *ps, int depth, STRING2 *str)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->str_max_len)
	ps->offset += str->str_str_len * sizeof(uint8);

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL prs_unistr2(BOOL charmode, char *name, prs_struct *ps, int depth, UNISTR2 *str)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->uni_str_len)
	ps->offset += str->uni_str_len * sizeof(uint16);

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL prs_unistr3(BOOL charmode, char *name, UNISTR3 *str, prs_struct *ps, int depth)
{
	char *q = mem_data(&(ps->data), ps->offset);
	if (q == NULL) return False;

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, str->str.buffer, str->uni_str_len)
	ps->offset += str->uni_str_len * sizeof(uint16);

	return True;
}

/*******************************************************************
 stream a unicode  null-terminated string
 ********************************************************************/
BOOL prs_unistr(char *name, prs_struct *ps, int depth, UNISTR *str)
{
	char *q = mem_data(&(ps->data), ps->offset);
	int i = -1;
	uint8 *start = (uint8*)q;

	if (q == NULL) return False;

	do
	{
		i++;
		RW_SVAL(ps->io, q, str->buffer[i],0);
		q += 2;
	}
	while ((i < sizeof(str->buffer) / sizeof(str->buffer[0])) &&
		     (str->buffer[i] != 0));


	ps->offset += (i+1)*2;

	dump_data(5+depth, (char *)start, i * 2);

	return True;
}

/*******************************************************************
 stream a null-terminated string.  len is strlen, and therefore does
 not include the null-termination character.

 len == 0 indicates variable length string
 (up to max size of pstring - 1024 chars).

 ********************************************************************/
BOOL prs_string(char *name, prs_struct *ps, int depth, char *str, uint16 len, uint16 max_buf_size)
{
	char *q = mem_data(&(ps->data), ps->offset);
	uint8 *start = (uint8*)q;
	int i = -1; /* start off at zero after 1st i++ */

	if (q == NULL) return False;

	do
	{
		i++;

		if (i < len || len == 0)
		{
			RW_CVAL(ps->io, q, str[i],0);
		}
		else
		{
			uint8 dummy = 0;
			RW_CVAL(ps->io, q, dummy,0);
		}

		q++;

	} while (i < max_buf_size && (len == 0 ? str[i] != 0 : i < len) );

	ps->offset += i+1;

	dump_data(5+depth, (char *)start, i);

	return True;
}

/*******************************************************************
 prs_uint16 wrapper.  call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading
 ********************************************************************/
BOOL prs_uint16_pre(char *name, prs_struct *ps, int depth, uint16 *data16, uint32 *offset)
{
	(*offset) = ps->offset;
	if (ps->io)
	{
		/* reading. */
		return prs_uint16(name, ps, depth, data16);
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
BOOL prs_uint16_post(char *name, prs_struct *ps, int depth, uint16 *data16,
				uint32 ptr_uint16, uint32 start_offset)
{
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
BOOL prs_uint32_pre(char *name, prs_struct *ps, int depth, uint32 *data32, uint32 *offset)
{
	(*offset) = ps->offset;
	if (ps->io)
	{
		/* reading. */
		return prs_uint32(name, ps, depth, data32);
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
BOOL prs_uint32_post(char *name, prs_struct *ps, int depth, uint32 *data32,
				uint32 ptr_uint32, uint32 data_size)
{
	if (!ps->io)
	{
		/* storing: go back and do a retrospective job.  i hate this */
		uint32 old_offset = ps->offset;
		ps->offset = ptr_uint32;
		prs_uint32(name, ps, depth, &data_size);
		ps->offset = old_offset;
	}
	return True;
}

