/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba memory buffer functions
   Copyright (C) Andrew Tridgell              1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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
 debug a parse structure
 ********************************************************************/
void prs_debug_out(prs_struct *ps, int level)
{
	DEBUG(level,("ps: io %s align %d offset %d err %d data %p len %d\n",
		BOOLSTR(ps->io), ps->align, ps->offset, ps->error, ps->data,
		ps->data != NULL ? mem_buf_len(ps->data) : 0));
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
	ps->error = False;

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
	int mod;
	if (ps->error) return;
	mod = ps->offset & (ps->align-1);
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
	if (ps->error) return False;
	return mem_grow_data(&(ps->data), ps->io, ps->offset, False);
}


/*******************************************************************
 stream a uint8
 ********************************************************************/
BOOL _prs_uint8(char *name, prs_struct *ps, int depth, uint8 *data8)
{
	char *q;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_CVAL(name, depth, ps->offset, ps->io, q, *data8)
	ps->offset += 1;

	return True;
}

/*******************************************************************
 stream a uint16
 ********************************************************************/
BOOL _prs_uint16(char *name, prs_struct *ps, int depth, uint16 *data16)
{
	char *q;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_SVAL(name, depth, ps->offset, ps->io, q, *data16)
	ps->offset += 2;

	return True;
}

/*******************************************************************
 hash a stream.
 ********************************************************************/
BOOL _prs_hash1(prs_struct *ps, uint32 offset, uint8 sess_key[16])
{
	char *q;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		return False;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("prs_hash1\n"));
	dump_data(100, sess_key, 16);
	dump_data(100, q, 68);
#endif
	SamOEMhash((uchar*)q, sess_key, 2);
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
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	if (q == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_IVAL(name, depth, ps->offset, ps->io, q, *data32)
	ps->offset += 4;

	return True;
}


/******************************************************************
 stream an array of uint8s.  length is number of uint8s
 ********************************************************************/
BOOL _prs_uint8s(BOOL charmode, char *name, prs_struct *ps, int depth, uint8 *data8s, int len)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + len * sizeof(uint8);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL) 
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, data8s, len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream an array of uint16s.  length is number of uint16s
 ********************************************************************/
BOOL _prs_uint16s(BOOL charmode, char *name, prs_struct *ps, int depth, uint16 *data16s, int len)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + len * sizeof(uint16);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, data16s, len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream an array of uint32s.  length is number of uint32s
 ********************************************************************/
BOOL _prs_uint32s(BOOL charmode, char *name, prs_struct *ps, int depth, uint32 *data32s, int len)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + len * sizeof(uint32);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PIVAL(charmode, name, depth, ps->offset, ps->io, q, data32s, len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a "not" unicode string, length/buffer specified separately,
 in byte chars
 ********************************************************************/
BOOL _prs_buffer2(BOOL charmode, char *name, prs_struct *ps, int depth, BUFFER2 *str)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + str->buf_len;
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->buf_len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a string, length/buffer specified separately,
 in uint8 chars.
 ********************************************************************/
BOOL _prs_string2(BOOL charmode, char *name, prs_struct *ps, int depth, STRING2 *str)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + str->str_str_len * sizeof(uint8);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PCVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->str_max_len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL _prs_unistr2(BOOL charmode, char *name, prs_struct *ps, int depth, UNISTR2 *str)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + str->uni_str_len * sizeof(uint16);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, str->buffer, str->uni_str_len)
	ps->offset = end_offset;

	return True;
}

/******************************************************************
 stream a unicode string, length/buffer specified separately,
 in uint16 chars.
 ********************************************************************/
BOOL _prs_unistr3(BOOL charmode, char *name, UNISTR3 *str, prs_struct *ps, int depth)
{
	char *q;
	int end_offset;
	char *e;
	if (ps->error) return False;
	q = mem_data(&(ps->data), ps->offset);
	end_offset = ps->offset + str->uni_str_len * sizeof(uint16);
	e = mem_data(&(ps->data), end_offset-1);

	if (q == NULL || e == NULL)
	{
		ps->error = True;
		return False;
	}

	DBG_RW_PSVAL(charmode, name, depth, ps->offset, ps->io, q, str->str.buffer, str->uni_str_len)
	ps->offset = end_offset;

	return True;
}

/*******************************************************************
 stream a unicode  null-terminated string
 ********************************************************************/
BOOL _prs_unistr(char *name, prs_struct *ps, int depth, UNISTR *str)
{
	int i = -1;
	uint8 *start;
	if (ps->error) return False;
	start = (uint8*)mem_data(&(ps->data), ps->offset);

	do
	{
		char *q;
		i++;
		q = mem_data(&(ps->data), ps->offset + i*2);
		if (q == NULL) 
		{
			ps->error = True;
			return False;
		}
		RW_SVAL(ps->io, q, str->buffer[i],0);
	}
	while ((((size_t)i) < sizeof(str->buffer) / sizeof(str->buffer[0])) &&
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
BOOL _prs_string(char *name, prs_struct *ps, int depth, char *str, uint16 len, uint16 max_buf_size)
{
	int i = -1; /* start off at zero after 1st i++ */
	uint8 *start;
	if (ps->error) return False;
	start = (uint8*)mem_data(&(ps->data), ps->offset);

	DEBUG(120,("_prs_string: string %s len %d max %d\n",
			str, len, max_buf_size));

	do
	{
		char *q;
		i++;

		q = mem_data(&(ps->data), ps->offset + i);
		if (q == NULL)
		{
			ps->error = True;
			return False;
		}

		if (i < len || len == 0)
		{
			RW_CVAL(ps->io, q, str[i], 0);
		}
		else
		{
			uint8 dummy = 0;
			RW_CVAL(ps->io, q, dummy,0);
		}

	} while (i < max_buf_size && (len == 0 ? str[i] != 0 : i < len) );

	DEBUG(120,("_prs_string: string %s len %d max %d\n",
			str, len, max_buf_size));

	ps->offset += i+1;

	dump_data(5+depth, (char *)start, i);

	return True;
}

/*******************************************************************
 prs_uint16 wrapper.  call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading
 ********************************************************************/
BOOL _prs_uint16_pre(char *name, prs_struct *ps, int depth, uint16 *data16, uint32 *offset)
{
	if (ps->error) return False;
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
	if (ps->error) return False;
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
BOOL _prs_uint32_pre(char *name, prs_struct *ps, int depth, uint32 *data32, uint32 *offset)
{
	if (ps->error) return False;
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
	if (ps->error) return False;
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

