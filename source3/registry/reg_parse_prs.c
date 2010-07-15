/*
   Unix SMB/CIFS implementation.
   Samba memory buffer functions
   Copyright (C) Andrew Tridgell              1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Jeremy Allison               1999
   Copyright (C) Andrew Bartlett              2003.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "reg_parse_prs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Debug output for parsing info

 XXXX side-effect of this function is to increase the debug depth XXXX.

********************************************************************/

void prs_debug(prs_struct *ps, int depth, const char *desc, const char *fn_name)
{
	DEBUG(5+depth, ("%s%06x %s %s\n", tab_depth(5+depth,depth), ps->data_offset, fn_name, desc));
}

/**
 * Initialise an expandable parse structure.
 *
 * @param size Initial buffer size.  If >0, a new buffer will be
 * created with talloc().
 *
 * @return False if allocation fails, otherwise True.
 **/

bool prs_init(prs_struct *ps, uint32 size, TALLOC_CTX *ctx, bool io)
{
	ZERO_STRUCTP(ps);
	ps->io = io;
	ps->bigendian_data = RPC_LITTLE_ENDIAN;
	ps->align = RPC_PARSE_ALIGN;
	ps->is_dynamic = False;
	ps->data_offset = 0;
	ps->buffer_size = 0;
	ps->data_p = NULL;
	ps->mem_ctx = ctx;

	if (size != 0) {
		ps->buffer_size = size;
		ps->data_p = (char *)talloc_zero_size(ps->mem_ctx, size);
		if(ps->data_p == NULL) {
			DEBUG(0,("prs_init: talloc fail for %u bytes.\n", (unsigned int)size));
			return False;
		}
		ps->is_dynamic = True; /* We own this memory. */
	} else if (MARSHALLING(ps)) {
		/* If size is zero and we're marshalling we should allocate memory on demand. */
		ps->is_dynamic = True;
	}

	return True;
}

/*******************************************************************
 Delete the memory in a parse structure - if we own it.

 NOTE: Contrary to the somewhat confusing naming, this function is not
       intended for freeing memory allocated by prs_alloc_mem().
       That memory is also attached to the talloc context given by
       ps->mem_ctx, but is only freed when that talloc context is
       freed. prs_mem_free() is used to delete "dynamic" memory
       allocated in marshalling/unmarshalling.
 ********************************************************************/

void prs_mem_free(prs_struct *ps)
{
	if(ps->is_dynamic) {
		TALLOC_FREE(ps->data_p);
	}
	ps->is_dynamic = False;
	ps->buffer_size = 0;
	ps->data_offset = 0;
}

/*******************************************************************
 Clear the memory in a parse structure.
 ********************************************************************/

void prs_mem_clear(prs_struct *ps)
{
	if (ps->buffer_size)
		memset(ps->data_p, '\0', (size_t)ps->buffer_size);
}

/*******************************************************************
 Allocate memory when unmarshalling... Always zero clears.
 ********************************************************************/

#if defined(PARANOID_MALLOC_CHECKER)
char *prs_alloc_mem_(prs_struct *ps, size_t size, unsigned int count)
#else
char *prs_alloc_mem(prs_struct *ps, size_t size, unsigned int count)
#endif
{
	char *ret = NULL;

	if (size && count) {
		/* We can't call the type-safe version here. */
		ret = (char *)_talloc_zero_array(ps->mem_ctx, size, count,
						 "parse_prs");
	}
	return ret;
}

/*******************************************************************
 Return the current talloc context we're using.
 ********************************************************************/

TALLOC_CTX *prs_get_mem_context(prs_struct *ps)
{
	return ps->mem_ctx;
}

/*******************************************************************
 Hand some already allocated memory to a prs_struct.
 If "is_dynamic" is true, this is a talloc_steal.
 If "is_dynamic" is false, just make ps->data_p a pointer to
 the unwritable memory.
 ********************************************************************/

void prs_give_memory(prs_struct *ps, char *buf, uint32 size, bool is_dynamic)
{
	ps->is_dynamic = is_dynamic;
	if (ps->is_dynamic && buf) {
		talloc_steal(ps->mem_ctx, buf);
	}
	ps->data_p = buf;
	ps->buffer_size = size;
}

/*******************************************************************
 Set a prs_struct to exactly a given size. Will grow or tuncate if neccessary.
 ********************************************************************/

bool prs_set_buffer_size(prs_struct *ps, uint32 newsize)
{
	if (newsize > ps->buffer_size)
		return prs_force_grow(ps, newsize - ps->buffer_size);

	if (newsize < ps->buffer_size) {
		ps->buffer_size = newsize;

		/* newsize == 0 acts as a free and set pointer to NULL */
		if (newsize == 0) {
			TALLOC_FREE(ps->data_p);
		} else {
			ps->data_p = talloc_realloc(ps->mem_ctx,
						ps->data_p,
						char,
						newsize);

			if (ps->data_p == NULL) {
				DEBUG(0,("prs_set_buffer_size: Realloc failure for size %u.\n",
					(unsigned int)newsize));
				return False;
			}
		}
	}

	return True;
}

/*******************************************************************
 Attempt, if needed, to grow a data buffer.
 Also depends on the data stream mode (io).
 ********************************************************************/

bool prs_grow(prs_struct *ps, uint32 extra_space)
{
	uint32 new_size;

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
		 * Start with 128 bytes (arbitrary value), enough for small rpc
		 * requests
		 */
		new_size = MAX(128, extra_space);

		ps->data_p = (char *)talloc_zero_size(ps->mem_ctx, new_size);
		if(ps->data_p == NULL) {
			DEBUG(0,("prs_grow: talloc failure for size %u.\n", (unsigned int)new_size));
			return False;
		}
	} else {
		/*
		 * If the current buffer size is bigger than the space needed,
		 * just double it, else add extra_space. Always keep 64 bytes
		 * more, so that after we added a large blob we don't have to
		 * realloc immediately again.
		 */
		new_size = MAX(ps->buffer_size*2,
			       ps->buffer_size + extra_space + 64);

		ps->data_p = talloc_realloc(ps->mem_ctx,
						ps->data_p,
						char,
						new_size);
		if (ps->data_p == NULL) {
			DEBUG(0,("prs_grow: Realloc failure for size %u.\n",
				(unsigned int)new_size));
			return False;
		}

		memset(&ps->data_p[ps->buffer_size], '\0', (size_t)(new_size - ps->buffer_size));
	}
	ps->buffer_size = new_size;

	return True;
}

/*******************************************************************
 Attempt to force a data buffer to grow by len bytes.
 This is only used when appending more data onto a prs_struct
 when reading an rpc reply, before unmarshalling it.
 ********************************************************************/

bool prs_force_grow(prs_struct *ps, uint32 extra_space)
{
	uint32 new_size = ps->buffer_size + extra_space;

	if(!UNMARSHALLING(ps) || !ps->is_dynamic) {
		DEBUG(0,("prs_force_grow: Buffer overflow - unable to expand buffer by %u bytes.\n",
				(unsigned int)extra_space));
		return False;
	}

	ps->data_p = (char *)talloc_realloc(ps->mem_ctx,
					ps->data_p,
					char,
					new_size);
	if(ps->data_p == NULL) {
		DEBUG(0,("prs_force_grow: Realloc failure for size %u.\n",
			(unsigned int)new_size));
		return False;
	}

	memset(&ps->data_p[ps->buffer_size], '\0', (size_t)(new_size - ps->buffer_size));

	ps->buffer_size = new_size;

	return True;
}

/*******************************************************************
 Get the data pointer (external interface).
********************************************************************/

char *prs_data_p(prs_struct *ps)
{
	return ps->data_p;
}

/*******************************************************************
 Get the current data size (external interface).
 ********************************************************************/

uint32 prs_data_size(prs_struct *ps)
{
	return ps->buffer_size;
}

/*******************************************************************
 Fetch the current offset (external interface).
 ********************************************************************/

uint32 prs_offset(prs_struct *ps)
{
	return ps->data_offset;
}

/*******************************************************************
 Set the current offset (external interface).
 ********************************************************************/

bool prs_set_offset(prs_struct *ps, uint32 offset)
{
	if ((offset > ps->data_offset)
	    && !prs_grow(ps, offset - ps->data_offset)) {
		return False;
	}

	ps->data_offset = offset;
	return True;
}

/*******************************************************************
 Append the data from one parse_struct into another.
 ********************************************************************/

bool prs_append_prs_data(prs_struct *dst, prs_struct *src)
{
	if (prs_offset(src) == 0)
		return True;

	if(!prs_grow(dst, prs_offset(src)))
		return False;

	memcpy(&dst->data_p[dst->data_offset], src->data_p, (size_t)prs_offset(src));
	dst->data_offset += prs_offset(src);

	return True;
}

/*******************************************************************
 Append some data from one parse_struct into another.
 ********************************************************************/

bool prs_append_some_data(prs_struct *dst, void *src_base, uint32_t start,
			  uint32_t len)
{
	if (len == 0) {
		return true;
	}

	if(!prs_grow(dst, len)) {
		return false;
	}

	memcpy(&dst->data_p[dst->data_offset], ((char *)src_base) + start, (size_t)len);
	dst->data_offset += len;
	return true;
}

bool prs_append_some_prs_data(prs_struct *dst, prs_struct *src, int32 start,
			      uint32 len)
{
	return prs_append_some_data(dst, src->data_p, start, len);
}

/*******************************************************************
 Append the data from a buffer into a parse_struct.
 ********************************************************************/

bool prs_copy_data_in(prs_struct *dst, const char *src, uint32 len)
{
	if (len == 0)
		return True;

	if(!prs_grow(dst, len))
		return False;

	memcpy(&dst->data_p[dst->data_offset], src, (size_t)len);
	dst->data_offset += len;

	return True;
}

/*******************************************************************
 Copy some data from a parse_struct into a buffer.
 ********************************************************************/

bool prs_copy_data_out(char *dst, prs_struct *src, uint32 len)
{
	if (len == 0)
		return True;

	if(!prs_mem_get(src, len))
		return False;

	memcpy(dst, &src->data_p[src->data_offset], (size_t)len);
	src->data_offset += len;

	return True;
}

/*******************************************************************
 Copy all the data from a parse_struct into a buffer.
 ********************************************************************/

bool prs_copy_all_data_out(char *dst, prs_struct *src)
{
	uint32 len = prs_offset(src);

	if (!len)
		return True;

	prs_set_offset(src, 0);
	return prs_copy_data_out(dst, src, len);
}

/*******************************************************************
 Set the data as X-endian (external interface).
 ********************************************************************/

void prs_set_endian_data(prs_struct *ps, bool endian)
{
	ps->bigendian_data = endian;
}

/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/

bool prs_align(prs_struct *ps)
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

/******************************************************************
 Align on a 2 byte boundary
 *****************************************************************/

bool prs_align_uint16(prs_struct *ps)
{
	bool ret;
	uint8 old_align = ps->align;

	ps->align = 2;
	ret = prs_align(ps);
	ps->align = old_align;

	return ret;
}

/******************************************************************
 Align on a 8 byte boundary
 *****************************************************************/

bool prs_align_uint64(prs_struct *ps)
{
	bool ret;
	uint8 old_align = ps->align;

	ps->align = 8;
	ret = prs_align(ps);
	ps->align = old_align;

	return ret;
}

/******************************************************************
 Align on a specific byte boundary
 *****************************************************************/

bool prs_align_custom(prs_struct *ps, uint8 boundary)
{
	bool ret;
	uint8 old_align = ps->align;

	ps->align = boundary;
	ret = prs_align(ps);
	ps->align = old_align;

	return ret;
}



/*******************************************************************
 Align only if required (for the unistr2 string mainly)
 ********************************************************************/

bool prs_align_needed(prs_struct *ps, uint32 needed)
{
	if (needed==0)
		return True;
	else
		return prs_align(ps);
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
			DEBUG(0,("prs_mem_get: reading data of size %u would overrun "
				"buffer by %u bytes.\n",
				(unsigned int)extra_size,
				(unsigned int)(ps->data_offset + extra_size - ps->buffer_size) ));
			return NULL;
		}
	} else {
		/*
		 * Writing - grow the buffer if needed.
		 */
		if(!prs_grow(ps, extra_size))
			return NULL;
	}
	return &ps->data_p[ps->data_offset];
}

/*******************************************************************
 Change the struct type.
 ********************************************************************/

void prs_switch_type(prs_struct *ps, bool io)
{
	if ((ps->io ^ io) == True)
		ps->io=io;
}

/*******************************************************************
 Stream a uint8.
 ********************************************************************/

bool prs_uint8(const char *name, prs_struct *ps, int depth, uint8 *data8)
{
	char *q = prs_mem_get(ps, 1);
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps))
		*data8 = CVAL(q,0);
	else
		SCVAL(q,0,*data8);

	DEBUGADD(5,("%s%04x %s: %02x\n", tab_depth(5,depth), ps->data_offset, name, *data8));

	ps->data_offset += 1;

	return True;
}

/*******************************************************************
 Stream a uint16.
 ********************************************************************/

bool prs_uint16(const char *name, prs_struct *ps, int depth, uint16 *data16)
{
	char *q = prs_mem_get(ps, sizeof(uint16));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data)
			*data16 = RSVAL(q,0);
		else
			*data16 = SVAL(q,0);
	} else {
		if (ps->bigendian_data)
			RSSVAL(q,0,*data16);
		else
			SSVAL(q,0,*data16);
	}

	DEBUGADD(5,("%s%04x %s: %04x\n", tab_depth(5,depth), ps->data_offset, name, *data16));

	ps->data_offset += sizeof(uint16);

	return True;
}

/*******************************************************************
 Stream a uint32.
 ********************************************************************/

bool prs_uint32(const char *name, prs_struct *ps, int depth, uint32 *data32)
{
	char *q = prs_mem_get(ps, sizeof(uint32));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data)
			*data32 = RIVAL(q,0);
		else
			*data32 = IVAL(q,0);
	} else {
		if (ps->bigendian_data)
			RSIVAL(q,0,*data32);
		else
			SIVAL(q,0,*data32);
	}

	DEBUGADD(5,("%s%04x %s: %08x\n", tab_depth(5,depth), ps->data_offset, name, *data32));

	ps->data_offset += sizeof(uint32);

	return True;
}

/*******************************************************************
 Stream an int32.
 ********************************************************************/

bool prs_int32(const char *name, prs_struct *ps, int depth, int32 *data32)
{
	char *q = prs_mem_get(ps, sizeof(int32));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data)
			*data32 = RIVALS(q,0);
		else
			*data32 = IVALS(q,0);
	} else {
		if (ps->bigendian_data)
			RSIVALS(q,0,*data32);
		else
			SIVALS(q,0,*data32);
	}

	DEBUGADD(5,("%s%04x %s: %08x\n", tab_depth(5,depth), ps->data_offset, name, *data32));

	ps->data_offset += sizeof(int32);

	return True;
}

/*******************************************************************
 Stream a uint64_struct
 ********************************************************************/
bool prs_uint64(const char *name, prs_struct *ps, int depth, uint64 *data64)
{
	if (UNMARSHALLING(ps)) {
		uint32 high, low;

		if (!prs_uint32(name, ps, depth+1, &low))
			return False;

		if (!prs_uint32(name, ps, depth+1, &high))
			return False;

		*data64 = ((uint64_t)high << 32) + low;

		return True;
	} else {
		uint32 high = (*data64) >> 32, low = (*data64) & 0xFFFFFFFF;
		return prs_uint32(name, ps, depth+1, &low) &&
			   prs_uint32(name, ps, depth+1, &high);
	}
}

/*******************************************************************
 Stream a DCE error code
 ********************************************************************/

bool prs_dcerpc_status(const char *name, prs_struct *ps, int depth, NTSTATUS *status)
{
	char *q = prs_mem_get(ps, sizeof(uint32));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data)
			*status = NT_STATUS(RIVAL(q,0));
		else
			*status = NT_STATUS(IVAL(q,0));
	} else {
		if (ps->bigendian_data)
			RSIVAL(q,0,NT_STATUS_V(*status));
		else
			SIVAL(q,0,NT_STATUS_V(*status));
	}

	DEBUGADD(5,("%s%04x %s: %s\n", tab_depth(5,depth), ps->data_offset, name,
		 dcerpc_errstr(talloc_tos(), NT_STATUS_V(*status))));

	ps->data_offset += sizeof(uint32);

	return True;
}

/******************************************************************
 Stream an array of uint8s. Length is number of uint8s.
 ********************************************************************/

bool prs_uint8s(bool charmode, const char *name, prs_struct *ps, int depth, uint8 *data8s, int len)
{
	int i;
	char *q = prs_mem_get(ps, len);
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		for (i = 0; i < len; i++)
			data8s[i] = CVAL(q,i);
	} else {
		for (i = 0; i < len; i++)
			SCVAL(q, i, data8s[i]);
	}

	DEBUGADD(5,("%s%04x %s: ", tab_depth(5,depth), ps->data_offset ,name));
	if (charmode)
		print_asc(5, (unsigned char*)data8s, len);
	else {
		for (i = 0; i < len; i++)
			DEBUGADD(5,("%02x ", data8s[i]));
	}
	DEBUGADD(5,("\n"));

	ps->data_offset += len;

	return True;
}

/******************************************************************
 Stream an array of uint16s. Length is number of uint16s.
 ********************************************************************/

bool prs_uint16s(bool charmode, const char *name, prs_struct *ps, int depth, uint16 *data16s, int len)
{
	int i;
	char *q = prs_mem_get(ps, len * sizeof(uint16));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data) {
			for (i = 0; i < len; i++)
				data16s[i] = RSVAL(q, 2*i);
		} else {
			for (i = 0; i < len; i++)
				data16s[i] = SVAL(q, 2*i);
		}
	} else {
		if (ps->bigendian_data) {
			for (i = 0; i < len; i++)
				RSSVAL(q, 2*i, data16s[i]);
		} else {
			for (i = 0; i < len; i++)
				SSVAL(q, 2*i, data16s[i]);
		}
	}

	DEBUGADD(5,("%s%04x %s: ", tab_depth(5,depth), ps->data_offset, name));
	if (charmode)
		print_asc(5, (unsigned char*)data16s, 2*len);
	else {
		for (i = 0; i < len; i++)
			DEBUGADD(5,("%04x ", data16s[i]));
	}
	DEBUGADD(5,("\n"));

	ps->data_offset += (len * sizeof(uint16));

	return True;
}

/******************************************************************
 Stream an array of uint32s. Length is number of uint32s.
 ********************************************************************/

bool prs_uint32s(bool charmode, const char *name, prs_struct *ps, int depth, uint32 *data32s, int len)
{
	int i;
	char *q = prs_mem_get(ps, len * sizeof(uint32));
	if (q == NULL)
		return False;

	if (UNMARSHALLING(ps)) {
		if (ps->bigendian_data) {
			for (i = 0; i < len; i++)
				data32s[i] = RIVAL(q, 4*i);
		} else {
			for (i = 0; i < len; i++)
				data32s[i] = IVAL(q, 4*i);
		}
	} else {
		if (ps->bigendian_data) {
			for (i = 0; i < len; i++)
				RSIVAL(q, 4*i, data32s[i]);
		} else {
			for (i = 0; i < len; i++)
				SIVAL(q, 4*i, data32s[i]);
		}
	}

	DEBUGADD(5,("%s%04x %s: ", tab_depth(5,depth), ps->data_offset, name));
	if (charmode)
		print_asc(5, (unsigned char*)data32s, 4*len);
	else {
		for (i = 0; i < len; i++)
			DEBUGADD(5,("%08x ", data32s[i]));
	}
	DEBUGADD(5,("\n"));

	ps->data_offset += (len * sizeof(uint32));

	return True;
}

/*******************************************************************
creates a new prs_struct containing a DATA_BLOB
********************************************************************/
bool prs_init_data_blob(prs_struct *prs, DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	if (!prs_init( prs, RPC_MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL ))
		return False;


	if (!prs_copy_data_in(prs, (char *)blob->data, blob->length))
		return False;

	return True;
}

/*******************************************************************
return the contents of a prs_struct in a DATA_BLOB
********************************************************************/
bool prs_data_blob(prs_struct *prs, DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	blob->length = prs_data_size(prs);
	blob->data = (uint8 *)TALLOC_ZERO_SIZE(mem_ctx, blob->length);

	/* set the pointer at the end of the buffer */
	prs_set_offset( prs, prs_data_size(prs) );

	if (!prs_copy_all_data_out((char *)blob->data, prs))
		return False;

	return True;
}
