/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Gerald (Jerry) Carter             2005
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/

bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth)
{
	uint32 low, high;
	if (nttime == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_time");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if (MARSHALLING(ps)) {
		low = *nttime & 0xFFFFFFFF;
		high = *nttime >> 32;
	}
	
	if(!prs_uint32("low ", ps, depth, &low)) /* low part */
		return False;
	if(!prs_uint32("high", ps, depth, &high)) /* high part */
		return False;

	if (UNMARSHALLING(ps)) {
		*nttime = (((uint64_t)high << 32) + low);
	}

	return True;
}

/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/

bool smb_io_nttime(const char *desc, prs_struct *ps, int depth, NTTIME *nttime)
{
	return smb_io_time( desc, nttime, ps, depth );
}

/*******************************************************************
 Reads or writes a DOM_SID structure.
********************************************************************/

bool smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth)
{
	int i;

	if (sid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_dom_sid");
	depth++;

	if(!prs_uint8 ("sid_rev_num", ps, depth, &sid->sid_rev_num))
		return False;

	if(!prs_uint8 ("num_auths  ", ps, depth, (uint8 *)&sid->num_auths))
		return False;

	for (i = 0; i < 6; i++)
	{
		fstring tmp;
		slprintf(tmp, sizeof(tmp) - 1, "id_auth[%d] ", i);
		if(!prs_uint8 (tmp, ps, depth, &sid->id_auth[i]))
			return False;
	}

	/* oops! XXXX should really issue a warning here... */
	if (sid->num_auths > MAXSUBAUTHS)
		sid->num_auths = MAXSUBAUTHS;

	if(!prs_uint32s(False, "sub_auths ", ps, depth, sid->sub_auths, sid->num_auths))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a struct GUID
********************************************************************/

bool smb_io_uuid(const char *desc, struct GUID *uuid, 
		 prs_struct *ps, int depth)
{
	if (uuid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_uuid");
	depth++;

	if(!prs_uint32 ("data   ", ps, depth, &uuid->time_low))
		return False;
	if(!prs_uint16 ("data   ", ps, depth, &uuid->time_mid))
		return False;
	if(!prs_uint16 ("data   ", ps, depth, &uuid->time_hi_and_version))
		return False;

	if(!prs_uint8s (False, "data   ", ps, depth, uuid->clock_seq, sizeof(uuid->clock_seq)))
		return False;
	if(!prs_uint8s (False, "data   ", ps, depth, uuid->node, sizeof(uuid->node)))
		return False;

	return True;
}

/*******************************************************************
 Inits a UNISTR structure.
********************************************************************/

void init_unistr(UNISTR *str, const char *buf)
{
	size_t len;

	if (buf == NULL) {
		str->buffer = NULL;
		return;
	}

	len = rpcstr_push_talloc(talloc_tos(), &str->buffer, buf);
	if (len == (size_t)-1) {
		str->buffer = NULL;
	}
}

/*******************************************************************
reads or writes a UNISTR structure.
XXXX NOTE: UNISTR structures NEED to be null-terminated.
********************************************************************/

bool smb_io_unistr(const char *desc, UNISTR *uni, prs_struct *ps, int depth)
{
	if (uni == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_unistr");
	depth++;

	if(!prs_unistr("unistr", ps, depth, uni))
		return False;

	return True;
}

/*******************************************************************
reads or writes a BUFFER5 structure.
the buf_len member tells you how large the buffer is.
********************************************************************/
bool smb_io_buffer5(const char *desc, BUFFER5 *buf5, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_buffer5");
	depth++;

	if (buf5 == NULL) return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("buf_len", ps, depth, &buf5->buf_len))
		return False;

	if(buf5->buf_len) {
		if(!prs_buffer5(True, "buffer" , ps, depth, buf5))
			return False;
	}

	return True;
}

/*******************************************************************
creates a UNISTR2 structure: sets up the buffer, too
********************************************************************/

void init_buf_unistr2(UNISTR2 *str, uint32 *ptr, const char *buf)
{
	if (buf != NULL) {
		*ptr = 1;
		init_unistr2(str, buf, UNI_STR_TERMINATE);
	} else {
		*ptr = 0;
		init_unistr2(str, NULL, UNI_FLAGS_NONE);

	}
}

/*******************************************************************
 Copies a UNISTR2 structure.
********************************************************************/

void copy_unistr2(UNISTR2 *str, const UNISTR2 *from)
{
	if (from->buffer == NULL) {
		ZERO_STRUCTP(str);
		return;
	}

	SMB_ASSERT(from->uni_max_len >= from->uni_str_len);

	str->uni_max_len = from->uni_max_len;
	str->offset      = from->offset;
	str->uni_str_len = from->uni_str_len;

	/* the string buffer is allocated to the maximum size
	   (the the length of the source string) to prevent
	   reallocation of memory. */
	if (str->buffer == NULL) {
		if (str->uni_max_len) {
			str->buffer = (uint16 *)TALLOC_ZERO_ARRAY(talloc_tos(), uint16, str->uni_max_len);
			if ((str->buffer == NULL)) {
				smb_panic("copy_unistr2: talloc fail");
				return;
			}
			/* copy the string */
			memcpy(str->buffer, from->buffer, str->uni_max_len*sizeof(uint16));
		} else {
			str->buffer = NULL;
		}
	}
}

/*******************************************************************
 Inits a UNISTR2 structure.
********************************************************************/

void init_unistr2(UNISTR2 *str, const char *buf, enum unistr2_term_codes flags)
{
	size_t len = 0;
	uint32 num_chars = 0;

	if (buf) {
		/* We always null terminate the copy. */
		len = strlen(buf) + 1;
		if ( flags == UNI_STR_DBLTERMINATE )
			len++;
	}

	if (buf == NULL || len == 0) {
		/* no buffer -- nothing to do */
		str->uni_max_len = 0;
		str->offset = 0;
		str->uni_str_len = 0;

		return;
	}
	

	str->buffer = TALLOC_ZERO_ARRAY(talloc_tos(), uint16, len);
	if (str->buffer == NULL) {
		smb_panic("init_unistr2: malloc fail");
		return;
	}

	/* Ensure len is the length in *bytes* */
	len *= sizeof(uint16);

	/*
	 * The UNISTR2 must be initialized !!!
	 * jfm, 7/7/2001.
	 */
	if (buf) {
		rpcstr_push((char *)str->buffer, buf, len, STR_TERMINATE);
		num_chars = strlen_w(str->buffer);
		if (flags == UNI_STR_TERMINATE || flags == UNI_MAXLEN_TERMINATE) {
			num_chars++;
		}
		if ( flags == UNI_STR_DBLTERMINATE )
			num_chars += 2;
	}

	str->uni_max_len = num_chars;
	str->offset = 0;
	str->uni_str_len = num_chars;
	if ( num_chars && ((flags == UNI_MAXLEN_TERMINATE) || (flags == UNI_BROKEN_NON_NULL)) )
		str->uni_max_len++;
}

/** 
 *  Inits a UNISTR2 structure.
 *  @param  ctx talloc context to allocate string on
 *  @param  str pointer to string to create
 *  @param  buf UCS2 null-terminated buffer to init from
*/

void init_unistr2_w(TALLOC_CTX *ctx, UNISTR2 *str, const smb_ucs2_t *buf)
{
	uint32 len = buf ? strlen_w(buf) : 0;

	ZERO_STRUCTP(str);

	/* set up string lengths. */
	str->uni_max_len = len;
	str->offset = 0;
	str->uni_str_len = len;

	if (len + 1) {
		str->buffer = TALLOC_ZERO_ARRAY(ctx, uint16, len + 1);
		if (str->buffer == NULL) {
			smb_panic("init_unistr2_w: talloc fail");
			return;
		}
	} else {
		str->buffer = NULL;
	}
	
	/*
	 * don't move this test above ! The UNISTR2 must be initialized !!!
	 * jfm, 7/7/2001.
	 */
	if (buf==NULL)
		return;
	
	/* Yes, this is a strncpy( foo, bar, strlen(bar)) - but as
           long as the buffer above is talloc()ed correctly then this
           is the correct thing to do */
	if (len+1) {
		strncpy_w(str->buffer, buf, len + 1);
	}
}

/*******************************************************************
 Inits a UNISTR2 structure from a UNISTR
********************************************************************/

void init_unistr2_from_unistr(TALLOC_CTX *ctx, UNISTR2 *to, const UNISTR *from)
{
	uint32 i;

	/* the destination UNISTR2 should never be NULL.
	   if it is it is a programming error */

	/* if the source UNISTR is NULL, then zero out
	   the destination string and return */
	ZERO_STRUCTP (to);
	if ((from == NULL) || (from->buffer == NULL))
		return;

	/* get the length; UNISTR must be NULL terminated */
	i = 0;
	while ((from->buffer)[i]!='\0')
		i++;
	i++;	/* one more to catch the terminating NULL */
		/* is this necessary -- jerry?  I need to think */

	/* set up string lengths; uni_max_len is set to i+1
           because we need to account for the final NULL termination */
	to->uni_max_len = i;
	to->offset = 0;
	to->uni_str_len = i;

	/* allocate the space and copy the string buffer */
	if (i) {
		to->buffer = TALLOC_ZERO_ARRAY(ctx, uint16, i);
		if (to->buffer == NULL)
			smb_panic("init_unistr2_from_unistr: talloc fail");
		memcpy(to->buffer, from->buffer, i*sizeof(uint16));
	} else {
		to->buffer = NULL;
	}
	return;
}

/*******************************************************************
  Inits a UNISTR2 structure from a DATA_BLOB.
  The length of the data_blob must count the bytes of the buffer.
  Copies the blob data.
********************************************************************/

void init_unistr2_from_datablob(UNISTR2 *str, DATA_BLOB *blob) 
{
	/* Allocs the unistring */
	init_unistr2(str, NULL, UNI_FLAGS_NONE);
	
	/* Sets the values */
	str->uni_str_len = blob->length / sizeof(uint16);
	str->uni_max_len = str->uni_str_len;
	str->offset = 0;
	if (blob->length) {
		str->buffer = (uint16 *) memdup(blob->data, blob->length);
	} else {
		str->buffer = NULL;
	}
	if ((str->buffer == NULL) && (blob->length > 0)) {
		smb_panic("init_unistr2_from_datablob: malloc fail");
	}
}

/*******************************************************************
 UNISTR2* are a little different in that the pointer and the UNISTR2
 are not necessarily read/written back to back.  So we break it up 
 into 2 separate functions.
 See SPOOL_USER_1 in include/rpc_spoolss.h for an example.
********************************************************************/

bool prs_io_unistr2_p(const char *desc, prs_struct *ps, int depth, UNISTR2 **uni2)
{
	uint32 data_p;

	/* caputure the pointer value to stream */

	data_p = *uni2 ? 0xf000baaa : 0;

	if ( !prs_uint32("ptr", ps, depth, &data_p ))
		return False;

	/* we're done if there is no data */

	if ( !data_p )
		return True;

	if (UNMARSHALLING(ps)) {
		if ( !(*uni2 = PRS_ALLOC_MEM(ps, UNISTR2, 1)) )
			return False;
	}

	return True;
}

/*******************************************************************
 now read/write the actual UNISTR2.  Memory for the UNISTR2 (but
 not UNISTR2.buffer) has been allocated previously by prs_unistr2_p()
********************************************************************/

bool prs_io_unistr2(const char *desc, prs_struct *ps, int depth, UNISTR2 *uni2 )
{
	/* just return true if there is no pointer to deal with.
	   the memory must have been previously allocated on unmarshalling
	   by prs_unistr2_p() */

	if ( !uni2 )
		return True;

	/* just pass off to smb_io_unstr2() passing the uni2 address as 
	   the pointer (like you would expect) */

	return smb_io_unistr2( desc, uni2, uni2 ? 1 : 0, ps, depth );
}

/*******************************************************************
 Reads or writes a UNISTR2 structure.
 XXXX NOTE: UNISTR2 structures need NOT be null-terminated.
   the uni_str_len member tells you how long the string is;
   the uni_max_len member tells you how large the buffer is.
********************************************************************/

bool smb_io_unistr2(const char *desc, UNISTR2 *uni2, uint32 buffer, prs_struct *ps, int depth)
{
	if (uni2 == NULL)
		return False;

	if (buffer) {

		prs_debug(ps, depth, desc, "smb_io_unistr2");
		depth++;

		if(!prs_align(ps))
			return False;
		
		if(!prs_uint32("uni_max_len", ps, depth, &uni2->uni_max_len))
			return False;
		if(!prs_uint32("offset     ", ps, depth, &uni2->offset))
			return False;
		if(!prs_uint32("uni_str_len", ps, depth, &uni2->uni_str_len))
			return False;

		/* buffer advanced by indicated length of string
		   NOT by searching for null-termination */
		if(!prs_unistr2(True, "buffer     ", ps, depth, uni2))
			return False;

	} else {

		prs_debug(ps, depth, desc, "smb_io_unistr2 - NULL");
		depth++;
		memset((char *)uni2, '\0', sizeof(*uni2));

	}

	return True;
}

/*******************************************************************
 Reads or writes an POLICY_HND structure.
********************************************************************/

bool smb_io_pol_hnd(const char *desc, POLICY_HND *pol, prs_struct *ps, int depth)
{
	if (pol == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_pol_hnd");
	depth++;

	if(!prs_align(ps))
		return False;

	if(UNMARSHALLING(ps))
		ZERO_STRUCTP(pol);
	
	if (!prs_uint32("handle_type", ps, depth, &pol->handle_type))
		return False;
	if (!smb_io_uuid("uuid", (struct GUID*)&pol->uuid, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Create a UNISTR3.
********************************************************************/

void init_unistr3(UNISTR3 *str, const char *buf)
{
	if (buf == NULL) {
		str->uni_str_len=0;
		str->str.buffer = NULL;
		return;
	}

	str->uni_str_len = strlen(buf) + 1;

	if (str->uni_str_len) {
		str->str.buffer = TALLOC_ZERO_ARRAY(talloc_tos(), uint16, str->uni_str_len);
		if (str->str.buffer == NULL)
			smb_panic("init_unistr3: malloc fail");

		rpcstr_push((char *)str->str.buffer, buf, str->uni_str_len * sizeof(uint16), STR_TERMINATE);
	} else {
		str->str.buffer = NULL;
	}
}

/*******************************************************************
 Reads or writes a UNISTR3 structure.
********************************************************************/

bool smb_io_unistr3(const char *desc, UNISTR3 *name, prs_struct *ps, int depth)
{
	if (name == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_unistr3");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("uni_str_len", ps, depth, &name->uni_str_len))
		return False;
		
	/* we're done if there is no string */
	
	if ( name->uni_str_len == 0 )
		return True;

	/* don't know if len is specified by uni_str_len member... */
	/* assume unicode string is unicode-null-terminated, instead */

	if(!prs_unistr3(True, "unistr", name, ps, depth))
		return False;

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
return the length of a UNISTR string.
********************************************************************/  

uint32 str_len_uni(UNISTR *source)
{
 	uint32 i=0;

	if (!source->buffer)
		return 0;

	while (source->buffer[i])
		i++;

	return i;
}

/*******************************************************************
 Verifies policy handle
********************************************************************/

bool policy_handle_is_valid(const POLICY_HND *hnd)
{
	POLICY_HND zero_pol;

	ZERO_STRUCT(zero_pol);
	return ((memcmp(&zero_pol, hnd, sizeof(POLICY_HND)) == 0) ? false : true );
}
