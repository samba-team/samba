/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 e  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

/****************************************************************************
 A temporary TALLOC context for things like unistrs, that is valid for
 the life of a complete RPC call.
****************************************************************************/

static TALLOC_CTX *current_rpc_talloc = NULL;

TALLOC_CTX *get_current_rpc_talloc(void)
{
    return current_rpc_talloc;
}

void set_current_rpc_talloc( TALLOC_CTX *ctx)
{
	current_rpc_talloc = ctx;
}

static TALLOC_CTX *main_loop_talloc = NULL;

/*******************************************************************
free up temporary memory - called from the main loop
********************************************************************/

void main_loop_talloc_free(void)
{
    if (!main_loop_talloc)
        return;
    talloc_destroy(main_loop_talloc);
    main_loop_talloc = NULL;
}

/*******************************************************************
 Get a talloc context that is freed in the main loop...
********************************************************************/

TALLOC_CTX *main_loop_talloc_get(void)
{
    if (!main_loop_talloc) {
        main_loop_talloc = talloc_init();
        if (!main_loop_talloc)
            smb_panic("main_loop_talloc: malloc fail\n");
    }

    return main_loop_talloc;
}

/*******************************************************************
 Try and get a talloc context. Get the rpc one if possible, else
 get the main loop one. The main loop one is more dangerous as it
 goes away between packets, the rpc one will stay around for as long
 as a current RPC lasts.
********************************************************************/ 

TALLOC_CTX *get_talloc_ctx(void)
{
	TALLOC_CTX *tc = get_current_rpc_talloc();

	if (tc)
		return tc;
	return main_loop_talloc_get();
}

/*******************************************************************
 Reads or writes a UTIME type.
********************************************************************/

static BOOL smb_io_utime(const char *desc, UTIME *t, prs_struct *ps, int depth)
{
	if (t == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_utime");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32 ("time", ps, depth, &t->time))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/

BOOL smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth)
{
	if (nttime == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_time");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("low ", ps, depth, &nttime->low)) /* low part */
		return False;
	if(!prs_uint32("high", ps, depth, &nttime->high)) /* high part */
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a LOOKUP_LEVEL structure.
********************************************************************/

BOOL smb_io_lookup_level(const char *desc, LOOKUP_LEVEL *level, prs_struct *ps, int depth)
{
	if (level == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_lookup_level");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint16("value", ps, depth, &level->value))
		return False;
	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
 Gets an enumeration handle from an ENUM_HND structure.
********************************************************************/

uint32 get_enum_hnd(ENUM_HND *enh)
{
	return (enh && enh->ptr_hnd != 0) ? enh->handle : 0;
}

/*******************************************************************
 Inits an ENUM_HND structure.
********************************************************************/

void init_enum_hnd(ENUM_HND *enh, uint32 hnd)
{
	DEBUG(5,("smb_io_enum_hnd\n"));

	enh->ptr_hnd = (hnd != 0) ? 1 : 0;
	enh->handle = hnd;
}

/*******************************************************************
 Reads or writes an ENUM_HND structure.
********************************************************************/

BOOL smb_io_enum_hnd(const char *desc, ENUM_HND *hnd, prs_struct *ps, int depth)
{
	if (hnd == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_enum_hnd");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_hnd", ps, depth, &hnd->ptr_hnd)) /* pointer */
		return False;

	if (hnd->ptr_hnd != 0) {
		if(!prs_uint32("handle ", ps, depth, &hnd->handle )) /* enum handle */
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes a DOM_SID structure.
********************************************************************/

BOOL smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth)
{
	int i;

	if (sid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_dom_sid");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint8 ("sid_rev_num", ps, depth, &sid->sid_rev_num))
		return False;
	if(!prs_uint8 ("num_auths  ", ps, depth, &sid->num_auths))
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
 Inits a DOM_SID structure.

 BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 
 identauth >= 2^32 can be detected because it will be specified in hex
********************************************************************/

void init_dom_sid(DOM_SID *sid, const char *str_sid)
{
	pstring domsid;
	int identauth;
	char *p;

	if (str_sid == NULL)
	{
		DEBUG(4,("netlogon domain SID: none\n"));
		sid->sid_rev_num = 0;
		sid->num_auths = 0;
		return;
	}
		
	pstrcpy(domsid, str_sid);

	DEBUG(4,("init_dom_sid %d SID:  %s\n", __LINE__, domsid));

	/* assume, but should check, that domsid starts "S-" */
	p = strtok(domsid+2,"-");
	sid->sid_rev_num = atoi(p);

	/* identauth in decimal should be <  2^32 */
	/* identauth in hex     should be >= 2^32 */
	identauth = atoi(strtok(0,"-"));

	DEBUG(4,("netlogon rev %d\n", sid->sid_rev_num));
	DEBUG(4,("netlogon %s ia %d\n", p, identauth));

	sid->id_auth[0] = 0;
	sid->id_auth[1] = 0;
	sid->id_auth[2] = (identauth & 0xff000000) >> 24;
	sid->id_auth[3] = (identauth & 0x00ff0000) >> 16;
	sid->id_auth[4] = (identauth & 0x0000ff00) >> 8;
	sid->id_auth[5] = (identauth & 0x000000ff);

	sid->num_auths = 0;

	while ((p = strtok(0, "-")) != NULL && sid->num_auths < MAXSUBAUTHS)
		sid->sub_auths[sid->num_auths++] = atoi(p);

	DEBUG(4,("init_dom_sid: %d SID:  %s\n", __LINE__, domsid));
}

/*******************************************************************
 Inits a DOM_SID2 structure.
********************************************************************/

void init_dom_sid2(DOM_SID2 *sid2, const DOM_SID *sid)
{
	sid2->sid = *sid;
	sid2->num_auths = sid2->sid.num_auths;
}

/*******************************************************************
 Reads or writes a DOM_SID2 structure.
********************************************************************/

BOOL smb_io_dom_sid2(const char *desc, DOM_SID2 *sid, prs_struct *ps, int depth)
{
	if (sid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_dom_sid2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("num_auths", ps, depth, &sid->num_auths))
		return False;

	if(!smb_io_dom_sid("sid", &sid->sid, ps, depth))
		return False;

	return True;
}

/*******************************************************************
creates a STRHDR structure.
********************************************************************/

void init_str_hdr(STRHDR *hdr, int max_len, int len, uint32 buffer)
{
	hdr->str_max_len = max_len;
	hdr->str_str_len = len;
	hdr->buffer      = buffer;
}

/*******************************************************************
 Reads or writes a STRHDR structure.
********************************************************************/

BOOL smb_io_strhdr(const char *desc,  STRHDR *hdr, prs_struct *ps, int depth)
{
	if (hdr == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_strhdr");
	depth++;

	prs_align(ps);
	
	if(!prs_uint16("str_str_len", ps, depth, &hdr->str_str_len))
		return False;
	if(!prs_uint16("str_max_len", ps, depth, &hdr->str_max_len))
		return False;
	if(!prs_uint32("buffer     ", ps, depth, &hdr->buffer))
		return False;

	return True;
}

/*******************************************************************
 Inits a UNIHDR structure.
********************************************************************/

void init_uni_hdr(UNIHDR *hdr, int len)
{
	hdr->uni_str_len = 2 * len;
	hdr->uni_max_len = 2 * len;
	hdr->buffer      = len != 0 ? 1 : 0;
}

/*******************************************************************
 Reads or writes a UNIHDR structure.
********************************************************************/

BOOL smb_io_unihdr(const char *desc, UNIHDR *hdr, prs_struct *ps, int depth)
{
	if (hdr == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_unihdr");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint16("uni_str_len", ps, depth, &hdr->uni_str_len))
		return False;
	if(!prs_uint16("uni_max_len", ps, depth, &hdr->uni_max_len))
		return False;
	if(!prs_uint32("buffer     ", ps, depth, &hdr->buffer))
		return False;

	return True;
}

/*******************************************************************
 Inits a BUFHDR structure.
********************************************************************/

void init_buf_hdr(BUFHDR *hdr, int max_len, int len)
{
	hdr->buf_max_len = max_len;
	hdr->buf_len     = len;
}

/*******************************************************************
 prs_uint16 wrapper. Call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading.
 ********************************************************************/

BOOL smb_io_hdrbuf_pre(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth, uint32 *offset)
{
	(*offset) = prs_offset(ps);
	if (ps->io) {

		/* reading. */

		if(!smb_io_hdrbuf(desc, hdr, ps, depth))
			return False;

	} else {

		/* writing. */

		if(!prs_set_offset(ps, prs_offset(ps) + (sizeof(uint32) * 2)))
			return False;
	}

	return True;
}

/*******************************************************************
 smb_io_hdrbuf wrapper. Call this and it retrospectively stores the size.
 Does nothing on reading, as that is already handled by ...._pre()
 ********************************************************************/

BOOL smb_io_hdrbuf_post(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth, 
				uint32 ptr_hdrbuf, uint32 max_len, uint32 len)
{
	if (!ps->io) {
		/* writing: go back and do a retrospective job.  i hate this */

		uint32 old_offset = prs_offset(ps);

		init_buf_hdr(hdr, max_len, len);
		if(!prs_set_offset(ps, ptr_hdrbuf))
			return False;
		if(!smb_io_hdrbuf(desc, hdr, ps, depth))
			return False;

		if(!prs_set_offset(ps, old_offset))
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes a BUFHDR structure.
********************************************************************/

BOOL smb_io_hdrbuf(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth)
{
	if (hdr == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_hdrbuf");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("buf_max_len", ps, depth, &hdr->buf_max_len))
		return False;
	if(!prs_uint32("buf_len    ", ps, depth, &hdr->buf_len))
		return False;

	return True;
}

/*******************************************************************
creates a UNIHDR2 structure.
********************************************************************/

void init_uni_hdr2(UNIHDR2 *hdr, int len)
{
	init_uni_hdr(&hdr->unihdr, len);
	hdr->buffer = (len > 0) ? 1 : 0;
}

/*******************************************************************
 Reads or writes a UNIHDR2 structure.
********************************************************************/

BOOL smb_io_unihdr2(const char *desc, UNIHDR2 *hdr2, prs_struct *ps, int depth)
{
	if (hdr2 == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_unihdr2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unihdr("hdr", &hdr2->unihdr, ps, depth))
		return False;
	if(!prs_uint32("buffer", ps, depth, &hdr2->buffer))
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
		

	len = strlen(buf) + 1;

	if (len < MAX_UNISTRLEN)
		len = MAX_UNISTRLEN;
	len *= sizeof(uint16);

	str->buffer = (uint16 *)talloc_zero(get_talloc_ctx(), len);
	if (str->buffer == NULL)
		smb_panic("init_unistr: malloc fail\n");

	/* store the string (null-terminated copy) */
	dos_struni2((char *)str->buffer, buf, len);
}

/*******************************************************************
reads or writes a UNISTR structure.
XXXX NOTE: UNISTR structures NEED to be null-terminated.
********************************************************************/

BOOL smb_io_unistr(const char *desc, UNISTR *uni, prs_struct *ps, int depth)
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
 Allocate the BUFFER3 memory.
********************************************************************/

static void create_buffer3(BUFFER3 *str, size_t len)
{
	if (len < MAX_BUFFERLEN)
		len = MAX_BUFFERLEN;

	str->buffer = talloc_zero(get_talloc_ctx(), len);
	if (str->buffer == NULL)
		smb_panic("create_buffer3: talloc fail\n");

}

/*******************************************************************
 Inits a BUFFER3 structure from a uint32
********************************************************************/

void init_buffer3_uint32(BUFFER3 *str, uint32 val)
{
	ZERO_STRUCTP(str);

	/* set up string lengths. */
	str->buf_max_len = sizeof(uint32);
	str->buf_len     = sizeof(uint32);

	create_buffer3(str, sizeof(uint32));
	SIVAL(str->buffer, 0, val);
}

/*******************************************************************
 Inits a BUFFER3 structure.
********************************************************************/

void init_buffer3_str(BUFFER3 *str, char *buf, int len)
{
	ZERO_STRUCTP(str);

	/* set up string lengths. */
	str->buf_max_len = len * 2;
	str->buf_len     = len * 2;

	create_buffer3(str, str->buf_max_len);

	/* store the string (null-terminated 8 bit chars into 16 bit chars) */
	dos_struni2((char *)str->buffer, buf, str->buf_max_len);
}

/*******************************************************************
 Inits a BUFFER3 structure from a hex string.
********************************************************************/

void init_buffer3_hex(BUFFER3 *str, char *buf)
{
	ZERO_STRUCTP(str);
	create_buffer3(str, strlen(buf));
	str->buf_max_len = str->buf_len = strhex_to_str((char *)str->buffer, sizeof(str->buffer), buf);
}

/*******************************************************************
 Inits a BUFFER3 structure.
********************************************************************/

void init_buffer3_bytes(BUFFER3 *str, uint8 *buf, int len)
{
	ZERO_STRUCTP(str);

	/* max buffer size (allocated size) */
	str->buf_max_len = len;
	if (buf != NULL) {
		create_buffer3(str, len);
		memcpy(str->buffer, buf, len);
	}
	str->buf_len = buf != NULL ? len : 0;
}

/*******************************************************************
 Reads or writes a BUFFER3 structure.
   the uni_max_len member tells you how large the buffer is.
   the uni_str_len member tells you how much of the buffer is really used.
********************************************************************/

BOOL smb_io_buffer3(const char *desc, BUFFER3 *buf3, prs_struct *ps, int depth)
{
	if (buf3 == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_buffer3");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("uni_max_len", ps, depth, &buf3->buf_max_len))
		return False;

	if (UNMARSHALLING(ps)) {
		buf3->buffer = (unsigned char *)prs_alloc_mem(ps, buf3->buf_max_len);
		if (buf3->buffer == NULL)
			return False;
	}

	if(!prs_uint8s(True, "buffer     ", ps, depth, buf3->buffer, buf3->buf_max_len))
		return False;

	if(!prs_uint32("buf_len    ", ps, depth, &buf3->buf_len))
		return False;

	return True;
}

/*******************************************************************
reads or writes a BUFFER5 structure.
the buf_len member tells you how large the buffer is.
********************************************************************/
BOOL smb_io_buffer5(const char *desc, BUFFER5 *buf5, prs_struct *ps, int depth)
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
 Inits a BUFFER2 structure.
********************************************************************/

void init_buffer2(BUFFER2 *str, uint8 *buf, int len)
{
	ZERO_STRUCTP(str);

	/* max buffer size (allocated size) */
	str->buf_max_len = len;
	str->undoc       = 0;
	str->buf_len = buf != NULL ? len : 0;

	if (buf != NULL) {
		if (len < MAX_BUFFERLEN)
			len = MAX_BUFFERLEN;
		str->buffer = talloc_zero(get_talloc_ctx(), len);
		if (str->buffer == NULL)
			smb_panic("init_buffer2: talloc fail\n");
		memcpy(str->buffer, buf, MIN(str->buf_len, len));
	}
}

/*******************************************************************
 Reads or writes a BUFFER2 structure.
   the uni_max_len member tells you how large the buffer is.
   the uni_str_len member tells you how much of the buffer is really used.
********************************************************************/

BOOL smb_io_buffer2(const char *desc, BUFFER2 *buf2, uint32 buffer, prs_struct *ps, int depth)
{
	if (buf2 == NULL)
		return False;

	if (buffer) {

		prs_debug(ps, depth, desc, "smb_io_buffer2");
		depth++;

		if(!prs_align(ps))
			return False;
		
		if(!prs_uint32("uni_max_len", ps, depth, &buf2->buf_max_len))
			return False;
		if(!prs_uint32("undoc      ", ps, depth, &buf2->undoc))
			return False;
		if(!prs_uint32("buf_len    ", ps, depth, &buf2->buf_len))
			return False;

		/* buffer advanced by indicated length of string
		   NOT by searching for null-termination */

		if(!prs_buffer2(True, "buffer     ", ps, depth, buf2))
			return False;

	} else {

		prs_debug(ps, depth, desc, "smb_io_buffer2 - NULL");
		depth++;
		memset((char *)buf2, '\0', sizeof(*buf2));

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
		init_unistr2(str, buf, strlen(buf)+1);

	} else {

		*ptr = 0;
		init_unistr2(str, "", 0);

	}
}

/*******************************************************************
 Copies a UNISTR2 structure.
********************************************************************/

void copy_unistr2(UNISTR2 *str, const UNISTR2 *from)
{

	/* set up string lengths. add one if string is not null-terminated */
	str->uni_max_len = from->uni_max_len;
	str->undoc       = from->undoc;
	str->uni_str_len = from->uni_str_len;

	if (from->buffer == NULL)
		return;
		
	/* the string buffer is allocated to the maximum size
	   (the the length of the source string) to prevent
	   reallocation of memory. */
	if (str->buffer == NULL) {
		size_t len = from->uni_max_len * sizeof(uint16);

		if (len < MAX_UNISTRLEN)
			len = MAX_UNISTRLEN;
		len *= sizeof(uint16);

   		str->buffer = (uint16 *)talloc_zero(get_talloc_ctx(), len);
		if ((str->buffer == NULL) && (len > 0 ))
		{
			smb_panic("copy_unistr2: talloc fail\n");
			return;
		}
	}

	/* copy the string */
	memcpy(str->buffer, from->buffer, from->uni_max_len*sizeof(uint16));
}

/*******************************************************************
 Creates a STRING2 structure.
********************************************************************/

void init_string2(STRING2 *str, const char *buf, int max_len, int str_len)
{
	int alloc_len = 0;

	/* set up string lengths. */
	str->str_max_len = max_len;
	str->undoc       = 0;
	str->str_str_len = str_len;

	/* store the string */
	if(str_len != 0) {
		if (str_len < MAX_STRINGLEN)
			alloc_len = MAX_STRINGLEN;
		str->buffer = talloc_zero(get_talloc_ctx(), alloc_len);
		if (str->buffer == NULL)
			smb_panic("init_string2: malloc fail\n");
		memcpy(str->buffer, buf, str_len);
  }
}

/*******************************************************************
 Reads or writes a STRING2 structure.
 XXXX NOTE: STRING2 structures need NOT be null-terminated.
   the str_str_len member tells you how long the string is;
   the str_max_len member tells you how large the buffer is.
********************************************************************/

BOOL smb_io_string2(const char *desc, STRING2 *str2, uint32 buffer, prs_struct *ps, int depth)
{
	if (str2 == NULL)
		return False;

	if (buffer) {

		prs_debug(ps, depth, desc, "smb_io_string2");
		depth++;

		if(!prs_align(ps))
			return False;
		
		if(!prs_uint32("str_max_len", ps, depth, &str2->str_max_len))
			return False;
		if(!prs_uint32("undoc      ", ps, depth, &str2->undoc))
			return False;
		if(!prs_uint32("str_str_len", ps, depth, &str2->str_str_len))
			return False;

		/* buffer advanced by indicated length of string
		   NOT by searching for null-termination */
		if(!prs_string2(True, "buffer     ", ps, depth, str2))
			return False;

	} else {

		prs_debug(ps, depth, desc, "smb_io_string2 - NULL");
		depth++;
		memset((char *)str2, '\0', sizeof(*str2));

	}

	return True;
}

/*******************************************************************
 Inits a UNISTR2 structure. len is in bytes.
********************************************************************/

void init_unistr2(UNISTR2 *str, const char *buf, size_t len)
{
	ZERO_STRUCTP(str);

	/* set up string lengths. */
	str->uni_max_len = (uint32)len;
	str->undoc       = 0;
	str->uni_str_len = (uint32)len;

	if (len < MAX_UNISTRLEN)
		len = MAX_UNISTRLEN;
	len *= sizeof(uint16);

	str->buffer = (uint16 *)talloc_zero(get_talloc_ctx(), len);
	if ((str->buffer == NULL) && (len > 0))
	{
		smb_panic("init_unistr2: malloc fail\n");
		return;
	}

	/*
	 * don't move this test above ! The UNISTR2 must be initialized !!!
	 * jfm, 7/7/2001.
	 */
	if (buf==NULL)
		return;

	/* store the string (null-terminated 8 bit chars into 16 bit chars) */
	dos_struni2((char *)str->buffer, buf, len);
}

/*******************************************************************
 Inits a UNISTR2 structure from a UNISTR
********************************************************************/
void init_unistr2_from_unistr (UNISTR2 *to, UNISTR *from)
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
	to->undoc       = 0;
	to->uni_str_len = i;

	/* allocate the space and copy the string buffer */
	to->buffer = (uint16 *)talloc_zero(get_talloc_ctx(), sizeof(uint16)*(to->uni_str_len));
	if (to->buffer == NULL)
		smb_panic("init_unistr2_from_unistr: malloc fail\n");
	memcpy(to->buffer, from->buffer, to->uni_max_len*sizeof(uint16));
		
	return;
}


/*******************************************************************
 Reads or writes a UNISTR2 structure.
 XXXX NOTE: UNISTR2 structures need NOT be null-terminated.
   the uni_str_len member tells you how long the string is;
   the uni_max_len member tells you how large the buffer is.
********************************************************************/

BOOL smb_io_unistr2(const char *desc, UNISTR2 *uni2, uint32 buffer, prs_struct *ps, int depth)
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
		if(!prs_uint32("undoc      ", ps, depth, &uni2->undoc))
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
 Inits a DOM_RID2 structure.
********************************************************************/

void init_dom_rid2(DOM_RID2 *rid2, uint32 rid, uint8 type, uint32 idx)
{
	rid2->type    = type;
	rid2->rid     = rid;
	rid2->rid_idx = idx;
}

/*******************************************************************
 Reads or writes a DOM_RID2 structure.
********************************************************************/

BOOL smb_io_dom_rid2(const char *desc, DOM_RID2 *rid2, prs_struct *ps, int depth)
{
	if (rid2 == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_dom_rid2");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint8("type   ", ps, depth, &rid2->type))
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("rid    ", ps, depth, &rid2->rid))
		return False;
	if(!prs_uint32("rid_idx", ps, depth, &rid2->rid_idx))
		return False;

	return True;
}

/*******************************************************************
creates a DOM_RID3 structure.
********************************************************************/

void init_dom_rid3(DOM_RID3 *rid3, uint32 rid, uint8 type)
{
    rid3->rid      = rid;
    rid3->type1    = type;
    rid3->ptr_type = 0x1; /* non-zero, basically. */
    rid3->type2    = 0x1;
    rid3->unk      = type;
}

/*******************************************************************
reads or writes a DOM_RID3 structure.
********************************************************************/

BOOL smb_io_dom_rid3(const char *desc, DOM_RID3 *rid3, prs_struct *ps, int depth)
{
	if (rid3 == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_dom_rid3");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("rid     ", ps, depth, &rid3->rid))
		return False;
	if(!prs_uint32("type1   ", ps, depth, &rid3->type1))
		return False;
	if(!prs_uint32("ptr_type", ps, depth, &rid3->ptr_type))
		return False;
	if(!prs_uint32("type2   ", ps, depth, &rid3->type2))
		return False;
	if(!prs_uint32("unk     ", ps, depth, &rid3->unk))
		return False;

	return True;
}

/*******************************************************************
 Inits a DOM_RID4 structure.
********************************************************************/

void init_dom_rid4(DOM_RID4 *rid4, uint16 unknown, uint16 attr, uint32 rid)
{
    rid4->unknown = unknown;
    rid4->attr    = attr;
    rid4->rid     = rid;
}

/*******************************************************************
 Inits a DOM_CLNT_SRV structure.
********************************************************************/

static void init_clnt_srv(DOM_CLNT_SRV *log, const char *logon_srv, const char *comp_name)
{
	DEBUG(5,("init_clnt_srv: %d\n", __LINE__));

	if (logon_srv != NULL) {
		log->undoc_buffer = 1;
		init_unistr2(&log->uni_logon_srv, logon_srv, strlen(logon_srv)+1);
	} else {
		log->undoc_buffer = 0;
	}

	if (comp_name != NULL) {
		log->undoc_buffer2 = 1;
		init_unistr2(&log->uni_comp_name, comp_name, strlen(comp_name)+1);
	} else {
		log->undoc_buffer2 = 0;
	}
}

/*******************************************************************
 Inits or writes a DOM_CLNT_SRV structure.
********************************************************************/

static BOOL smb_io_clnt_srv(const char *desc, DOM_CLNT_SRV *log, prs_struct *ps, int depth)
{
	if (log == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_clnt_srv");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("undoc_buffer ", ps, depth, &log->undoc_buffer))
		return False;

	if (log->undoc_buffer != 0) {
		if(!smb_io_unistr2("unistr2", &log->uni_logon_srv, log->undoc_buffer, ps, depth))
			return False;
	}

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("undoc_buffer2", ps, depth, &log->undoc_buffer2))
		return False;

	if (log->undoc_buffer2 != 0) {
		if(!smb_io_unistr2("unistr2", &log->uni_comp_name, log->undoc_buffer2, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 Inits a DOM_LOG_INFO structure.
********************************************************************/

void init_log_info(DOM_LOG_INFO *log, const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name)
{
	DEBUG(5,("make_log_info %d\n", __LINE__));

	log->undoc_buffer = 1;

	init_unistr2(&log->uni_logon_srv, logon_srv, strlen(logon_srv)+1);
	init_unistr2(&log->uni_acct_name, acct_name, strlen(acct_name)+1);

	log->sec_chan = sec_chan;

	init_unistr2(&log->uni_comp_name, comp_name, strlen(comp_name)+1);
}

/*******************************************************************
 Reads or writes a DOM_LOG_INFO structure.
********************************************************************/

BOOL smb_io_log_info(const char *desc, DOM_LOG_INFO *log, prs_struct *ps, int depth)
{
	if (log == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_log_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("undoc_buffer", ps, depth, &log->undoc_buffer))
		return False;

	if(!smb_io_unistr2("unistr2", &log->uni_logon_srv, True, ps, depth))
		return False;
	if(!smb_io_unistr2("unistr2", &log->uni_acct_name, True, ps, depth))
		return False;

	if(!prs_uint16("sec_chan", ps, depth, &log->sec_chan))
		return False;

	if(!smb_io_unistr2("unistr2", &log->uni_comp_name, True, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a DOM_CHAL structure.
********************************************************************/

BOOL smb_io_chal(const char *desc, DOM_CHAL *chal, prs_struct *ps, int depth)
{
	if (chal == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_chal");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint8s (False, "data", ps, depth, chal->data, 8))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a DOM_CRED structure.
********************************************************************/

BOOL smb_io_cred(const char *desc,  DOM_CRED *cred, prs_struct *ps, int depth)
{
	if (cred == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_cred");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_chal ("", &cred->challenge, ps, depth))
		return False;

	if(!smb_io_utime("", &cred->timestamp, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Inits a DOM_CLNT_INFO2 structure.
********************************************************************/

void init_clnt_info2(DOM_CLNT_INFO2 *clnt,
				const char *logon_srv, const char *comp_name,
				DOM_CRED *clnt_cred)
{
	DEBUG(5,("make_clnt_info: %d\n", __LINE__));

	init_clnt_srv(&(clnt->login), logon_srv, comp_name);

	if (clnt_cred != NULL) {
		clnt->ptr_cred = 1;
		memcpy(&(clnt->cred), clnt_cred, sizeof(clnt->cred));
	} else {
		clnt->ptr_cred = 0;
	}
}

/*******************************************************************
 Reads or writes a DOM_CLNT_INFO2 structure.
********************************************************************/

BOOL smb_io_clnt_info2(const char *desc, DOM_CLNT_INFO2 *clnt, prs_struct *ps, int depth)
{
	if (clnt == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_clnt_info2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_clnt_srv("", &clnt->login, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_cred", ps, depth, &clnt->ptr_cred))
		return False;
	if(!smb_io_cred("", &clnt->cred, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Inits a DOM_CLNT_INFO structure.
********************************************************************/

void init_clnt_info(DOM_CLNT_INFO *clnt,
		const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name,
				DOM_CRED *cred)
{
	DEBUG(5,("make_clnt_info\n"));

	init_log_info(&clnt->login, logon_srv, acct_name, sec_chan, comp_name);
	memcpy(&clnt->cred, cred, sizeof(clnt->cred));
}

/*******************************************************************
 Reads or writes a DOM_CLNT_INFO structure.
********************************************************************/

BOOL smb_io_clnt_info(const char *desc,  DOM_CLNT_INFO *clnt, prs_struct *ps, int depth)
{
	if (clnt == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_clnt_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_log_info("", &clnt->login, ps, depth))
		return False;
	if(!smb_io_cred("", &clnt->cred, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Inits a DOM_LOGON_ID structure.
********************************************************************/

void init_logon_id(DOM_LOGON_ID *log, uint32 log_id_low, uint32 log_id_high)
{
	DEBUG(5,("make_logon_id: %d\n", __LINE__));

	log->low  = log_id_low;
	log->high = log_id_high;
}

/*******************************************************************
 Reads or writes a DOM_LOGON_ID structure.
********************************************************************/

BOOL smb_io_logon_id(const char *desc, DOM_LOGON_ID *log, prs_struct *ps, int depth)
{
	if (log == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_logon_id");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("low ", ps, depth, &log->low ))
		return False;
	if(!prs_uint32("high", ps, depth, &log->high))
		return False;

	return True;
}

/*******************************************************************
 Inits an OWF_INFO structure.
********************************************************************/

void init_owf_info(OWF_INFO *hash, uint8 data[16])
{
	DEBUG(5,("init_owf_info: %d\n", __LINE__));
	
	if (data != NULL)
		memcpy(hash->data, data, sizeof(hash->data));
	else
		memset((char *)hash->data, '\0', sizeof(hash->data));
}

/*******************************************************************
 Reads or writes an OWF_INFO structure.
********************************************************************/

BOOL smb_io_owf_info(const char *desc, OWF_INFO *hash, prs_struct *ps, int depth)
{
	if (hash == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_owf_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint8s (False, "data", ps, depth, hash->data, 16))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a DOM_GID structure.
********************************************************************/

BOOL smb_io_gid(const char *desc,  DOM_GID *gid, prs_struct *ps, int depth)
{
	if (gid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_gid");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("g_rid", ps, depth, &gid->g_rid))
		return False;
	if(!prs_uint32("attr ", ps, depth, &gid->attr))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an POLICY_HND structure.
********************************************************************/

BOOL smb_io_pol_hnd(const char *desc, POLICY_HND *pol, prs_struct *ps, int depth)
{
	if (pol == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_pol_hnd");
	depth++;

	if(!prs_align(ps))
		return False;

	if(UNMARSHALLING(ps))
		ZERO_STRUCTP(pol);
	
	if (!prs_uint32("data1", ps, depth, &pol->data1))
		return False;
	if (!prs_uint32("data2", ps, depth, &pol->data2))
		return False;
	if (!prs_uint16("data3", ps, depth, &pol->data3))
		return False;
	if (!prs_uint16("data4", ps, depth, &pol->data4))
		return False;
	if(!prs_uint8s (False, "data5", ps, depth, pol->data5, sizeof(pol->data5)))
		return False;

	return True;
}

/*******************************************************************
 Create a UNISTR3.
********************************************************************/

void init_unistr3(UNISTR3 *str, const char *buf)
{
	size_t len;

	if (buf == NULL) {
		str->uni_str_len=0;
		str->str.buffer = NULL;
		return;
	}

	len = strlen(buf) + 1;

	str->uni_str_len=len;

	if (len < MAX_UNISTRLEN)
		len = MAX_UNISTRLEN;

	len *= sizeof(uint16);

	str->str.buffer = (uint16 *)talloc_zero(get_talloc_ctx(), len);
	if (str->str.buffer == NULL)
		smb_panic("init_unistr3: malloc fail\n");

	/* store the string (null-terminated copy) */
	dos_struni2((char *)str->str.buffer, buf, len);
}

/*******************************************************************
 Reads or writes a UNISTR3 structure.
********************************************************************/

BOOL smb_io_unistr3(const char *desc, UNISTR3 *name, prs_struct *ps, int depth)
{
	if (name == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_unistr3");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("uni_str_len", ps, depth, &name->uni_str_len))
		return False;

	/* don't know if len is specified by uni_str_len member... */
	/* assume unicode string is unicode-null-terminated, instead */

	if(!prs_unistr3(True, "unistr", name, ps, depth))
		return False;

	return True;
}


/*******************************************************************
 Stream a uint64_struct
 ********************************************************************/
BOOL prs_uint64(const char *name, prs_struct *ps, int depth, UINT64_S *data64)
{
	return prs_uint32(name, ps, depth+1, &data64->low) &&
		prs_uint32(name, ps, depth+1, &data64->high);
}

/*******************************************************************
reads or writes a BUFHDR2 structure.
********************************************************************/
BOOL smb_io_bufhdr2(const char *desc, BUFHDR2 *hdr, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_bufhdr2");
	depth++;

	prs_align(ps);
	prs_uint32("info_level", ps, depth, &(hdr->info_level));
	prs_uint32("length    ", ps, depth, &(hdr->length    ));
	prs_uint32("buffer    ", ps, depth, &(hdr->buffer    ));

	return True;
}

/*******************************************************************
reads or writes a BUFFER4 structure.
********************************************************************/
BOOL smb_io_buffer4(const char *desc, BUFFER4 *buf4, uint32 buffer, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_buffer4");
	depth++;

	prs_align(ps);
	prs_uint32("buf_len", ps, depth, &(buf4->buf_len));

	if (buf4->buf_len > MAX_BUFFERLEN)
	{
		buf4->buf_len = MAX_BUFFERLEN;
	}

	prs_uint8s(True, "buffer", ps, depth, buf4->buffer, buf4->buf_len);

	return True;
}

/*******************************************************************
creates a UNIHDR structure.
********************************************************************/

BOOL make_uni_hdr(UNIHDR *hdr, int len)
{
	if (hdr == NULL)
	{
		return False;
	}
	hdr->uni_str_len = 2 * len;
	hdr->uni_max_len = 2 * len;
	hdr->buffer      = len != 0 ? 1 : 0;

	return True;
}

/*******************************************************************
creates a BUFHDR2 structure.
********************************************************************/
BOOL make_bufhdr2(BUFHDR2 *hdr, uint32 info_level, uint32 length, uint32 buffer)
{
	hdr->info_level = info_level;
	hdr->length     = length;
	hdr->buffer     = buffer;

	return True;
}
