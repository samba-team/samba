
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
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

extern int DEBUGLEVEL;


/*******************************************************************
reads or writes a structure.
********************************************************************/
void sec_io_info(char *desc, SEC_INFO *t, prs_struct *ps, int depth)
{
	if (t == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_info");
	depth++;

	prs_align(ps);
	
	prs_uint32("perms", ps, depth, &(t->perms));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void sec_io_ace(char *desc, SEC_ACE *t, prs_struct *ps, int depth)
{
	uint32 old_offset;
	uint32 offset_ace_size;
	if (t == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_ace");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint8     ("type ", ps, depth, &(t->type));
	prs_uint8     ("flags", ps, depth, &(t->flags));
	prs_uint16_pre("size ", ps, depth, &(t->size ), &offset_ace_size);

	sec_io_info   ("info ", &t->info, ps, depth);
	prs_align(ps);
	smb_io_dom_sid("sid  ", &t->sid , ps, depth);

	prs_uint16_post("size ", ps, depth, &t->size, offset_ace_size, old_offset);
}

/*******************************************************************
reads or writes a structure.  this is one of those retrospective jobs,
which i hate.  why do we have to do this?  what's it all about?
********************************************************************/
void sec_io_acl(char *desc, SEC_ACL *t, prs_struct *ps, int depth)
{
	int i;
	uint32 old_offset;
	uint32 offset_acl_size;

	if (t == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_acl");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint16("revision", ps, depth, &(t->revision));
	prs_uint16_pre("size     ", ps, depth, &(t->size     ), &offset_acl_size);
	prs_uint32("num_aces ", ps, depth, &(t->num_aces ));

	for (i = 0; i < MIN(t->num_aces, MAX_SEC_ACES); i++)
	{
		fstring tmp;
		snprintf(tmp, sizeof(tmp), "ace[%02d]: ", i);
		sec_io_ace(tmp, &t->ace[i], ps, depth);
	}

	prs_align(ps);

	prs_uint16_post("size     ", ps, depth, &t->size    , offset_acl_size, old_offset);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
static void sec_io_desc(char *desc, SEC_DESC *t, prs_struct *ps, int depth)
{
	uint32 off_owner_sid;
	uint32 off_grp_sid  ;
	uint32 off_sacl     ;
	uint32 off_dacl      ;
	uint32 old_offset;

	if (t == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_desc");
	depth++;

	prs_align(ps);
	
	/* start of security descriptor stored for back-calc offset purposes */
	old_offset = ps->offset;

	prs_uint16("revision ", ps, depth, &(t->revision ));
	prs_uint16("type     ", ps, depth, &(t->type     ));

	prs_uint32_pre("off_owner_sid", ps, depth, &(t->off_owner_sid), &off_owner_sid);
	prs_uint32_pre("off_grp_sid  ", ps, depth, &(t->off_grp_sid  ), &off_grp_sid  );
	prs_uint32_pre("off_sacl     ", ps, depth, &(t->off_sacl     ), &off_sacl     );
	prs_uint32_pre("off_dacl     ", ps, depth, &(t->off_dacl     ), &off_dacl     );

	if (IS_BITS_SET_ALL(t->type, SEC_DESC_DACL_PRESENT))
	{
		prs_uint32_post("off_dacl    ", ps, depth, &(t->off_dacl     ), off_dacl     , ps->offset - old_offset);
		ps->offset = old_offset + t->off_dacl;
		sec_io_acl     ("dacl"        , &t->dacl       , ps, depth);
		prs_align(ps);
	}
	else
	{
		prs_uint32_post("off_dacl    ", ps, depth, &(t->off_dacl     ), off_dacl     , 0);
	}

	if (IS_BITS_SET_ALL(t->type, SEC_DESC_SACL_PRESENT))
	{
		prs_uint32_post("off_sacl  ", ps, depth, &(t->off_sacl  ), off_sacl  , ps->offset - old_offset);
		ps->offset = old_offset + t->off_sacl;
		sec_io_acl     ("sacl"      , &t->sacl       , ps, depth);
		prs_align(ps);
	}
	else
	{
		prs_uint32_post("off_sacl  ", ps, depth, &(t->off_sacl  ), off_sacl  , 0);
	}

	prs_uint32_post("off_owner_sid", ps, depth, &(t->off_owner_sid), off_owner_sid, ps->offset - old_offset);
	if (t->off_owner_sid != 0)
	{
		if (ps->io)
		{
			ps->offset = old_offset + t->off_owner_sid;
		}
		smb_io_dom_sid("owner_sid ", &t->owner_sid , ps, depth);
		prs_align(ps);
	}

	prs_uint32_post("off_grp_sid  ", ps, depth, &(t->off_grp_sid  ), off_grp_sid  , ps->offset - old_offset);
	if (t->off_grp_sid != 0)
	{
		if (ps->io)
		{
			ps->offset = old_offset + t->off_grp_sid;
		}
		smb_io_dom_sid("grp_sid", &t->grp_sid, ps, depth);
		prs_align(ps);
	}
}

/*******************************************************************
creates a SEC_DESC_BUF structure.
********************************************************************/
void make_sec_desc_buf(SEC_DESC_BUF *buf, int len, SEC_DESC *data)
{
	ZERO_STRUCTP(buf);

	/* max buffer size (allocated size) */
	buf->max_len = len;
	buf->undoc       = 0;
	buf->len = data != NULL ? len : 0;
	buf->sec = data;
}


/*******************************************************************
reads or writes a SEC_DESC_BUF structure.
********************************************************************/
void sec_io_desc_buf(char *desc, SEC_DESC_BUF *sec, prs_struct *ps, int depth)
{
	uint32 off_len;
	uint32 off_max_len;
	uint32 old_offset;
	uint32 size;

	if (sec == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_desc_buf");
	depth++;

	prs_align(ps);
	
	prs_uint32_pre("max_len", ps, depth, &(sec->max_len), &off_max_len);
	prs_uint32    ("undoc  ", ps, depth, &(sec->undoc  ));
	prs_uint32_pre("len    ", ps, depth, &(sec->len    ), &off_len);

	old_offset = ps->offset;

	/* reading, length is non-zero; writing, descriptor is non-NULL */
	if ((sec->len != 0 || (!ps->io)) && sec->sec != NULL)
	{
		sec_io_desc("sec   ", sec->sec, ps, depth);
	}

	size = ps->offset - old_offset;
	prs_uint32_post("max_len", ps, depth, &(sec->max_len), off_max_len, size == 0 ? sec->max_len : size);
	prs_uint32_post("len    ", ps, depth, &(sec->len    ), off_len    , size);
}

