
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

	prs_uint16("unknown_1", ps, depth, &(t->unknown_1));
	prs_uint16_pre("ace_size ", ps, depth, &(t->ace_size ), &offset_ace_size);

	sec_io_info   ("info", &t->info, ps, depth);
	prs_align(ps);
	smb_io_dom_sid("sid ", &t->sid , ps, depth);

	prs_uint16_post("ace_size ", ps, depth, &t->ace_size, offset_ace_size, old_offset);
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

	prs_uint16("unknown_1", ps, depth, &(t->unknown_1));
	prs_uint16_pre("acl_size ", ps, depth, &(t->acl_size ), &offset_acl_size);
	prs_uint32("num_aces ", ps, depth, &(t->num_aces ));

	for (i = 0; i < MIN(t->num_aces, MAX_SEC_ACES); i++)
	{
		fstring tmp;
		snprintf(tmp, sizeof(tmp), "ace[%02d]: ", i);
		sec_io_ace(tmp, &t->ace[i], ps, depth);
	}

	prs_align(ps);

	prs_uint16_post("acl_size ", ps, depth, &t->acl_size, offset_acl_size, old_offset);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void sec_io_desc(char *desc, SEC_DESC *t, prs_struct *ps, int depth)
{
	uint32 off_owner_sid;
	uint32 off_pnt_sid  ;
	uint32 off_unknown  ;
	uint32 off_acl      ;
	uint32 old_offset;

	if (t == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_desc");
	depth++;

	prs_align(ps);
	
	/* start of security descriptor stored for back-calc offset purposes */
	old_offset = ps->offset;

	prs_uint32("unknown_1", ps, depth, &(t->unknown_1));

	prs_uint32_pre("off_owner_sid", ps, depth, &(t->off_owner_sid), &off_owner_sid);
	prs_uint32_pre("off_pnt_sid  ", ps, depth, &(t->off_pnt_sid  ), &off_pnt_sid  );
	prs_uint32_pre("off_unknown  ", ps, depth, &(t->off_unknown  ), &off_unknown  );
	prs_uint32_pre("off_acl      ", ps, depth, &(t->off_acl      ), &off_acl      );

	prs_uint32_post("off_acl     ", ps, depth, &(t->off_acl      ), off_acl      , old_offset);
	sec_io_acl    ("acl"       , &t->acl       , ps, depth);
	prs_align(ps);

	prs_uint32_post("off_unknown  ", ps, depth, &(t->off_unknown  ), off_unknown  , ps->offset);

	prs_uint32_post("off_owner_sid", ps, depth, &(t->off_owner_sid), off_owner_sid, old_offset);
	smb_io_dom_sid("owner_sid ", &t->owner_sid , ps, depth);
	prs_align(ps);

	prs_uint32_post("off_pnt_sid  ", ps, depth, &(t->off_pnt_sid  ), off_pnt_sid  , old_offset);
	smb_io_dom_sid("parent_sid", &t->parent_sid, ps, depth);
	prs_align(ps);
}

/*******************************************************************
reads or writes a SEC_DESC_BUF structure.
********************************************************************/
void sec_io_desc_buf(char *desc, SEC_DESC_BUF *sec, prs_struct *ps, int depth)
{
	uint32 off_len;
	uint32 old_offset;

	if (sec == NULL) return;

	prs_debug(ps, depth, desc, "sec_io_desc_buf");
	depth++;

	prs_align(ps);
	
	prs_uint32    ("max_len", ps, depth, &(sec->max_len));
	prs_uint32    ("undoc  ", ps, depth, &(sec->undoc  ));
	prs_uint32_pre("len    ", ps, depth, &(sec->len    ), &off_len);

	old_offset = ps->offset;

	/* reading, length is non-zero; writing, descriptor is non-NULL */
	if ((sec->len != 0 || (!ps->io)) && sec->sec != NULL)
	{
		sec_io_desc("sec   ", sec->sec, ps, depth);
	}

	prs_uint32_post("len    ", ps, depth, &(sec->len    ), off_len    , old_offset);
}

