/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Jeremy R. Allison            1995-1999
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Paul Ashton                  1997-1999.
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
#include "rpc_parse.h"

extern int DEBUGLEVEL;


/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_sec_access(SEC_ACCESS *t, uint32 mask)
{
	t->mask = mask;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sec_io_access(char *desc, SEC_ACCESS *t, prs_struct *ps, int depth)
{
	if (t == NULL) return False;

	prs_debug(ps, depth, desc, "sec_io_access");
	depth++;

	prs_align(ps);
	
	prs_uint32("mask", ps, depth, &(t->mask));

	return True;
}


/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_sec_ace(SEC_ACE *t, DOM_SID *sid, uint8 type, SEC_ACCESS mask, uint8 flag)
{
	t->type = type;
	t->flags = flag;
	t->size = sid_size(sid) + 8;
	t->info = mask;

	sid_copy(&t->sid, sid);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sec_io_ace(char *desc, SEC_ACE *t, prs_struct *ps, int depth)
{
	uint32 old_offset;
	uint32 offset_ace_size;
	if (t == NULL) return False;

	prs_debug(ps, depth, desc, "sec_io_ace");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint8     ("type ", ps, depth, &(t->type));
	prs_uint8     ("flags", ps, depth, &(t->flags));
	prs_uint16_pre("size ", ps, depth, &(t->size ), &offset_ace_size);

	sec_io_access   ("info ", &t->info, ps, depth);
	prs_align(ps);
	smb_io_dom_sid("sid  ", &t->sid , ps, depth);
	prs_align(ps);

	prs_uint16_post("size ", ps, depth, &t->size, offset_ace_size, old_offset);

	return True;
}

/*******************************************************************
makes a structure.  
********************************************************************/
BOOL make_sec_acl(SEC_ACL *t, uint16 revision, int num_aces, SEC_ACE *ace)
{
	int i;
	t->revision = revision;
	t->num_aces = num_aces;
	t->size = 4;
	t->ace = ace;

	for (i = 0; i < num_aces; i++)
	{
		t->size += ace[i].size;
	}

	return True;
}

/*******************************************************************
frees a structure.  
********************************************************************/
void free_sec_acl(SEC_ACL *t)
{
	if (t->ace != NULL)
	{
		free(t->ace);
	}
}

/*******************************************************************
reads or writes a structure.  

first of the xx_io_xx functions that allocates its data structures
 for you as it reads them.
********************************************************************/
BOOL sec_io_acl(char *desc, SEC_ACL *t, prs_struct *ps, int depth)
{
	uint32 i;
	uint32 old_offset;
	uint32 offset_acl_size;

	if (t == NULL) return False;

	prs_debug(ps, depth, desc, "sec_io_acl");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint16("revision", ps, depth, &(t->revision));
	prs_uint16_pre("size     ", ps, depth, &(t->size     ), &offset_acl_size);
	prs_uint32("num_aces ", ps, depth, &(t->num_aces ));

	if (ps->io && t->num_aces != 0)
	{
		/* reading */
		t->ace = (SEC_ACE*)malloc(sizeof(t->ace[0]) * t->num_aces);
		ZERO_STRUCTP(t->ace);
		}

	if (t->ace == NULL && t->num_aces != 0)
	{
		DEBUG(0,("INVALID ACL\n"));
		ps->offset = 0xfffffffe;
		return False;
	}

	for (i = 0; i < MIN(t->num_aces, MAX_SEC_ACES); i++)
	{
		fstring tmp;
		slprintf(tmp, sizeof(tmp)-1, "ace[%02d]: ", i);
		sec_io_ace(tmp, &t->ace[i], ps, depth);
	}

	prs_align(ps);

	prs_uint16_post("size     ", ps, depth, &t->size    , offset_acl_size, old_offset);

	return True;
}


/*******************************************************************
makes a structure
********************************************************************/
int make_sec_desc(SEC_DESC *t, uint16 revision, uint16 type,
			DOM_SID *owner_sid, DOM_SID *grp_sid,
				SEC_ACL *sacl, SEC_ACL *dacl)
{
	uint32 offset;

	t->revision = revision;
	t->type     = type;

	t->off_owner_sid = 0;
	t->off_grp_sid   = 0;
	t->off_sacl      = 0;
	t->off_dacl      = 0;

	t->dacl      = dacl;
	t->sacl      = sacl;
	t->owner_sid = owner_sid;
	t->grp_sid   = grp_sid;

	offset = 0x0;

	if (dacl != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		t->off_dacl = offset;
		offset += dacl->size;
	}

	if (sacl != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		t->off_dacl = offset;
		offset += dacl->size;
	}

	if (owner_sid != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		t->off_owner_sid = offset;
		offset += sid_size(owner_sid);
	}

	if (grp_sid != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		t->off_grp_sid = offset;
		offset += sid_size(grp_sid);
	}

	return (offset == 0) ? 0x14 : offset;
}


/*******************************************************************
frees a structure
********************************************************************/
void free_sec_desc(SEC_DESC *t)
{
	if (t->dacl != NULL)
	{
		free_sec_acl(t->dacl);
	}

	if (t->sacl != NULL)
	{
		free_sec_acl(t->dacl);

	}

	if (t->owner_sid != NULL)
	{
		free(t->owner_sid);
	}

	if (t->grp_sid != NULL)
	{
		free(t->grp_sid);
	}
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL sec_io_desc(char *desc, SEC_DESC *t, prs_struct *ps, int depth)
{
#if 0
	uint32 off_owner_sid;
	uint32 off_grp_sid  ;
	uint32 off_sacl     ;
	uint32 off_dacl     ;
#endif
	uint32 old_offset;
	uint32 max_offset = 0; /* after we're done, move offset to end */

	if (t == NULL) return False;

	prs_debug(ps, depth, desc, "sec_io_desc");
	depth++;

	prs_align(ps);
	
	/* start of security descriptor stored for back-calc offset purposes */
	old_offset = ps->offset;
	max_offset = old_offset;

	prs_uint16("revision ", ps, depth, &(t->revision ));
	prs_uint16("type     ", ps, depth, &(t->type     ));

	prs_uint32("off_owner_sid", ps, depth, &(t->off_owner_sid));
	prs_uint32("off_grp_sid  ", ps, depth, &(t->off_grp_sid  ));
	prs_uint32("off_sacl     ", ps, depth, &(t->off_sacl     ));
	prs_uint32("off_dacl     ", ps, depth, &(t->off_dacl     ));
#if 0
	prs_uint32_pre("off_owner_sid", ps, depth, &(t->off_owner_sid), &off_owner_sid);
	prs_uint32_pre("off_grp_sid  ", ps, depth, &(t->off_grp_sid  ), &off_grp_sid  );
	prs_uint32_pre("off_sacl     ", ps, depth, &(t->off_sacl     ), &off_sacl     );
	prs_uint32_pre("off_dacl     ", ps, depth, &(t->off_dacl     ), &off_dacl     );
#endif
	max_offset = MAX(max_offset, ps->offset);

	if (IS_BITS_SET_ALL(t->type, SEC_DESC_DACL_PRESENT))
	{
#if 0
		prs_uint32_post("off_dacl    ", ps, depth, &(t->off_dacl     ), off_dacl     , ps->offset - old_offset);
#endif
		ps->offset = old_offset + t->off_dacl;
		if (ps->io)
		{
			/* reading */
			t->dacl = (SEC_ACL*)malloc(sizeof(*t->dacl));
			ZERO_STRUCTP(t->dacl);
		}

		if (t->dacl == NULL)
		{
			DEBUG(0,("INVALID DACL\n"));
			ps->offset = 0xfffffffe;
			return False;
		}

		sec_io_acl     ("dacl"        , t->dacl       , ps, depth);
		prs_align(ps);
	}
#if 0
	else
	{
		prs_uint32_post("off_dacl    ", ps, depth, &(t->off_dacl     ), off_dacl     , 0);
	}
#endif

	max_offset = MAX(max_offset, ps->offset);

	if (IS_BITS_SET_ALL(t->type, SEC_DESC_SACL_PRESENT))
	{
#if 0
		prs_uint32_post("off_sacl  ", ps, depth, &(t->off_sacl  ), off_sacl  , ps->offset - old_offset);
#endif
		ps->offset = old_offset + t->off_sacl;
		if (ps->io)
		{
			/* reading */
			t->sacl = (SEC_ACL*)malloc(sizeof(*t->sacl));
			ZERO_STRUCTP(t->sacl);
		}

		if (t->sacl == NULL)
		{
			DEBUG(0,("INVALID SACL\n"));
			ps->offset = 0xfffffffe;
			return False;
		}

		sec_io_acl     ("sacl"      , t->sacl       , ps, depth);
		prs_align(ps);
	}
#if 0
	else
	{
		prs_uint32_post("off_sacl  ", ps, depth, &(t->off_sacl  ), off_sacl  , 0);
	}
#endif

	max_offset = MAX(max_offset, ps->offset);

#if 0
	prs_uint32_post("off_owner_sid", ps, depth, &(t->off_owner_sid), off_owner_sid, ps->offset - old_offset);
#endif
	if (t->off_owner_sid != 0)
	{
		if (ps->io)
		{
			ps->offset = old_offset + t->off_owner_sid;
			}
		if (ps->io)
		{
			/* reading */
			t->owner_sid = (DOM_SID*)malloc(sizeof(*t->owner_sid));
			ZERO_STRUCTP(t->owner_sid);
		}

		if (t->owner_sid == NULL)
		{
			DEBUG(0,("INVALID OWNER SID\n"));
			ps->offset = 0xfffffffe;
			return False;
		}

		smb_io_dom_sid("owner_sid ", t->owner_sid , ps, depth);
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

#if 0
	prs_uint32_post("off_grp_sid  ", ps, depth, &(t->off_grp_sid  ), off_grp_sid  , ps->offset - old_offset);
#endif
	if (t->off_grp_sid != 0)
	{
		if (ps->io)
		{
			ps->offset = old_offset + t->off_grp_sid;

		}
		if (ps->io)
		{
			/* reading */
			t->grp_sid = (DOM_SID*)malloc(sizeof(*t->grp_sid));
			ZERO_STRUCTP(t->grp_sid);
		}

		if (t->grp_sid == NULL)
		{
			DEBUG(0,("INVALID GROUP SID\n"));
			ps->offset = 0xfffffffe;
			return False;
		}

		smb_io_dom_sid("grp_sid", t->grp_sid, ps, depth);
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

	ps->offset = max_offset;

	return True;
}

/*******************************************************************
creates a SEC_DESC_BUF structure.
********************************************************************/
BOOL make_sec_desc_buf(SEC_DESC_BUF *buf, int len, SEC_DESC *data)
{
	ZERO_STRUCTP(buf);

	/* max buffer size (allocated size) */
	buf->max_len = len;
	buf->undoc       = 0;
	buf->len = data != NULL ? len : 0;
	buf->sec = data;

	return True;
}

/*******************************************************************
frees a SEC_DESC_BUF structure.
********************************************************************/
void free_sec_desc_buf(SEC_DESC_BUF *buf)
{
	if (buf->sec != NULL)
	{
		free_sec_desc(buf->sec);
		free(buf->sec);
	}
}


/*******************************************************************
reads or writes a SEC_DESC_BUF structure.
********************************************************************/
BOOL sec_io_desc_buf(char *desc, SEC_DESC_BUF *sec, prs_struct *ps, int depth)
{
	uint32 off_len;
	uint32 off_max_len;
	uint32 old_offset;
	uint32 size;

	if (sec == NULL) return False;

	prs_debug(ps, depth, desc, "sec_io_desc_buf");
	depth++;

	prs_align(ps);
	
	prs_uint32_pre("max_len", ps, depth, &(sec->max_len), &off_max_len);
	prs_uint32    ("undoc  ", ps, depth, &(sec->undoc  ));
	prs_uint32_pre("len    ", ps, depth, &(sec->len    ), &off_len);

	old_offset = ps->offset;

	if (sec->len != 0 && ps->io)
	{
		/* reading */
		sec->sec = (SEC_DESC*)malloc(sizeof(*sec->sec));
		ZERO_STRUCTP(sec->sec);

		if (sec->sec == NULL)
		{
			DEBUG(0,("INVALID SEC_DESC\n"));
			ps->offset = 0xfffffffe;
			return False;
		}
	}

	/* reading, length is non-zero; writing, descriptor is non-NULL */
	if ((sec->len != 0 || (!ps->io)) && sec->sec != NULL)
	{
		sec_io_desc("sec   ", sec->sec, ps, depth);
	}

	prs_align(ps);
	
	size = ps->offset - old_offset - 8;
	prs_uint32_post("max_len", ps, depth, &(sec->max_len), off_max_len, size == 0 ? sec->max_len : size + 8);
	prs_uint32_post("len    ", ps, depth, &(sec->len    ), off_len    , size == 0 ? 0 : size + 8);

	ps->offset = old_offset + size + 8;

	return True;
}

