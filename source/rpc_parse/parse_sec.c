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

extern int DEBUGLEVEL;


/*******************************************************************
 Sets up a SEC_ACCESS structure.
********************************************************************/

void init_sec_access(SEC_ACCESS *t, uint32 mask)
{
	t->mask = mask;
}

/*******************************************************************
 Reads or writes a SEC_ACCESS structure.
********************************************************************/

BOOL sec_io_access(char *desc, SEC_ACCESS *t, prs_struct *ps, int depth)
{
	if (t == NULL)
	{
		return False;
	}

	prs_debug(ps, depth, desc, "sec_io_access");
	depth++;

	prs_align(ps);
	
	prs_uint32("mask", ps, depth, &(t->mask));
	return True;
}


/*******************************************************************
 Sets up a SEC_ACE structure.
********************************************************************/

void init_sec_ace(SEC_ACE *t, DOM_SID *sid, uint8 type, SEC_ACCESS mask,
				uint8 flag)
{
	t->type = type;
	t->flags = flag;
	t->size = sid_size(sid) + 8;
	t->info = mask;

	ZERO_STRUCTP(&t->sid);
	sid_copy(&t->sid, sid);
}

/*******************************************************************
 Reads or writes a SEC_ACE structure.
********************************************************************/

BOOL sec_io_ace(char *desc, SEC_ACE *psa, prs_struct *ps, int depth)
{
	uint32 old_offset;
	uint32 offset_ace_size;

	if (psa == NULL)
	{
		return False;
	}

	prs_debug(ps, depth, desc, "sec_io_ace");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint8     ("type ", ps, depth, &psa->type);
	prs_uint8     ("flags", ps, depth, &psa->flags);
	prs_uint16_pre("size ", ps, depth, &psa->size, &offset_ace_size);

	if (!sec_io_access("info ", &psa->info, ps, depth))
	{
		return False;
	}

	prs_align(ps);
	if (!smb_io_dom_sid("sid  ", &psa->sid , ps, depth))
	{
		return False;
	}


	prs_uint16_post("size ", ps, depth, &psa->size, offset_ace_size, old_offset);
	return True;
}

/*******************************************************************
 Create a SEC_ACL structure.  
********************************************************************/

SEC_ACL *make_sec_acl(uint16 revision, int num_aces, SEC_ACE *ace_list)
{
	SEC_ACL *dst;
	int i;

	dst = (SEC_ACL *)malloc(sizeof(SEC_ACL));
	if (dst == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(dst);

	dst->revision = revision;
	dst->num_aces = num_aces;
	dst->size = 4;

	if ((dst->ace_list = (SEC_ACE *)malloc( sizeof(SEC_ACE) * num_aces )) == NULL) {
		free_sec_acl(&dst);
		return NULL;
	}

	for (i = 0; i < num_aces; i++)
	{
		dst->ace_list[i] = ace_list[i]; /* Structure copy. */
		dst->size += ace_list[i].size;
	}

	return dst;
}

/*******************************************************************
 Duplicate a SEC_ACL structure.  
********************************************************************/

SEC_ACL *dup_sec_acl( SEC_ACL *src)
{
	if (src == NULL)
	{
		return NULL;
	}

	return make_sec_acl( src->revision, src->num_aces, src->ace_list);
}

/*******************************************************************
 Delete a SEC_ACL structure.  
********************************************************************/

void free_sec_acl(SEC_ACL **ppsa)
{
	SEC_ACL *psa;

	if (ppsa == NULL || *ppsa == NULL)
	{
		return;
	}

	psa = *ppsa;
	if (psa->ace_list != NULL)
	{
		free(psa->ace_list);
	}

	free(psa);
	*ppsa = NULL;
}

/*******************************************************************
 Reads or writes a SEC_ACL structure.  

 First of the xx_io_xx functions that allocates its data structures
 for you as it reads them.
********************************************************************/

BOOL sec_io_acl(char *desc, SEC_ACL **ppsa, prs_struct *ps, int depth)
{
	int i;
	uint32 old_offset;
	uint32 offset_acl_size;
	SEC_ACL *psa;

	if (ppsa == NULL)
	{
		return False;
	}

	psa = *ppsa;

	if (ps->io && psa == NULL)
	{
		/*
		 * This is a read and we must allocate the stuct to read into.
		 */
		psa = (SEC_ACL *)malloc(sizeof(SEC_ACL));
		if (psa == NULL)
		{
			return False;
		}
		ZERO_STRUCTP(psa);
		*ppsa = psa;
	}

	prs_debug(ps, depth, desc, "sec_io_acl");
	depth++;

	prs_align(ps);
	
	old_offset = ps->offset;

	prs_uint16("revision", ps, depth, &psa->revision);
	prs_uint16_pre("size     ", ps, depth, &psa->size, &offset_acl_size);
	prs_uint32("num_aces ", ps, depth, &psa->num_aces);

	if (ps->io && psa->num_aces != 0)
	{
		/* reading */
		psa->ace_list = malloc(sizeof(psa->ace_list[0]) * psa->num_aces);
		if (psa->ace_list == NULL)
		{
			return False;
		}
		ZERO_STRUCTP(psa->ace_list);
	}

	for (i = 0; i < MIN(psa->num_aces, MAX_SEC_ACES); i++)
	{
		fstring tmp;
		slprintf(tmp, sizeof(tmp)-1, "ace_list[%02d]: ", i);
		if (!sec_io_ace(tmp, &psa->ace_list[i], ps, depth))
		{
			return False;
		}
	}

	prs_align(ps);

	prs_uint16_post("size     ", ps, depth, &psa->size, offset_acl_size, old_offset);

	return True;
}


/*******************************************************************
 Creates a SEC_DESC structure
********************************************************************/

SEC_DESC *make_sec_desc(uint16 revision, uint16 type,
			DOM_SID *owner_sid, DOM_SID *grp_sid,
			SEC_ACL *sacl, SEC_ACL *dacl, size_t *sec_desc_size)
{
	SEC_DESC *dst;
	uint32 offset;

	*sec_desc_size = 0;

	dst = (SEC_DESC *)malloc(sizeof(SEC_DESC));

	if (dst == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(dst);

	dst->revision = revision;
	dst->type     = type;

	dst->off_owner_sid = 0;
	dst->off_grp_sid   = 0;
	dst->off_sacl      = 0;
	dst->off_dacl      = 0;

	/* duplicate sids and acls as necessary */

	if (dacl      != NULL) dst->dacl      = dup_sec_acl(dacl);
	if (sacl      != NULL) dst->sacl      = dup_sec_acl(sacl);
	if (owner_sid != NULL) dst->owner_sid = sid_dup(owner_sid);
	if (grp_sid   != NULL) dst->grp_sid   = sid_dup(grp_sid);

	/* having duplicated sids and acls as necessary, check success */

	if ((dacl      != NULL && dst->dacl      == NULL) ||
	    (sacl      != NULL && dst->sacl      == NULL) ||
	    (owner_sid != NULL && dst->owner_sid == NULL) ||
	    (grp_sid   != NULL && dst->grp_sid   == NULL))
	{
		*sec_desc_size = 0;
		free_sec_desc(&dst);

		return NULL;
	}

	offset = 0x0;

	/*
	 * Work out the linearization sizes.
	 */

	if (dst->dacl != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		dst->off_dacl = offset;
		offset += dacl->size;
	}

	if (dst->sacl != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		dst->off_sacl = offset;
		offset += sacl->size;
	}

	if (dst->owner_sid != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		dst->off_owner_sid = offset;
		offset += sid_size(dst->owner_sid);
	}

	if (dst->grp_sid != NULL)
	{
		if (offset == 0)
		{
			offset = 0x14;
		}
		dst->off_grp_sid = offset;
		offset += sid_size(dst->grp_sid);
	}

	*sec_desc_size = (size_t)((offset == 0) ? 0x14 : offset);
	return dst;
}

/*******************************************************************
 Duplicate a SEC_DESC structure.  
********************************************************************/

SEC_DESC *dup_sec_desc( SEC_DESC *src)
{
	size_t dummy;

	if (src == NULL)
		return NULL;

	return make_sec_desc( src->revision, src->type, 
				src->owner_sid, src->grp_sid, src->sacl,
				src->dacl, &dummy);
}

/*******************************************************************
 Deletes a SEC_DESC structure
********************************************************************/

void free_sec_desc(SEC_DESC **ppsd)
{
	SEC_DESC *psd;

	if (ppsd == NULL || *ppsd == NULL)
	{
		return;
	}

	psd = *ppsd;

	free_sec_acl(&psd->dacl);
	free_sec_acl(&psd->dacl);
	free(psd->owner_sid);
	free(psd->grp_sid);
	free(psd);
	*ppsd = NULL;
}

/*******************************************************************
 Creates a SEC_DESC structure with typical defaults.
********************************************************************/

SEC_DESC *make_standard_sec_desc(DOM_SID *owner_sid, DOM_SID *grp_sid,
				 SEC_ACL *dacl, size_t *sec_desc_size)
{
	return make_sec_desc(1, SEC_DESC_SELF_RELATIVE|SEC_DESC_DACL_PRESENT,
	                     owner_sid, grp_sid, NULL, dacl, sec_desc_size);
}


/*******************************************************************
 Reads or writes a SEC_DESC structure.
 If reading and the *ppsd = NULL, allocates the structure.
********************************************************************/

BOOL sec_io_desc(char *desc, SEC_DESC **ppsd, prs_struct *ps, int depth)
{
	uint32 old_offset;
	uint32 max_offset = 0; /* after we're done, move offset to end */
	SEC_DESC *psd;

	if (ppsd == NULL)
		return False;

	psd = *ppsd;

	if (ps->io && psd == NULL)
	{
		psd = (SEC_DESC *)malloc(sizeof(SEC_DESC));
		if (psd == NULL)
		{
			return False;
		}
		ZERO_STRUCTP(psd);
		*ppsd = psd;
	}

	prs_debug(ps, depth, desc, "sec_io_desc");
	depth++;

	prs_align(ps);
	
	/* start of security descriptor stored for back-calc offset purposes */
	old_offset = ps->offset;

	prs_uint16("revision ", ps, depth, &psd->revision);
	prs_uint16("type     ", ps, depth, &psd->type);

	prs_uint32("off_owner_sid", ps, depth, &psd->off_owner_sid);
	prs_uint32("off_grp_sid  ", ps, depth, &psd->off_grp_sid);
	prs_uint32("off_sacl     ", ps, depth, &psd->off_sacl);
	prs_uint32("off_dacl     ", ps, depth, &psd->off_dacl);

	max_offset = MAX(max_offset, ps->offset);

	if (IS_BITS_SET_ALL(psd->type, SEC_DESC_DACL_PRESENT) && psd->dacl)
	{
		ps->offset = old_offset + psd->off_dacl;
		if (!sec_io_acl("dacl", &psd->dacl, ps, depth))
		{
			return False;
		}
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

	if (IS_BITS_SET_ALL(psd->type, SEC_DESC_SACL_PRESENT) && psd->sacl)
	{
		ps->offset = old_offset + psd->off_sacl;
		if (!sec_io_acl("sacl", &psd->sacl, ps, depth))
		{
			return False;
		}
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

	if (psd->off_owner_sid != 0)
	{
		if (ps->io)
		{
			ps->offset = old_offset + psd->off_owner_sid;
			/* reading */
			psd->owner_sid = malloc(sizeof(*psd->owner_sid));
			if (psd->owner_sid == NULL)
			{
				return False;
			}
			ZERO_STRUCTP(psd->owner_sid);
		}

		if (!smb_io_dom_sid("owner_sid ", psd->owner_sid , ps, depth))
		{
			return False;
		}
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

	if (psd->off_grp_sid != 0)
	{
		if (ps->io)
		{
			/* reading */
			ps->offset = old_offset + psd->off_grp_sid;
			psd->grp_sid = malloc(sizeof(*psd->grp_sid));
			if (psd->grp_sid == NULL)
			{
				return False;
			}
			ZERO_STRUCTP(psd->grp_sid);
		}

		if (!smb_io_dom_sid("grp_sid", psd->grp_sid, ps, depth))
		{
			return False;
		}
		prs_align(ps);
	}

	max_offset = MAX(max_offset, ps->offset);

	ps->offset = max_offset;
	return True;
}

/*******************************************************************
 Creates a SEC_DESC_BUF structure.
********************************************************************/

SEC_DESC_BUF *make_sec_desc_buf(int len, SEC_DESC *sec_desc)
{
	SEC_DESC_BUF *dst;

	dst = (SEC_DESC_BUF *)malloc(sizeof(SEC_DESC_BUF));
	if (dst == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(dst);

	/* max buffer size (allocated size) */
	dst->max_len = len;
	dst->len = len;

	if (sec_desc && ((dst->sec = dup_sec_desc(sec_desc)) == NULL))
	{
		free_sec_desc_buf(&dst);
		return NULL;
	}

	return dst;
}

/*******************************************************************
 Duplicates a SEC_DESC_BUF structure.
********************************************************************/

SEC_DESC_BUF *dup_sec_desc_buf(SEC_DESC_BUF *src)
{
	if (src == NULL)
	{
		return NULL;
	}

	return make_sec_desc_buf( src->len, src->sec);
}

/*******************************************************************
 Deletes a SEC_DESC_BUF structure.
********************************************************************/

void free_sec_desc_buf(SEC_DESC_BUF **ppsdb)
{
	SEC_DESC_BUF *psdb;

	if (ppsdb == NULL || *ppsdb == NULL)
	{
		return;
	}

	psdb = *ppsdb;
	free_sec_desc(&psdb->sec);
	free(psdb);
	*ppsdb = NULL;
}


/*******************************************************************
 Reads or writes a SEC_DESC_BUF structure.
********************************************************************/

BOOL sec_io_desc_buf(char *desc, SEC_DESC_BUF **ppsdb, prs_struct *ps, int depth)
{
	uint32 off_len;
	uint32 off_max_len;
	uint32 old_offset;
	uint32 size;
	SEC_DESC_BUF *psdb;

	if (ppsdb == NULL)
	{
		return False;
	}

	psdb = *ppsdb;

	if (ps->io && psdb == NULL)
	{
		psdb = (SEC_DESC_BUF *)malloc(sizeof(SEC_DESC_BUF));
		if (psdb == NULL)
		{
			return False;
		}
		ZERO_STRUCTP(psdb);
		*ppsdb = psdb;
	}

	prs_debug(ps, depth, desc, "sec_io_desc_buf");
	depth++;

	prs_align(ps);
	
	prs_uint32_pre("max_len", ps, depth, &psdb->max_len, &off_max_len);
	prs_uint32    ("undoc  ", ps, depth, &psdb->undoc);
	prs_uint32_pre("len    ", ps, depth, &psdb->len, &off_len);

	old_offset = ps->offset;

	/* reading, length is non-zero; writing, descriptor is non-NULL */
	if ((psdb->len != 0 || (!ps->io)) && psdb->sec != NULL)
	{
		if (!sec_io_desc("sec   ", &psdb->sec, ps, depth))
		{
			return False;
		}
	}

	size = ps->offset - old_offset;
	prs_uint32_post("max_len", ps, depth, &psdb->max_len, off_max_len, size == 0 ? psdb->max_len : size);
	prs_uint32_post("len    ", ps, depth, &psdb->len, off_len, size);

	return True;
}

