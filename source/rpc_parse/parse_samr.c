/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Elrond                            2000,
 *  Copyright (C) Jeremy Allison                    2001,
 *  Copyright (C) Jean François Micouleau      1998-2001,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002.
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
reads or writes a SAM_ENTRY structure.
********************************************************************/

static bool sam_io_sam_entry(const char *desc, SAM_ENTRY * sam,
			     prs_struct *ps, int depth)
{
	if (sam == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_sam_entry");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("rid", ps, depth, &sam->rid))
		return False;
	if(!smb_io_unihdr("unihdr", &sam->hdr_name, ps, depth))	/* account name unicode string header */
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_Q_ENUM_DOM_GROUPS structure.
********************************************************************/

void init_samr_q_enum_dom_groups(SAMR_Q_ENUM_DOM_GROUPS * q_e,
				 POLICY_HND *pol,
				 uint32 start_idx, uint32 size)
{
	DEBUG(5, ("init_samr_q_enum_dom_groups\n"));

	q_e->pol = *pol;

	q_e->start_idx = start_idx;
	q_e->max_size = size;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_q_enum_dom_groups(const char *desc, SAMR_Q_ENUM_DOM_GROUPS * q_e,
			       prs_struct *ps, int depth)
{
	if (q_e == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_groups");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("pol", &(q_e->pol), ps, depth))
		return False;

	if(!prs_uint32("start_idx", ps, depth, &q_e->start_idx))
		return False;
	if(!prs_uint32("max_size ", ps, depth, &q_e->max_size))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_R_ENUM_DOM_GROUPS structure.
********************************************************************/

void init_samr_r_enum_dom_groups(SAMR_R_ENUM_DOM_GROUPS * r_u,
				 uint32 next_idx, uint32 num_sam_entries)
{
	DEBUG(5, ("init_samr_r_enum_dom_groups\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0) {
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	} else {
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_r_enum_dom_groups(const char *desc, SAMR_R_ENUM_DOM_GROUPS * r_u,
			       prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_groups");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("next_idx    ", ps, depth, &r_u->next_idx))
		return False;
	if(!prs_uint32("ptr_entries1", ps, depth, &r_u->ptr_entries1))
		return False;

	if (r_u->ptr_entries1 != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &r_u->num_entries2))
			return False;
		if(!prs_uint32("ptr_entries2", ps, depth, &r_u->ptr_entries2))
			return False;
		if(!prs_uint32("num_entries3", ps, depth, &r_u->num_entries3))
			return False;

		if (UNMARSHALLING(ps) && r_u->num_entries2) {
			r_u->sam = PRS_ALLOC_MEM(ps,SAM_ENTRY,r_u->num_entries2);
			r_u->uni_grp_name = PRS_ALLOC_MEM(ps,UNISTR2,r_u->num_entries2);
		}

		if ((r_u->sam == NULL || r_u->uni_grp_name == NULL) && r_u->num_entries2 != 0) {
			DEBUG(0,
			      ("NULL pointers in SAMR_R_ENUM_DOM_GROUPS\n"));
			r_u->num_entries4 = 0;
			r_u->status = NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)	{
			if(!sam_io_sam_entry("", &r_u->sam[i], ps, depth))
				return False;
		}

		for (i = 0; i < r_u->num_entries2; i++)	{
			if(!smb_io_unistr2("", &r_u->uni_grp_name[i],
				       r_u->sam[i].hdr_name.buffer, ps, depth))
				return False;
		}
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries4", ps, depth, &r_u->num_entries4))
		return False;
	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_Q_ENUM_DOM_ALIASES structure.
********************************************************************/

void init_samr_q_enum_dom_aliases(SAMR_Q_ENUM_DOM_ALIASES * q_e,
				  POLICY_HND *pol, uint32 start_idx,
				  uint32 size)
{
	DEBUG(5, ("init_samr_q_enum_dom_aliases\n"));

	q_e->pol = *pol;

	q_e->start_idx = start_idx;
	q_e->max_size = size;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_q_enum_dom_aliases(const char *desc, SAMR_Q_ENUM_DOM_ALIASES * q_e,
				prs_struct *ps, int depth)
{
	if (q_e == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_q_enum_dom_aliases");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("pol", &q_e->pol, ps, depth))
		return False;

	if(!prs_uint32("start_idx", ps, depth, &q_e->start_idx))
		return False;
	if(!prs_uint32("max_size ", ps, depth, &q_e->max_size))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_R_ENUM_DOM_ALIASES structure.
********************************************************************/

void init_samr_r_enum_dom_aliases(SAMR_R_ENUM_DOM_ALIASES *r_u, uint32 next_idx, uint32 num_sam_entries)
{
	DEBUG(5, ("init_samr_r_enum_dom_aliases\n"));

	r_u->next_idx = next_idx;

	if (num_sam_entries != 0) {
		r_u->ptr_entries1 = 1;
		r_u->ptr_entries2 = 1;
		r_u->num_entries2 = num_sam_entries;
		r_u->num_entries3 = num_sam_entries;

		r_u->num_entries4 = num_sam_entries;
	} else {
		r_u->ptr_entries1 = 0;
		r_u->num_entries2 = num_sam_entries;
		r_u->ptr_entries2 = 1;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_r_enum_dom_aliases(const char *desc, SAMR_R_ENUM_DOM_ALIASES * r_u,
				prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_enum_dom_aliases");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("next_idx    ", ps, depth, &r_u->next_idx))
		return False;
	if(!prs_uint32("ptr_entries1", ps, depth, &r_u->ptr_entries1))
		return False;

	if (r_u->ptr_entries1 != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &r_u->num_entries2))
			return False;
		if(!prs_uint32("ptr_entries2", ps, depth, &r_u->ptr_entries2))
			return False;
		if(!prs_uint32("num_entries3", ps, depth, &r_u->num_entries3))
			return False;

		if (UNMARSHALLING(ps) && (r_u->num_entries2 > 0)) {
			r_u->sam = PRS_ALLOC_MEM(ps,SAM_ENTRY,r_u->num_entries2);
			r_u->uni_grp_name = PRS_ALLOC_MEM(ps,UNISTR2,r_u->num_entries2);
		}

		if (r_u->num_entries2 != 0 && 
		    (r_u->sam == NULL || r_u->uni_grp_name == NULL)) {
			DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_ALIASES\n"));
			r_u->num_entries4 = 0;
			r_u->status = NT_STATUS_MEMORY_NOT_ALLOCATED;
			return False;
		}

		for (i = 0; i < r_u->num_entries2; i++) {
			if(!sam_io_sam_entry("", &r_u->sam[i], ps, depth))
				return False;
		}

		for (i = 0; i < r_u->num_entries2; i++) {
			if(!smb_io_unistr2("", &r_u->uni_grp_name[i],
				       r_u->sam[i].hdr_name.buffer, ps,
				       depth))
				return False;
		}
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries4", ps, depth, &r_u->num_entries4))
		return False;
	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}
