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
inits a SAM_ENTRY structure.
********************************************************************/

void init_sam_entry(SAM_ENTRY *sam, UNISTR2 *uni2, uint32 rid)
{
	DEBUG(10, ("init_sam_entry: %d\n", rid));

	sam->rid = rid;
	init_uni_hdr(&sam->hdr_name, uni2);
}

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

/*******************************************************************
inits a SAMR_Q_LOOKUP_RIDS structure.
********************************************************************/

void init_samr_q_lookup_rids(TALLOC_CTX *ctx, SAMR_Q_LOOKUP_RIDS * q_u,
			     POLICY_HND *pol, uint32 flags,
			     uint32 num_rids, uint32 *rid)
{
	DEBUG(5, ("init_samr_q_lookup_rids\n"));

	q_u->pol = *pol;

	q_u->num_rids1 = num_rids;
	q_u->flags = flags;
	q_u->ptr = 0;
	q_u->num_rids2 = num_rids;
	if (num_rids) {
		q_u->rid = TALLOC_ZERO_ARRAY(ctx, uint32, num_rids );
	} else {
		q_u->rid = NULL;
	}
	if (q_u->rid == NULL) {
		q_u->num_rids1 = 0;
		q_u->num_rids2 = 0;
	} else {
		memcpy(q_u->rid, rid, num_rids * sizeof(q_u->rid[0]));
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_q_lookup_rids(const char *desc, SAMR_Q_LOOKUP_RIDS * q_u,
			   prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;

	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_q_lookup_rids");
	depth++;

	if (UNMARSHALLING(ps))
		ZERO_STRUCTP(q_u);

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("pol", &q_u->pol, ps, depth))
		return False;

	if(!prs_uint32("num_rids1", ps, depth, &q_u->num_rids1))
		return False;
	if(!prs_uint32("flags    ", ps, depth, &q_u->flags))
		return False;
	if(!prs_uint32("ptr      ", ps, depth, &q_u->ptr))
		return False;
	if(!prs_uint32("num_rids2", ps, depth, &q_u->num_rids2))
		return False;

	if (UNMARSHALLING(ps) && (q_u->num_rids2 != 0)) {
		q_u->rid = PRS_ALLOC_MEM(ps, uint32, q_u->num_rids2);
		if (q_u->rid == NULL)
			return False;
	}

	for (i = 0; i < q_u->num_rids2; i++) {
		slprintf(tmp, sizeof(tmp) - 1, "rid[%02d]  ", i);
		if(!prs_uint32(tmp, ps, depth, &q_u->rid[i]))
			return False;
	}

	return True;
}

/*******************************************************************
inits a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/

void init_samr_r_lookup_rids(SAMR_R_LOOKUP_RIDS * r_u,
			     uint32 num_names, UNIHDR * hdr_name,
			     UNISTR2 *uni_name, uint32 *type)
{
	DEBUG(5, ("init_samr_r_lookup_rids\n"));

	r_u->hdr_name = NULL;
	r_u->uni_name = NULL;
	r_u->type = NULL;

	if (num_names != 0) {
		r_u->num_names1 = num_names;
		r_u->ptr_names = 1;
		r_u->num_names2 = num_names;

		r_u->num_types1 = num_names;
		r_u->ptr_types = 1;
		r_u->num_types2 = num_names;

		r_u->hdr_name = hdr_name;
		r_u->uni_name = uni_name;
		r_u->type = type;
	} else {
		r_u->num_names1 = num_names;
		r_u->ptr_names = 0;
		r_u->num_names2 = num_names;

		r_u->num_types1 = num_names;
		r_u->ptr_types = 0;
		r_u->num_types2 = num_names;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_r_lookup_rids(const char *desc, SAMR_R_LOOKUP_RIDS * r_u,
			   prs_struct *ps, int depth)
{
	uint32 i;
	fstring tmp;
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_lookup_rids");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_names1", ps, depth, &r_u->num_names1))
		return False;
	if(!prs_uint32("ptr_names ", ps, depth, &r_u->ptr_names))
		return False;

	if (r_u->ptr_names != 0) {

		if(!prs_uint32("num_names2", ps, depth, &r_u->num_names2))
			return False;


		if (UNMARSHALLING(ps) && (r_u->num_names2 != 0)) {
			r_u->hdr_name = PRS_ALLOC_MEM(ps, UNIHDR, r_u->num_names2);
			if (r_u->hdr_name == NULL)
				return False;

			r_u->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, r_u->num_names2);
			if (r_u->uni_name == NULL)
				return False;
		}
		
		for (i = 0; i < r_u->num_names2; i++) {
			slprintf(tmp, sizeof(tmp) - 1, "hdr[%02d]  ", i);
			if(!smb_io_unihdr("", &r_u->hdr_name[i], ps, depth))
				return False;
		}
		for (i = 0; i < r_u->num_names2; i++) {
			slprintf(tmp, sizeof(tmp) - 1, "str[%02d]  ", i);
			if(!smb_io_unistr2("", &r_u->uni_name[i], r_u->hdr_name[i].buffer, ps, depth))
				return False;
		}

	}
	
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_types1", ps, depth, &r_u->num_types1))
		return False;
	if(!prs_uint32("ptr_types ", ps, depth, &r_u->ptr_types))
		return False;

	if (r_u->ptr_types != 0) {

		if(!prs_uint32("num_types2", ps, depth, &r_u->num_types2))
			return False;

		if (UNMARSHALLING(ps) && (r_u->num_types2 != 0)) {
			r_u->type = PRS_ALLOC_MEM(ps, uint32, r_u->num_types2);
			if (r_u->type == NULL)
				return False;
		}

		for (i = 0; i < r_u->num_types2; i++) {
			slprintf(tmp, sizeof(tmp) - 1, "type[%02d]  ", i);
			if(!prs_uint32(tmp, ps, depth, &r_u->type[i]))
				return False;
		}
	}

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
reads or writes a LOGON_HRS structure.
********************************************************************/

static bool sam_io_logon_hrs(const char *desc, LOGON_HRS * hrs,
			     prs_struct *ps, int depth)
{
	if (hrs == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_logon_hrs");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("maxlen", ps, depth, &hrs->max_len))
		return False;

	if(!prs_uint32("offset", ps, depth, &hrs->offset))
		return False;

	if(!prs_uint32("len  ", ps, depth, &hrs->len))
		return False;

	if (hrs->len > sizeof(hrs->hours)) {
		DEBUG(3, ("sam_io_logon_hrs: truncating length from %d\n", hrs->len));
		hrs->len = sizeof(hrs->hours);
	}

	if(!prs_uint8s(False, "hours", ps, depth, hrs->hours, hrs->len))
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USER_INFO_18 structure.
********************************************************************/

void init_sam_user_info18(SAM_USER_INFO_18 * usr,
			  const uint8 lm_pwd[16], const uint8 nt_pwd[16])
{
	DEBUG(5, ("init_sam_user_info18\n"));

	usr->lm_pwd_active =
		memcpy(usr->lm_pwd, lm_pwd, sizeof(usr->lm_pwd)) ? 1 : 0;
	usr->nt_pwd_active =
		memcpy(usr->nt_pwd, nt_pwd, sizeof(usr->nt_pwd)) ? 1 : 0;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info18(const char *desc, SAM_USER_INFO_18 * u,
			prs_struct *ps, int depth)
{
	if (u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_user_info18");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint8s(False, "lm_pwd", ps, depth, u->lm_pwd, sizeof(u->lm_pwd)))
		return False;
	if(!prs_uint8s(False, "nt_pwd", ps, depth, u->nt_pwd, sizeof(u->nt_pwd)))
		return False;

	if(!prs_uint8("lm_pwd_active", ps, depth, &u->lm_pwd_active))
		return False;
	if(!prs_uint8("nt_pwd_active", ps, depth, &u->nt_pwd_active))
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USER_INFO_7 structure.
********************************************************************/

void init_sam_user_info7(SAM_USER_INFO_7 * usr, const char *name)
{
	DEBUG(5, ("init_sam_user_info7\n"));

	init_unistr2(&usr->uni_name, name, UNI_FLAGS_NONE);	/* unicode string for name */
	init_uni_hdr(&usr->hdr_name, &usr->uni_name);		/* unicode header for name */

}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info7(const char *desc, SAM_USER_INFO_7 * usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_user_info7");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unihdr("unihdr", &usr->hdr_name, ps, depth))
		return False;

	if(!smb_io_unistr2("unistr2", &usr->uni_name, True, ps, depth))
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USER_INFO_9 structure.
********************************************************************/

void init_sam_user_info9(SAM_USER_INFO_9 * usr, uint32 rid_group)
{
	DEBUG(5, ("init_sam_user_info9\n"));

	usr->rid_group = rid_group;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info9(const char *desc, SAM_USER_INFO_9 * usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_user_info9");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("rid_group", ps, depth, &usr->rid_group))
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USER_INFO_16 structure.
********************************************************************/

void init_sam_user_info16(SAM_USER_INFO_16 * usr, uint32 acb_info)
{
	DEBUG(5, ("init_sam_user_info16\n"));

	usr->acb_info = acb_info;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info16(const char *desc, SAM_USER_INFO_16 * usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_user_info16");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("acb_info", ps, depth, &usr->acb_info))
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USER_INFO_17 structure.
********************************************************************/

void init_sam_user_info17(SAM_USER_INFO_17 * usr,
			  NTTIME * expiry,
			  char *mach_acct,
			  uint32 rid_user, uint32 rid_group, uint16 acct_ctrl)
{
	DEBUG(5, ("init_sam_user_info17\n"));

	memcpy(&usr->expiry, expiry, sizeof(usr->expiry));	/* expiry time or something? */
	ZERO_STRUCT(usr->padding_1);	/* 0 - padding 24 bytes */

	usr->padding_2 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_1 = 1;		/* pointer */
	ZERO_STRUCT(usr->padding_3);	/* 0 - padding 32 bytes */
	usr->padding_4 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_2 = 1;		/* pointer */
	usr->padding_5 = 0;	/* 0 - padding 4 bytes */

	usr->ptr_3 = 1;		/* pointer */
	ZERO_STRUCT(usr->padding_6);	/* 0 - padding 32 bytes */

	usr->rid_user = rid_user;
	usr->rid_group = rid_group;

	usr->acct_ctrl = acct_ctrl;
	usr->unknown_3 = 0x0000;

	usr->unknown_4 = 0x003f;	/* 0x003f      - 16 bit unknown */
	usr->unknown_5 = 0x003c;	/* 0x003c      - 16 bit unknown */

	ZERO_STRUCT(usr->padding_7);	/* 0 - padding 16 bytes */
	usr->padding_8 = 0;	/* 0 - padding 4 bytes */

	init_unistr2(&usr->uni_mach_acct, mach_acct, UNI_FLAGS_NONE);	/* unicode string for machine account */
	init_uni_hdr(&usr->hdr_mach_acct, &usr->uni_mach_acct);	/* unicode header for machine account */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info17(const char *desc, SAM_USER_INFO_17 * usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_unknown_17");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint8s(False, "padding_0", ps, depth, usr->padding_0, sizeof(usr->padding_0)))
		return False;

	if(!smb_io_time("time", &usr->expiry, ps, depth))
		return False;

	if(!prs_uint8s(False, "padding_1", ps, depth, usr->padding_1, sizeof(usr->padding_1)))
		return False;

	if(!smb_io_unihdr("unihdr", &usr->hdr_mach_acct, ps, depth))
		return False;

	if(!prs_uint32("padding_2", ps, depth, &usr->padding_2))
		return False;

	if(!prs_uint32("ptr_1    ", ps, depth, &usr->ptr_1))
		return False;
	if(!prs_uint8s(False, "padding_3", ps, depth, usr->padding_3, sizeof(usr->padding_3)))
		return False;

	if(!prs_uint32("padding_4", ps, depth, &usr->padding_4))
		return False;

	if(!prs_uint32("ptr_2    ", ps, depth, &usr->ptr_2))
		return False;
	if(!prs_uint32("padding_5", ps, depth, &usr->padding_5))
		return False;

	if(!prs_uint32("ptr_3    ", ps, depth, &usr->ptr_3))
		return False;
	if(!prs_uint8s(False, "padding_6", ps, depth, usr->padding_6,sizeof(usr->padding_6)))
		return False;

	if(!prs_uint32("rid_user ", ps, depth, &usr->rid_user))
		return False;
	if(!prs_uint32("rid_group", ps, depth, &usr->rid_group))
		return False;
	if(!prs_uint16("acct_ctrl", ps, depth, &usr->acct_ctrl))
		return False;
	if(!prs_uint16("unknown_3", ps, depth, &usr->unknown_3))
		return False;
	if(!prs_uint16("unknown_4", ps, depth, &usr->unknown_4))
		return False;
	if(!prs_uint16("unknown_5", ps, depth, &usr->unknown_5))
		return False;

	if(!prs_uint8s(False, "padding_7", ps, depth, usr->padding_7, sizeof(usr->padding_7)))
		return False;

	if(!prs_uint32("padding_8", ps, depth, &(usr->padding_8)))
		return False;

	if(!smb_io_unistr2("unistr2", &usr->uni_mach_acct, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint8s(False, "padding_9", ps, depth, usr->padding_9, sizeof(usr->padding_9)))
		return False;

	return True;
}

/*************************************************************************
 init_sam_user_infoa
 *************************************************************************/

void init_sam_user_info24(SAM_USER_INFO_24 * usr, char newpass[516],
			  uint8 pw_len)
{
	DEBUG(10, ("init_sam_user_info24:\n"));
	memcpy(usr->pass, newpass, sizeof(usr->pass));
	usr->pw_len = pw_len;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info24(const char *desc, SAM_USER_INFO_24 * usr,
			       prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info24");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint8s(False, "password", ps, depth, usr->pass, 
		       sizeof(usr->pass)))
		return False;
	
	if (MARSHALLING(ps) && (usr->pw_len != 0)) {
		if (!prs_uint8("pw_len", ps, depth, &usr->pw_len))
			return False;
	} else if (UNMARSHALLING(ps)) {
		if (!prs_uint8("pw_len", ps, depth, &usr->pw_len))
			return False;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info26(const char *desc, SAM_USER_INFO_26 * usr,
			       prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info26");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint8s(False, "password", ps, depth, usr->pass, 
		       sizeof(usr->pass)))
		return False;
	
	if (!prs_uint8("pw_len", ps, depth, &usr->pw_len))
		return False;

	return True;
}


/*************************************************************************
 init_sam_user_info23

 unknown_6 = 0x0000 04ec 

 *************************************************************************/

void init_sam_user_info23W(SAM_USER_INFO_23 * usr, NTTIME * logon_time,	/* all zeros */
			NTTIME * logoff_time,	/* all zeros */
			NTTIME * kickoff_time,	/* all zeros */
			NTTIME * pass_last_set_time,	/* all zeros */
			NTTIME * pass_can_change_time,	/* all zeros */
			NTTIME * pass_must_change_time,	/* all zeros */
			UNISTR2 *user_name,
			UNISTR2 *full_name,
			UNISTR2 *home_dir,
			UNISTR2 *dir_drive,
			UNISTR2 *log_scr,
			UNISTR2 *prof_path,
			UNISTR2 *desc,
			UNISTR2 *wkstas,
			UNISTR2 *unk_str,
			UNISTR2 *mung_dial,
			uint32 user_rid,	/* 0x0000 0000 */
			uint32 group_rid,
			uint32 acb_info,
			uint32 fields_present,
			uint16 logon_divs,
			LOGON_HRS * hrs,
			uint16 bad_password_count,
			uint16 logon_count,
			char newpass[516])
{
	usr->logon_time = *logon_time;	/* all zeros */
	usr->logoff_time = *logoff_time;	/* all zeros */
	usr->kickoff_time = *kickoff_time;	/* all zeros */
	usr->pass_last_set_time = *pass_last_set_time;	/* all zeros */
	usr->pass_can_change_time = *pass_can_change_time;	/* all zeros */
	usr->pass_must_change_time = *pass_must_change_time;	/* all zeros */

	ZERO_STRUCT(usr->nt_pwd);
	ZERO_STRUCT(usr->lm_pwd);

	usr->user_rid = user_rid;	/* 0x0000 0000 */
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->fields_present = fields_present;	/* 09f8 27fa */

	usr->logon_divs = logon_divs;	/* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;

	if (nt_time_is_zero(pass_must_change_time)) {
		usr->passmustchange=PASS_MUST_CHANGE_AT_NEXT_LOGON;
	} else {
		usr->passmustchange=0;
	}

	ZERO_STRUCT(usr->padding1);
	ZERO_STRUCT(usr->padding2);

	usr->bad_password_count = bad_password_count;
	usr->logon_count = logon_count;

	memcpy(usr->pass, newpass, sizeof(usr->pass));

	copy_unistr2(&usr->uni_user_name, user_name);
	init_uni_hdr(&usr->hdr_user_name, &usr->uni_user_name);

	copy_unistr2(&usr->uni_full_name, full_name);
	init_uni_hdr(&usr->hdr_full_name, &usr->uni_full_name);

	copy_unistr2(&usr->uni_home_dir, home_dir);
	init_uni_hdr(&usr->hdr_home_dir, &usr->uni_home_dir);

	copy_unistr2(&usr->uni_dir_drive, dir_drive);
	init_uni_hdr(&usr->hdr_dir_drive, &usr->uni_dir_drive);

	copy_unistr2(&usr->uni_logon_script, log_scr);
	init_uni_hdr(&usr->hdr_logon_script, &usr->uni_logon_script);

	copy_unistr2(&usr->uni_profile_path, prof_path);
	init_uni_hdr(&usr->hdr_profile_path, &usr->uni_profile_path);

	copy_unistr2(&usr->uni_acct_desc, desc);
	init_uni_hdr(&usr->hdr_acct_desc, &usr->uni_acct_desc);

	copy_unistr2(&usr->uni_workstations, wkstas);
	init_uni_hdr(&usr->hdr_workstations, &usr->uni_workstations);

	copy_unistr2(&usr->uni_comment, unk_str);
	init_uni_hdr(&usr->hdr_comment, &usr->uni_comment);

	copy_unistr2(&usr->uni_munged_dial, mung_dial);
	init_uni_hdr(&usr->hdr_munged_dial, &usr->uni_munged_dial);

	if (hrs) {
		memcpy(&usr->logon_hrs, hrs, sizeof(usr->logon_hrs));
	} else {
		ZERO_STRUCT(usr->logon_hrs);
	}
}

/*************************************************************************
 init_sam_user_info23

 unknown_6 = 0x0000 04ec 

 *************************************************************************/

void init_sam_user_info23A(SAM_USER_INFO_23 * usr, NTTIME * logon_time,	/* all zeros */
			   NTTIME * logoff_time,	/* all zeros */
			   NTTIME * kickoff_time,	/* all zeros */
			   NTTIME * pass_last_set_time,	/* all zeros */
			   NTTIME * pass_can_change_time,	/* all zeros */
			   NTTIME * pass_must_change_time,	/* all zeros */
			   char *user_name,	/* NULL */
			   char *full_name,
			   char *home_dir, char *dir_drive, char *log_scr,
			   char *prof_path, const char *desc, char *wkstas,
			   char *unk_str, char *mung_dial, uint32 user_rid,	/* 0x0000 0000 */
			   uint32 group_rid, uint32 acb_info,
			   uint32 fields_present, uint16 logon_divs,
			   LOGON_HRS * hrs, uint16 bad_password_count, uint16 logon_count,
			   char newpass[516])
{
	DATA_BLOB blob = base64_decode_data_blob(mung_dial);
	
	usr->logon_time = *logon_time;	/* all zeros */
	usr->logoff_time = *logoff_time;	/* all zeros */
	usr->kickoff_time = *kickoff_time;	/* all zeros */
	usr->pass_last_set_time = *pass_last_set_time;	/* all zeros */
	usr->pass_can_change_time = *pass_can_change_time;	/* all zeros */
	usr->pass_must_change_time = *pass_must_change_time;	/* all zeros */

	ZERO_STRUCT(usr->nt_pwd);
	ZERO_STRUCT(usr->lm_pwd);

	usr->user_rid = user_rid;	/* 0x0000 0000 */
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->fields_present = fields_present;	/* 09f8 27fa */

	usr->logon_divs = logon_divs;	/* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;

	if (nt_time_is_zero(pass_must_change_time)) {
		usr->passmustchange=PASS_MUST_CHANGE_AT_NEXT_LOGON;
	} else {
		usr->passmustchange=0;
	}

	ZERO_STRUCT(usr->padding1);
	ZERO_STRUCT(usr->padding2);

	usr->bad_password_count = bad_password_count;
	usr->logon_count = logon_count;

	memcpy(usr->pass, newpass, sizeof(usr->pass));

	init_unistr2(&usr->uni_user_name, user_name, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_user_name, &usr->uni_user_name);

	init_unistr2(&usr->uni_full_name, full_name, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_full_name, &usr->uni_full_name);

	init_unistr2(&usr->uni_home_dir, home_dir, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_home_dir, &usr->uni_home_dir);

	init_unistr2(&usr->uni_dir_drive, dir_drive, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_dir_drive, &usr->uni_dir_drive);

	init_unistr2(&usr->uni_logon_script, log_scr, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_logon_script, &usr->uni_logon_script);

	init_unistr2(&usr->uni_profile_path, prof_path, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_profile_path, &usr->uni_profile_path);

	init_unistr2(&usr->uni_acct_desc, desc, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_acct_desc, &usr->uni_acct_desc);

	init_unistr2(&usr->uni_workstations, wkstas, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_workstations, &usr->uni_workstations);

	init_unistr2(&usr->uni_comment, unk_str, UNI_FLAGS_NONE);
	init_uni_hdr(&usr->hdr_comment, &usr->uni_comment);

	init_unistr2_from_datablob(&usr->uni_munged_dial, &blob);
	init_uni_hdr(&usr->hdr_munged_dial, &usr->uni_munged_dial);

	data_blob_free(&blob);
	
	if (hrs) {
		memcpy(&usr->logon_hrs, hrs, sizeof(usr->logon_hrs));
	} else {
		ZERO_STRUCT(usr->logon_hrs);
	}
}


/*************************************************************************
 init_samr_user_info25P
 fields_present = ACCT_NT_PWD_SET | ACCT_LM_PWD_SET | SAMR_FIELD_ACCT_FLAGS
*************************************************************************/

void init_sam_user_info25P(SAM_USER_INFO_25 * usr,
			   uint32 fields_present, uint32 acb_info,
			   char newpass[532])
{
	usr->fields_present = fields_present;
	ZERO_STRUCT(usr->padding1);
	ZERO_STRUCT(usr->padding2);

	usr->acb_info = acb_info;
	memcpy(usr->pass, newpass, sizeof(usr->pass));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info23(const char *desc, SAM_USER_INFO_23 * usr,
			       prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info23");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_time("logon_time           ", &usr->logon_time, ps, depth))
		return False;
	if(!smb_io_time("logoff_time          ", &usr->logoff_time, ps, depth))
		return False;
	if(!smb_io_time("kickoff_time         ", &usr->kickoff_time, ps, depth))
		return False;
	if(!smb_io_time("pass_last_set_time   ", &usr->pass_last_set_time, ps, depth))
		return False;
	if(!smb_io_time("pass_can_change_time ", &usr->pass_can_change_time, ps, depth))
		return False;
	if(!smb_io_time("pass_must_change_time", &usr->pass_must_change_time, ps, depth))
		return False;

	if(!smb_io_unihdr("hdr_user_name   ", &usr->hdr_user_name, ps, depth))	/* username unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_full_name   ", &usr->hdr_full_name, ps, depth))	/* user's full name unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_home_dir    ", &usr->hdr_home_dir, ps, depth))	/* home directory unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_dir_drive   ", &usr->hdr_dir_drive, ps, depth))	/* home directory drive */
		return False;
	if(!smb_io_unihdr("hdr_logon_script", &usr->hdr_logon_script, ps, depth))	/* logon script unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_profile_path", &usr->hdr_profile_path, ps, depth))	/* profile path unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_acct_desc   ", &usr->hdr_acct_desc, ps, depth))	/* account desc */
		return False;
	if(!smb_io_unihdr("hdr_workstations", &usr->hdr_workstations, ps, depth))	/* wkstas user can log on from */
		return False;
	if(!smb_io_unihdr("hdr_comment ", &usr->hdr_comment, ps, depth))	/* unknown string */
		return False;
	if(!smb_io_unihdr("hdr_munged_dial ", &usr->hdr_munged_dial, ps, depth))	/* wkstas user can log on from */
		return False;

	if(!prs_uint8s(False, "lm_pwd        ", ps, depth, usr->lm_pwd, sizeof(usr->lm_pwd)))
		return False;
	if(!prs_uint8s(False, "nt_pwd        ", ps, depth, usr->nt_pwd, sizeof(usr->nt_pwd)))
		return False;

	if(!prs_uint32("user_rid      ", ps, depth, &usr->user_rid))	/* User ID */
		return False;
	if(!prs_uint32("group_rid     ", ps, depth, &usr->group_rid))	/* Group ID */
		return False;
	if(!prs_uint32("acb_info      ", ps, depth, &usr->acb_info))
		return False;

	if(!prs_uint32("fields_present ", ps, depth, &usr->fields_present))
		return False;
	if(!prs_uint16("logon_divs    ", ps, depth, &usr->logon_divs))	/* logon divisions per week */
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("ptr_logon_hrs ", ps, depth, &usr->ptr_logon_hrs))
		return False;

	if(!prs_uint16("bad_password_count     ", ps, depth, &usr->bad_password_count))
		return False;
	if(!prs_uint16("logon_count     ", ps, depth, &usr->logon_count))
		return False;

	if(!prs_uint8s(False, "padding1      ", ps, depth, usr->padding1, sizeof(usr->padding1)))
		return False;
	if(!prs_uint8("passmustchange ", ps, depth, &usr->passmustchange))
		return False;
	if(!prs_uint8("padding2       ", ps, depth, &usr->padding2))
		return False;


	if(!prs_uint8s(False, "password      ", ps, depth, usr->pass, sizeof(usr->pass)))
		return False;

	/* here begins pointed-to data */

	if(!smb_io_unistr2("uni_user_name   ", &usr->uni_user_name, usr->hdr_user_name.buffer, ps, depth))	/* username unicode string */
		return False;

	if(!smb_io_unistr2("uni_full_name   ", &usr->uni_full_name, usr->hdr_full_name.buffer, ps, depth))	/* user's full name unicode string */
		return False;

	if(!smb_io_unistr2("uni_home_dir    ", &usr->uni_home_dir, usr->hdr_home_dir.buffer, ps, depth))	/* home directory unicode string */
		return False;

	if(!smb_io_unistr2("uni_dir_drive   ", &usr->uni_dir_drive, usr->hdr_dir_drive.buffer, ps, depth))	/* home directory drive unicode string */
		return False;

	if(!smb_io_unistr2("uni_logon_script", &usr->uni_logon_script, usr->hdr_logon_script.buffer, ps, depth))	/* logon script unicode string */
		return False;

	if(!smb_io_unistr2("uni_profile_path", &usr->uni_profile_path, usr->hdr_profile_path.buffer, ps, depth))	/* profile path unicode string */
		return False;

	if(!smb_io_unistr2("uni_acct_desc   ", &usr->uni_acct_desc, usr->hdr_acct_desc.buffer, ps, depth))	/* user desc unicode string */
		return False;

	if(!smb_io_unistr2("uni_workstations", &usr->uni_workstations, usr->hdr_workstations.buffer, ps, depth))	/* worksations user can log on from */
		return False;

	if(!smb_io_unistr2("uni_comment ", &usr->uni_comment, usr->hdr_comment.buffer, ps, depth))	/* unknown string */
		return False;

	if(!smb_io_unistr2("uni_munged_dial ", &usr->uni_munged_dial, usr->hdr_munged_dial.buffer, ps, depth))
		return False;

	/* ok, this is only guess-work (as usual) */
	if (usr->ptr_logon_hrs) {
		if(!sam_io_logon_hrs("logon_hrs", &usr->logon_hrs, ps, depth))
			return False;
	} 

	return True;
}

/*******************************************************************
 reads or writes a structure.
 NB. This structure is *definately* incorrect. It's my best guess
 currently for W2K SP2. The password field is encrypted in a different
 way than normal... And there are definately other problems. JRA.
********************************************************************/

static bool sam_io_user_info25(const char *desc, SAM_USER_INFO_25 * usr, prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info25");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_time("logon_time           ", &usr->logon_time, ps, depth))
		return False;
	if(!smb_io_time("logoff_time          ", &usr->logoff_time, ps, depth))
		return False;
	if(!smb_io_time("kickoff_time         ", &usr->kickoff_time, ps, depth))
		return False;
	if(!smb_io_time("pass_last_set_time   ", &usr->pass_last_set_time, ps, depth))
		return False;
	if(!smb_io_time("pass_can_change_time ", &usr->pass_can_change_time, ps, depth))
		return False;
	if(!smb_io_time("pass_must_change_time", &usr->pass_must_change_time, ps, depth))
		return False;

	if(!smb_io_unihdr("hdr_user_name   ", &usr->hdr_user_name, ps, depth))	/* username unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_full_name   ", &usr->hdr_full_name, ps, depth))	/* user's full name unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_home_dir    ", &usr->hdr_home_dir, ps, depth))	/* home directory unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_dir_drive   ", &usr->hdr_dir_drive, ps, depth))	/* home directory drive */
		return False;
	if(!smb_io_unihdr("hdr_logon_script", &usr->hdr_logon_script, ps, depth))	/* logon script unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_profile_path", &usr->hdr_profile_path, ps, depth))	/* profile path unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_acct_desc   ", &usr->hdr_acct_desc, ps, depth))	/* account desc */
		return False;
	if(!smb_io_unihdr("hdr_workstations", &usr->hdr_workstations, ps, depth))	/* wkstas user can log on from */
		return False;
	if(!smb_io_unihdr("hdr_comment ", &usr->hdr_comment, ps, depth))	/* unknown string */
		return False;
	if(!smb_io_unihdr("hdr_munged_dial ", &usr->hdr_munged_dial, ps, depth))	/* wkstas user can log on from */
		return False;

	if(!prs_uint8s(False, "lm_pwd        ", ps, depth, usr->lm_pwd, sizeof(usr->lm_pwd)))
		return False;
	if(!prs_uint8s(False, "nt_pwd        ", ps, depth, usr->nt_pwd, sizeof(usr->nt_pwd)))
		return False;

	if(!prs_uint32("user_rid      ", ps, depth, &usr->user_rid))	/* User ID */
		return False;
	if(!prs_uint32("group_rid     ", ps, depth, &usr->group_rid))	/* Group ID */
		return False;
	if(!prs_uint32("acb_info      ", ps, depth, &usr->acb_info))
		return False;
	if(!prs_uint32("fields_present ", ps, depth, &usr->fields_present))
		return False;

	if(!prs_uint16("logon_divs    ", ps, depth, &usr->logon_divs))	/* logon divisions per week */
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("ptr_logon_hrs ", ps, depth, &usr->ptr_logon_hrs))
		return False;

	if(!prs_uint16("bad_password_count     ", ps, depth, &usr->bad_password_count))
		return False;
	if(!prs_uint16("logon_count     ", ps, depth, &usr->logon_count))
		return False;

	if(!prs_uint8s(False, "padding1      ", ps, depth, usr->padding1, sizeof(usr->padding1)))
		return False;
	if(!prs_uint8("passmustchange ", ps, depth, &usr->passmustchange))
		return False;
	if(!prs_uint8("padding2       ", ps, depth, &usr->padding2))
		return False;


	if(!prs_uint8s(False, "password      ", ps, depth, usr->pass, sizeof(usr->pass)))
		return False;

	/* here begins pointed-to data */

	if(!smb_io_unistr2("uni_user_name   ", &usr->uni_user_name, usr->hdr_user_name.buffer, ps, depth))	/* username unicode string */
		return False;

	if(!smb_io_unistr2("uni_full_name   ", &usr->uni_full_name, usr->hdr_full_name.buffer, ps, depth))	/* user's full name unicode string */
		return False;

	if(!smb_io_unistr2("uni_home_dir    ", &usr->uni_home_dir, usr->hdr_home_dir.buffer, ps, depth))	/* home directory unicode string */
		return False;

	if(!smb_io_unistr2("uni_dir_drive   ", &usr->uni_dir_drive, usr->hdr_dir_drive.buffer, ps, depth))	/* home directory drive unicode string */
		return False;

	if(!smb_io_unistr2("uni_logon_script", &usr->uni_logon_script, usr->hdr_logon_script.buffer, ps, depth))	/* logon script unicode string */
		return False;

	if(!smb_io_unistr2("uni_profile_path", &usr->uni_profile_path, usr->hdr_profile_path.buffer, ps, depth))	/* profile path unicode string */
		return False;

	if(!smb_io_unistr2("uni_acct_desc   ", &usr->uni_acct_desc, usr->hdr_acct_desc.buffer, ps, depth))	/* user desc unicode string */
		return False;

	if(!smb_io_unistr2("uni_workstations", &usr->uni_workstations, usr->hdr_workstations.buffer, ps, depth))	/* worksations user can log on from */
		return False;

	if(!smb_io_unistr2("uni_comment ", &usr->uni_comment, usr->hdr_comment.buffer, ps, depth))	/* unknown string */
		return False;

	if(!smb_io_unistr2("uni_munged_dial ", &usr->uni_munged_dial, usr->hdr_munged_dial.buffer, ps, depth))
		return False;

	/* ok, this is only guess-work (as usual) */
	if (usr->ptr_logon_hrs) {
		if(!sam_io_logon_hrs("logon_hrs", &usr->logon_hrs, ps, depth))
			return False;
	} 

	return True;
}


/*************************************************************************
 init_sam_user_info21W

 unknown_6 = 0x0000 04ec 

 *************************************************************************/

void init_sam_user_info21W(SAM_USER_INFO_21 * usr,
			   NTTIME * logon_time,
			   NTTIME * logoff_time,
			   NTTIME * kickoff_time,
			   NTTIME * pass_last_set_time,
			   NTTIME * pass_can_change_time,
			   NTTIME * pass_must_change_time,
			   UNISTR2 *user_name,
			   UNISTR2 *full_name,
			   UNISTR2 *home_dir,
			   UNISTR2 *dir_drive,
			   UNISTR2 *log_scr,
			   UNISTR2 *prof_path,
			   UNISTR2 *desc,
			   UNISTR2 *wkstas,
			   UNISTR2 *unk_str,
			   UNISTR2 *mung_dial,
			   uchar lm_pwd[16],
			   uchar nt_pwd[16],
			   uint32 user_rid,
			   uint32 group_rid,
			   uint32 acb_info,
			   uint32 fields_present,
			   uint16 logon_divs,
			   LOGON_HRS * hrs,
			   uint16 bad_password_count,
			   uint16 logon_count)
{
	usr->logon_time = *logon_time;
	usr->logoff_time = *logoff_time;
	usr->kickoff_time = *kickoff_time;
	usr->pass_last_set_time = *pass_last_set_time;
	usr->pass_can_change_time = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	memcpy(usr->lm_pwd, lm_pwd, sizeof(usr->lm_pwd));
	memcpy(usr->nt_pwd, nt_pwd, sizeof(usr->nt_pwd));

	usr->user_rid = user_rid;
	usr->group_rid = group_rid;
	usr->acb_info = acb_info;
	usr->fields_present = fields_present;	/* 0x00ff ffff */

	usr->logon_divs = logon_divs;	/* should be 168 (hours/week) */
	usr->ptr_logon_hrs = hrs ? 1 : 0;
	usr->bad_password_count = bad_password_count;
	usr->logon_count = logon_count;

	if (nt_time_is_zero(pass_must_change_time)) {
		usr->passmustchange=PASS_MUST_CHANGE_AT_NEXT_LOGON;
	} else {
		usr->passmustchange=0;
	}

	ZERO_STRUCT(usr->padding1);
	ZERO_STRUCT(usr->padding2);

	copy_unistr2(&usr->uni_user_name, user_name);
	init_uni_hdr(&usr->hdr_user_name, &usr->uni_user_name);

	copy_unistr2(&usr->uni_full_name, full_name);
	init_uni_hdr(&usr->hdr_full_name, &usr->uni_full_name);

	copy_unistr2(&usr->uni_home_dir, home_dir);
	init_uni_hdr(&usr->hdr_home_dir, &usr->uni_home_dir);

	copy_unistr2(&usr->uni_dir_drive, dir_drive);
	init_uni_hdr(&usr->hdr_dir_drive, &usr->uni_dir_drive);

	copy_unistr2(&usr->uni_logon_script, log_scr);
	init_uni_hdr(&usr->hdr_logon_script, &usr->uni_logon_script);

	copy_unistr2(&usr->uni_profile_path, prof_path);
	init_uni_hdr(&usr->hdr_profile_path, &usr->uni_profile_path);

	copy_unistr2(&usr->uni_acct_desc, desc);
	init_uni_hdr(&usr->hdr_acct_desc, &usr->uni_acct_desc);

	copy_unistr2(&usr->uni_workstations, wkstas);
	init_uni_hdr(&usr->hdr_workstations, &usr->uni_workstations);

	copy_unistr2(&usr->uni_comment, unk_str);
	init_uni_hdr(&usr->hdr_comment, &usr->uni_comment);

	copy_unistr2(&usr->uni_munged_dial, mung_dial);
	init_uni_hdr(&usr->hdr_munged_dial, &usr->uni_munged_dial);

	if (hrs) {
		memcpy(&usr->logon_hrs, hrs, sizeof(usr->logon_hrs));
	} else {
		ZERO_STRUCT(usr->logon_hrs);
	}
}

/*************************************************************************
 init_sam_user_info21

 unknown_6 = 0x0000 04ec 

 *************************************************************************/

NTSTATUS init_sam_user_info21A(SAM_USER_INFO_21 *usr, struct samu *pw, DOM_SID *domain_sid)
{
	NTTIME 		logon_time, logoff_time, kickoff_time,
			pass_last_set_time, pass_can_change_time,
			pass_must_change_time;
			
	time_t must_change_time;
	const char*		user_name = pdb_get_username(pw);
	const char*		full_name = pdb_get_fullname(pw);
	const char*		home_dir  = pdb_get_homedir(pw);
	const char*		dir_drive = pdb_get_dir_drive(pw);
	const char*		logon_script = pdb_get_logon_script(pw);
	const char*		profile_path = pdb_get_profile_path(pw);
	const char*		description = pdb_get_acct_desc(pw);
	const char*		workstations = pdb_get_workstations(pw);
	const char*		munged_dial = pdb_get_munged_dial(pw);
	DATA_BLOB 		munged_dial_blob;

	uint32 user_rid;
	const DOM_SID *user_sid;

	uint32 group_rid;
	const DOM_SID *group_sid;

	if (munged_dial) {
		munged_dial_blob = base64_decode_data_blob(munged_dial);
	} else {
		munged_dial_blob = data_blob_null;
	}

	/* Create NTTIME structs */
	unix_to_nt_time (&logon_time,	        pdb_get_logon_time(pw));
	unix_to_nt_time (&logoff_time,	pdb_get_logoff_time(pw));
	unix_to_nt_time (&kickoff_time, 	pdb_get_kickoff_time(pw));
	unix_to_nt_time (&pass_last_set_time, pdb_get_pass_last_set_time(pw));
	unix_to_nt_time (&pass_can_change_time,pdb_get_pass_can_change_time(pw));
	must_change_time = pdb_get_pass_must_change_time(pw);
	if (must_change_time == get_time_t_max())
		unix_to_nt_time_abs(&pass_must_change_time, must_change_time);
	else
		unix_to_nt_time(&pass_must_change_time, must_change_time);
	
	/* structure assignment */
	usr->logon_time            = logon_time;
	usr->logoff_time           = logoff_time;
	usr->kickoff_time          = kickoff_time;
	usr->pass_last_set_time    = pass_last_set_time;
	usr->pass_can_change_time  = pass_can_change_time;
	usr->pass_must_change_time = pass_must_change_time;

	ZERO_STRUCT(usr->nt_pwd);
	ZERO_STRUCT(usr->lm_pwd);

	user_sid = pdb_get_user_sid(pw);
	
	if (!sid_peek_check_rid(domain_sid, user_sid, &user_rid)) {
		DEBUG(0, ("init_sam_user_info_21A: User %s has SID %s, \nwhich conflicts with "
			  "the domain sid %s.  Failing operation.\n", 
			  user_name, sid_string_dbg(user_sid),
			  sid_string_dbg(domain_sid)));
		data_blob_free(&munged_dial_blob);
		return NT_STATUS_UNSUCCESSFUL;
	}

	become_root();	
	group_sid = pdb_get_group_sid(pw);
	unbecome_root();

	if (!sid_peek_check_rid(domain_sid, group_sid, &group_rid)) {
		DEBUG(0, ("init_sam_user_info_21A: User %s has Primary Group SID %s, \n"
			  "which conflicts with the domain sid %s.  Failing operation.\n", 
			  user_name, sid_string_dbg(group_sid),
			  sid_string_dbg(domain_sid)));
		data_blob_free(&munged_dial_blob);
		return NT_STATUS_UNSUCCESSFUL;
	}

	usr->user_rid  = user_rid;
	usr->group_rid = group_rid;
	usr->acb_info  = pdb_get_acct_ctrl(pw);

	/*
	  Look at a user on a real NT4 PDC with usrmgr, press
	  'ok'. Then you will see that fields_present is set to
	  0x08f827fa. Look at the user immediately after that again,
	  and you will see that 0x00fffff is returned. This solves
	  the problem that you get access denied after having looked
	  at the user.
	  -- Volker
	*/
	usr->fields_present = pdb_build_fields_present(pw);

	usr->logon_divs = pdb_get_logon_divs(pw); 
	usr->ptr_logon_hrs = pdb_get_hours(pw) ? 1 : 0;
	usr->bad_password_count = pdb_get_bad_password_count(pw);
	usr->logon_count = pdb_get_logon_count(pw);

	if (pdb_get_pass_must_change_time(pw) == 0) {
		usr->passmustchange=PASS_MUST_CHANGE_AT_NEXT_LOGON;
	} else {
		usr->passmustchange=0;
	}

	ZERO_STRUCT(usr->padding1);
	ZERO_STRUCT(usr->padding2);

	init_unistr2(&usr->uni_user_name, user_name, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_user_name, &usr->uni_user_name);

	init_unistr2(&usr->uni_full_name, full_name, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_full_name, &usr->uni_full_name);

	init_unistr2(&usr->uni_home_dir, home_dir, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_home_dir, &usr->uni_home_dir);

	init_unistr2(&usr->uni_dir_drive, dir_drive, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_dir_drive, &usr->uni_dir_drive);

	init_unistr2(&usr->uni_logon_script, logon_script, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_logon_script, &usr->uni_logon_script);

	init_unistr2(&usr->uni_profile_path, profile_path, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_profile_path, &usr->uni_profile_path);

	init_unistr2(&usr->uni_acct_desc, description, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_acct_desc, &usr->uni_acct_desc);

	init_unistr2(&usr->uni_workstations, workstations, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_workstations, &usr->uni_workstations);

	init_unistr2(&usr->uni_comment, NULL, UNI_STR_TERMINATE);
	init_uni_hdr(&usr->hdr_comment, &usr->uni_comment);

	init_unistr2_from_datablob(&usr->uni_munged_dial, &munged_dial_blob);
	init_uni_hdr(&usr->hdr_munged_dial, &usr->uni_munged_dial);
	data_blob_free(&munged_dial_blob);

	if (pdb_get_hours(pw)) {
		usr->logon_hrs.max_len = 1260;
		usr->logon_hrs.offset = 0;
		usr->logon_hrs.len = pdb_get_hours_len(pw);
		memcpy(&usr->logon_hrs.hours, pdb_get_hours(pw), MAX_HOURS_LEN);
	} else {
		usr->logon_hrs.max_len = 1260;
		usr->logon_hrs.offset = 0;
		usr->logon_hrs.len = 0;
		memset(&usr->logon_hrs, 0xff, sizeof(usr->logon_hrs));
	}

	return NT_STATUS_OK;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info21(const char *desc, SAM_USER_INFO_21 * usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info21");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_time("logon_time           ", &usr->logon_time, ps, depth))
		return False;
	if(!smb_io_time("logoff_time          ", &usr->logoff_time, ps, depth))
		return False;
	if(!smb_io_time("pass_last_set_time   ", &usr->pass_last_set_time, ps,depth))
		return False;
	if(!smb_io_time("kickoff_time         ", &usr->kickoff_time, ps, depth))
		return False;
	if(!smb_io_time("pass_can_change_time ", &usr->pass_can_change_time, ps,depth))
		return False;
	if(!smb_io_time("pass_must_change_time", &usr->pass_must_change_time,  ps, depth))
		return False;

	if(!smb_io_unihdr("hdr_user_name   ", &usr->hdr_user_name, ps, depth))	/* username unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_full_name   ", &usr->hdr_full_name, ps, depth))	/* user's full name unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_home_dir    ", &usr->hdr_home_dir, ps, depth))	/* home directory unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_dir_drive   ", &usr->hdr_dir_drive, ps, depth))	/* home directory drive */
		return False;
	if(!smb_io_unihdr("hdr_logon_script", &usr->hdr_logon_script, ps, depth))	/* logon script unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_profile_path", &usr->hdr_profile_path, ps, depth))	/* profile path unicode string header */
		return False;
	if(!smb_io_unihdr("hdr_acct_desc   ", &usr->hdr_acct_desc, ps, depth))	/* account desc */
		return False;
	if(!smb_io_unihdr("hdr_workstations", &usr->hdr_workstations, ps, depth))	/* wkstas user can log on from */
		return False;
	if(!smb_io_unihdr("hdr_comment ", &usr->hdr_comment, ps, depth))	/* unknown string */
		return False;
	if(!smb_io_unihdr("hdr_munged_dial ", &usr->hdr_munged_dial, ps, depth))	/* wkstas user can log on from */
		return False;

	if(!prs_uint8s(False, "lm_pwd        ", ps, depth, usr->lm_pwd, sizeof(usr->lm_pwd)))
		return False;
	if(!prs_uint8s(False, "nt_pwd        ", ps, depth, usr->nt_pwd, sizeof(usr->nt_pwd)))
		return False;

	if(!prs_uint32("user_rid      ", ps, depth, &usr->user_rid))	/* User ID */
		return False;
	if(!prs_uint32("group_rid     ", ps, depth, &usr->group_rid))	/* Group ID */
		return False;
	if(!prs_uint32("acb_info      ", ps, depth, &usr->acb_info))
		return False;

	if(!prs_uint32("fields_present ", ps, depth, &usr->fields_present))
		return False;
	if(!prs_uint16("logon_divs    ", ps, depth, &usr->logon_divs))	/* logon divisions per week */
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("ptr_logon_hrs ", ps, depth, &usr->ptr_logon_hrs))
		return False;

	if(!prs_uint16("bad_password_count     ", ps, depth, &usr->bad_password_count))
		return False;
	if(!prs_uint16("logon_count     ", ps, depth, &usr->logon_count))
		return False;

	if(!prs_uint8s(False, "padding1      ", ps, depth, usr->padding1, sizeof(usr->padding1)))
		return False;
	if(!prs_uint8("passmustchange ", ps, depth, &usr->passmustchange))
		return False;
	if(!prs_uint8("padding2       ", ps, depth, &usr->padding2))
		return False;

	/* here begins pointed-to data */

	if(!smb_io_unistr2("uni_user_name   ", &usr->uni_user_name,usr->hdr_user_name.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_full_name   ", &usr->uni_full_name, usr->hdr_full_name.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_home_dir    ", &usr->uni_home_dir, usr->hdr_home_dir.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_dir_drive   ", &usr->uni_dir_drive, usr->hdr_dir_drive.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_logon_script", &usr->uni_logon_script, usr->hdr_logon_script.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_profile_path", &usr->uni_profile_path, usr->hdr_profile_path.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_acct_desc   ", &usr->uni_acct_desc, usr->hdr_acct_desc.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_workstations", &usr->uni_workstations, usr->hdr_workstations.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_comment", &usr->uni_comment, usr->hdr_comment.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_munged_dial ", &usr->uni_munged_dial,usr->hdr_munged_dial.buffer, ps, depth))
		return False;

	/* ok, this is only guess-work (as usual) */
	if (usr->ptr_logon_hrs) {
		if(!sam_io_logon_hrs("logon_hrs", &usr->logon_hrs, ps, depth))
			return False;
	}

	return True;
}

void init_sam_user_info20A(SAM_USER_INFO_20 *usr, struct samu *pw)
{
	const char *munged_dial = pdb_get_munged_dial(pw);
	DATA_BLOB blob;

	if (munged_dial) {
		blob = base64_decode_data_blob(munged_dial);
	} else {
		blob = data_blob_null;
	}

	init_unistr2_from_datablob(&usr->uni_munged_dial, &blob);
	init_uni_hdr(&usr->hdr_munged_dial, &usr->uni_munged_dial);
	data_blob_free(&blob);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool sam_io_user_info20(const char *desc, SAM_USER_INFO_20 *usr,
			prs_struct *ps, int depth)
{
	if (usr == NULL)
		return False;

	prs_debug(ps, depth, desc, "sam_io_user_info20");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unihdr("hdr_munged_dial ", &usr->hdr_munged_dial, ps, depth))	/* wkstas user can log on from */
		return False;

	if(!smb_io_unistr2("uni_munged_dial ", &usr->uni_munged_dial,usr->hdr_munged_dial.buffer, ps, depth))	/* worksations user can log on from */
		return False;

	return True;
}

/*******************************************************************
inits a SAM_USERINFO_CTR structure.
********************************************************************/

NTSTATUS make_samr_userinfo_ctr_usr21(TALLOC_CTX *ctx, SAM_USERINFO_CTR * ctr,
				    uint16 switch_value,
				    SAM_USER_INFO_21 * usr)
{
	DEBUG(5, ("make_samr_userinfo_ctr_usr21\n"));

	ctr->switch_value = switch_value;
	ctr->info.id = NULL;

	switch (switch_value) {
	case 16:
		ctr->info.id16 = TALLOC_ZERO_P(ctx,SAM_USER_INFO_16);
		if (ctr->info.id16 == NULL)
			return NT_STATUS_NO_MEMORY;

		init_sam_user_info16(ctr->info.id16, usr->acb_info);
		break;
#if 0
/* whoops - got this wrong.  i think.  or don't understand what's happening. */
	case 17:
		{
			NTTIME expire;
			info = (void *)&id11;

			expire.low = 0xffffffff;
			expire.high = 0x7fffffff;

			ctr->info.id = TALLOC_ZERO_P(ctx,SAM_USER_INFO_17);
			init_sam_user_info11(ctr->info.id17, &expire,
					     "BROOKFIELDS$",	/* name */
					     0x03ef,	/* user rid */
					     0x201,	/* group rid */
					     0x0080);	/* acb info */

			break;
		}
#endif
	case 18:
		ctr->info.id18 = TALLOC_ZERO_P(ctx,SAM_USER_INFO_18);
		if (ctr->info.id18 == NULL)
			return NT_STATUS_NO_MEMORY;

		init_sam_user_info18(ctr->info.id18, usr->lm_pwd, usr->nt_pwd);
		break;
	case 21:
		{
			SAM_USER_INFO_21 *cusr;
			cusr = TALLOC_ZERO_P(ctx,SAM_USER_INFO_21);
			ctr->info.id21 = cusr;
			if (ctr->info.id21 == NULL)
				return NT_STATUS_NO_MEMORY;
			memcpy(cusr, usr, sizeof(*usr));
			memset(cusr->lm_pwd, 0, sizeof(cusr->lm_pwd));
			memset(cusr->nt_pwd, 0, sizeof(cusr->nt_pwd));
			break;
		}
	default:
		DEBUG(4,("make_samr_userinfo_ctr: unsupported info\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
inits a SAM_USERINFO_CTR structure.
********************************************************************/

static void init_samr_userinfo_ctr(SAM_USERINFO_CTR * ctr, DATA_BLOB *sess_key,
				   uint16 switch_value, void *info)
{
	DEBUG(5, ("init_samr_userinfo_ctr\n"));

	ctr->switch_value = switch_value;
	ctr->info.id = info;

	switch (switch_value) {
	case 0x18:
		SamOEMhashBlob(ctr->info.id24->pass, 516, sess_key);
		dump_data(100, sess_key->data, sess_key->length);
		dump_data(100, ctr->info.id24->pass, 516);
		break;
	case 0x17:
		SamOEMhashBlob(ctr->info.id23->pass, 516, sess_key);
		dump_data(100, sess_key->data, sess_key->length);
		dump_data(100, ctr->info.id23->pass, 516);
		break;
	case 0x07:
		break;
	default:
		DEBUG(4,("init_samr_userinfo_ctr: unsupported switch level: %d\n", switch_value));
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static bool samr_io_userinfo_ctr(const char *desc, SAM_USERINFO_CTR **ppctr,
				 prs_struct *ps, int depth)
{
	bool ret;
	SAM_USERINFO_CTR *ctr;

	prs_debug(ps, depth, desc, "samr_io_userinfo_ctr");
	depth++;

	if (UNMARSHALLING(ps)) {
		ctr = PRS_ALLOC_MEM(ps,SAM_USERINFO_CTR,1);
		if (ctr == NULL)
			return False;
		*ppctr = ctr;
	} else {
		ctr = *ppctr;
	}

	/* lkclXXXX DO NOT ALIGN BEFORE READING SWITCH VALUE! */

	if(!prs_uint16("switch_value", ps, depth, &ctr->switch_value))
		return False;
	if(!prs_align(ps))
		return False;

	ret = False;

	switch (ctr->switch_value) {
	case 7:
		if (UNMARSHALLING(ps))
			ctr->info.id7 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_7,1);
		if (ctr->info.id7 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info7("", ctr->info.id7, ps, depth);
		break;
	case 9:
		if (UNMARSHALLING(ps))
			ctr->info.id9 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_9,1);
		if (ctr->info.id9 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info9("", ctr->info.id9, ps, depth);
		break;
	case 16:
		if (UNMARSHALLING(ps))
			ctr->info.id16 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_16,1);
		if (ctr->info.id16 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info16("", ctr->info.id16, ps, depth);
		break;
	case 17:
		if (UNMARSHALLING(ps))
			ctr->info.id17 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_17,1);

		if (ctr->info.id17 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info17("", ctr->info.id17, ps, depth);
		break;
	case 18:
		if (UNMARSHALLING(ps))
			ctr->info.id18 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_18,1);

		if (ctr->info.id18 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info18("", ctr->info.id18, ps, depth);
		break;
	case 20:
		if (UNMARSHALLING(ps))
			ctr->info.id20 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_20,1);

		if (ctr->info.id20 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info20("", ctr->info.id20, ps, depth);
		break;
	case 21:
		if (UNMARSHALLING(ps))
			ctr->info.id21 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_21,1);

		if (ctr->info.id21 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info21("", ctr->info.id21, ps, depth);
		break;
	case 23:
		if (UNMARSHALLING(ps))
			ctr->info.id23 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_23,1);

		if (ctr->info.id23 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info23("", ctr->info.id23, ps, depth);
		break;
	case 24:
		if (UNMARSHALLING(ps))
			ctr->info.id24 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_24,1);

		if (ctr->info.id24 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info24("", ctr->info.id24, ps,  depth);
		break;
	case 25:
		if (UNMARSHALLING(ps))
			ctr->info.id25 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_25,1);

		if (ctr->info.id25 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info25("", ctr->info.id25, ps, depth);
		break;
	case 26:
		if (UNMARSHALLING(ps))
			ctr->info.id26 = PRS_ALLOC_MEM(ps,SAM_USER_INFO_26,1);

		if (ctr->info.id26 == NULL) {
			DEBUG(2,("samr_io_userinfo_ctr: info pointer not initialised\n"));
			return False;
		}
		ret = sam_io_user_info26("", ctr->info.id26, ps,  depth);
		break;
	default:
		DEBUG(2, ("samr_io_userinfo_ctr: unknown switch level 0x%x\n", ctr->switch_value));
		ret = False;
		break;
	}

	return ret;
}

/*******************************************************************
inits a SAMR_Q_SET_USERINFO structure.
********************************************************************/

void init_samr_q_set_userinfo(SAMR_Q_SET_USERINFO * q_u,
			      const POLICY_HND *hnd, DATA_BLOB *sess_key,
			      uint16 switch_value, void *info)
{
	DEBUG(5, ("init_samr_q_set_userinfo\n"));

	q_u->pol = *hnd;
	q_u->switch_value = switch_value;
	init_samr_userinfo_ctr(q_u->ctr, sess_key, switch_value, info);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_q_set_userinfo(const char *desc, SAMR_Q_SET_USERINFO * q_u,
			    prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_userinfo");
	depth++;

	if(!prs_align(ps))
		return False;

	smb_io_pol_hnd("pol", &(q_u->pol), ps, depth);

	if(!prs_uint16("switch_value", ps, depth, &q_u->switch_value))
		return False;
	if(!samr_io_userinfo_ctr("ctr", &q_u->ctr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_R_SET_USERINFO structure.
********************************************************************/

void init_samr_r_set_userinfo(SAMR_R_SET_USERINFO * r_u, NTSTATUS status)
{
	DEBUG(5, ("init_samr_r_set_userinfo\n"));

	r_u->status = status;	/* return status */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_r_set_userinfo(const char *desc, SAMR_R_SET_USERINFO * r_u,
			    prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_userinfo");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_Q_SET_USERINFO2 structure.
********************************************************************/

void init_samr_q_set_userinfo2(SAMR_Q_SET_USERINFO2 * q_u,
			       const POLICY_HND *hnd, DATA_BLOB *sess_key,
			       uint16 switch_value, SAM_USERINFO_CTR * ctr)
{
	DEBUG(5, ("init_samr_q_set_userinfo2\n"));

	q_u->pol = *hnd;
	q_u->switch_value = switch_value;
	q_u->ctr = ctr;

	q_u->ctr->switch_value = switch_value;

	switch (switch_value) {
	case 18:
		SamOEMhashBlob(ctr->info.id18->lm_pwd, 16, sess_key);
		SamOEMhashBlob(ctr->info.id18->nt_pwd, 16, sess_key);
		dump_data(100, sess_key->data, sess_key->length);
		dump_data(100, ctr->info.id18->lm_pwd, 16);
		dump_data(100, ctr->info.id18->nt_pwd, 16);
		break;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_q_set_userinfo2(const char *desc, SAMR_Q_SET_USERINFO2 * q_u,
			     prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_q_set_userinfo2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("pol", &q_u->pol, ps, depth))
		return False;

	if(!prs_uint16("switch_value", ps, depth, &q_u->switch_value))
		return False;
	if(!samr_io_userinfo_ctr("ctr", &q_u->ctr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
inits a SAMR_R_SET_USERINFO2 structure.
********************************************************************/

void init_samr_r_set_userinfo2(SAMR_R_SET_USERINFO2 * r_u, NTSTATUS status)
{
	DEBUG(5, ("init_samr_r_set_userinfo2\n"));

	r_u->status = status;	/* return status */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool samr_io_r_set_userinfo2(const char *desc, SAMR_R_SET_USERINFO2 * r_u,
			     prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "samr_io_r_set_userinfo2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}
