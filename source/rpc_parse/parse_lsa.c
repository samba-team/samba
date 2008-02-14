/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Andrew Bartlett                   2002,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002.
 *  Copyright (C) Gerald )Jerry) Carter             2005
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

static bool lsa_io_trans_names(const char *desc, LSA_TRANS_NAME_ENUM *trn, prs_struct *ps, int depth);
static bool lsa_io_trans_names2(const char *desc, LSA_TRANS_NAME_ENUM2 *trn, prs_struct *ps, int depth);

/*******************************************************************
 Inits a LSA_TRANS_NAME structure.
********************************************************************/

void init_lsa_trans_name(LSA_TRANS_NAME *trn, UNISTR2 *uni_name,
			 uint16 sid_name_use, const char *name, uint32 idx)
{
	trn->sid_name_use = sid_name_use;
	init_unistr2(uni_name, name, UNI_FLAGS_NONE);
	init_uni_hdr(&trn->hdr_name, uni_name);
	trn->domain_idx = idx;
}

/*******************************************************************
 Reads or writes a LSA_TRANS_NAME structure.
********************************************************************/

static bool lsa_io_trans_name(const char *desc, LSA_TRANS_NAME *trn, prs_struct *ps, 
			      int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_trans_name");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint16("sid_name_use", ps, depth, &trn->sid_name_use))
		return False;
	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unihdr ("hdr_name", &trn->hdr_name, ps, depth))
		return False;
	if(!prs_uint32("domain_idx  ", ps, depth, &trn->domain_idx))
		return False;

	return True;
}

/*******************************************************************
 Inits a LSA_TRANS_NAME2 structure.
********************************************************************/

void init_lsa_trans_name2(LSA_TRANS_NAME2 *trn, UNISTR2 *uni_name,
			 uint16 sid_name_use, const char *name, uint32 idx)
{
	trn->sid_name_use = sid_name_use;
	init_unistr2(uni_name, name, UNI_FLAGS_NONE);
	init_uni_hdr(&trn->hdr_name, uni_name);
	trn->domain_idx = idx;
	trn->unknown = 0;
}

/*******************************************************************
 Reads or writes a LSA_TRANS_NAME2 structure.
********************************************************************/

static bool lsa_io_trans_name2(const char *desc, LSA_TRANS_NAME2 *trn, prs_struct *ps, 
			      int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_trans_name2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint16("sid_name_use", ps, depth, &trn->sid_name_use))
		return False;
	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unihdr ("hdr_name", &trn->hdr_name, ps, depth))
		return False;
	if(!prs_uint32("domain_idx  ", ps, depth, &trn->domain_idx))
		return False;
	if(!prs_uint32("unknown  ", ps, depth, &trn->unknown))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a DOM_R_REF structure.
********************************************************************/

static bool lsa_io_dom_r_ref(const char *desc, DOM_R_REF *dom, prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_dom_r_ref");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("num_ref_doms_1", ps, depth, &dom->num_ref_doms_1)) /* num referenced domains? */
		return False;
	if(!prs_uint32("ptr_ref_dom   ", ps, depth, &dom->ptr_ref_dom)) /* undocumented buffer pointer. */
		return False;
	if(!prs_uint32("max_entries   ", ps, depth, &dom->max_entries)) /* 32 - max number of entries */
		return False;

	SMB_ASSERT_ARRAY(dom->hdr_ref_dom, dom->num_ref_doms_1);

	if (dom->ptr_ref_dom != 0) {

		if(!prs_uint32("num_ref_doms_2", ps, depth, &dom->num_ref_doms_2)) /* 4 - num referenced domains? */
			return False;

		SMB_ASSERT_ARRAY(dom->ref_dom, dom->num_ref_doms_2);

		for (i = 0; i < dom->num_ref_doms_1; i++) {
			fstring t;

			slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
			if(!smb_io_unihdr(t, &dom->hdr_ref_dom[i].hdr_dom_name, ps, depth))
				return False;

			slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
			if(!prs_uint32(t, ps, depth, &dom->hdr_ref_dom[i].ptr_dom_sid))
				return False;
		}

		for (i = 0; i < dom->num_ref_doms_2; i++) {
			fstring t;

			if (dom->hdr_ref_dom[i].hdr_dom_name.buffer != 0) {
				slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
				if(!smb_io_unistr2(t, &dom->ref_dom[i].uni_dom_name, True, ps, depth)) /* domain name unicode string */
					return False;
				if(!prs_align(ps))
					return False;
			}

			if (dom->hdr_ref_dom[i].ptr_dom_sid != 0) {
				slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
				if(!smb_io_dom_sid2(t, &dom->ref_dom[i].ref_dom, ps, depth)) /* referenced domain SIDs */
					return False;
			}
		}
	}

	return True;
}

/*******************************************************************
 Inits a LSA_SID_ENUM structure.
********************************************************************/

static void init_lsa_sid_enum(TALLOC_CTX *mem_ctx, LSA_SID_ENUM *sen, 
		       int num_entries, const DOM_SID *sids)
{
	int i;

	DEBUG(5, ("init_lsa_sid_enum\n"));

	sen->num_entries  = num_entries;
	sen->ptr_sid_enum = (num_entries != 0);
	sen->num_entries2 = num_entries;

	/* Allocate memory for sids and sid pointers */

	if (num_entries) {
		if ((sen->ptr_sid = TALLOC_ZERO_ARRAY(mem_ctx, uint32, num_entries )) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for ptr_sid\n"));
			return;
		}

		if ((sen->sid = TALLOC_ZERO_ARRAY(mem_ctx, DOM_SID2, num_entries)) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for sids\n"));
			return;
		}
	}

	/* Copy across SIDs and SID pointers */

	for (i = 0; i < num_entries; i++) {
		sen->ptr_sid[i] = 1;
		init_dom_sid2(&sen->sid[i], &sids[i]);
	}
}

/*******************************************************************
 Reads or writes a LSA_SID_ENUM structure.
********************************************************************/

static bool lsa_io_sid_enum(const char *desc, LSA_SID_ENUM *sen, prs_struct *ps, 
			    int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_sid_enum");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("num_entries ", ps, depth, &sen->num_entries))
		return False;
	if(!prs_uint32("ptr_sid_enum", ps, depth, &sen->ptr_sid_enum))
		return False;

	/*
	   if the ptr is NULL, leave here. checked from a real w2k trace.
	   JFM, 11/23/2001
	 */
	
	if (sen->ptr_sid_enum==0)
		return True;

	if(!prs_uint32("num_entries2", ps, depth, &sen->num_entries2))
		return False;

	/* Mallocate memory if we're unpacking from the wire */

	if (UNMARSHALLING(ps) && sen->num_entries) {
		if ((sen->ptr_sid = PRS_ALLOC_MEM( ps, uint32, sen->num_entries)) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for "
				  "ptr_sid\n"));
			return False;
		}

		if ((sen->sid = PRS_ALLOC_MEM( ps, DOM_SID2, sen->num_entries)) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for "
				  "sids\n"));
			return False;
		}
	}

	for (i = 0; i < sen->num_entries; i++) {	
		fstring temp;

		slprintf(temp, sizeof(temp) - 1, "ptr_sid[%d]", i);
		if(!prs_uint32(temp, ps, depth, &sen->ptr_sid[i])) {
			return False;
		}
	}

	for (i = 0; i < sen->num_entries; i++) {
		fstring temp;

		slprintf(temp, sizeof(temp) - 1, "sid[%d]", i);
		if(!smb_io_dom_sid2(temp, &sen->sid[i], ps, depth)) {
			return False;
		}
	}

	return True;
}

/*******************************************************************
 Inits an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/

void init_q_lookup_sids(TALLOC_CTX *mem_ctx, LSA_Q_LOOKUP_SIDS *q_l, 
			POLICY_HND *hnd, int num_sids, const DOM_SID *sids,
			uint16 level)
{
	DEBUG(5, ("init_q_lookup_sids\n"));

	ZERO_STRUCTP(q_l);

	memcpy(&q_l->pol, hnd, sizeof(q_l->pol));
	init_lsa_sid_enum(mem_ctx, &q_l->sids, num_sids, sids);
	
	q_l->level = level;
}

/*******************************************************************
 Reads or writes a LSA_Q_LOOKUP_SIDS structure.
********************************************************************/

bool lsa_io_q_lookup_sids(const char *desc, LSA_Q_LOOKUP_SIDS *q_s, prs_struct *ps,
			  int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_lookup_sids");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("pol_hnd", &q_s->pol, ps, depth)) /* policy handle */
		return False;
	if(!lsa_io_sid_enum("sids   ", &q_s->sids, ps, depth)) /* sids to be looked up */
		return False;
	if(!lsa_io_trans_names("names  ", &q_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_uint16("level", ps, depth, &q_s->level)) /* lookup level */
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &q_s->mapped_count))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a LSA_Q_LOOKUP_SIDS2 structure.
********************************************************************/

bool lsa_io_q_lookup_sids2(const char *desc, LSA_Q_LOOKUP_SIDS2 *q_s, prs_struct *ps,
			  int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_lookup_sids2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("pol_hnd", &q_s->pol, ps, depth)) /* policy handle */
		return False;
	if(!lsa_io_sid_enum("sids   ", &q_s->sids, ps, depth)) /* sids to be looked up */
		return False;
	if(!lsa_io_trans_names2("names  ", &q_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_uint16("level", ps, depth, &q_s->level)) /* lookup level */
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &q_s->mapped_count))
		return False;
	if(!prs_uint32("unknown1", ps, depth, &q_s->unknown1))
		return False;
	if(!prs_uint32("unknown2", ps, depth, &q_s->unknown2))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a LSA_Q_LOOKUP_SIDS3 structure.
********************************************************************/

bool lsa_io_q_lookup_sids3(const char *desc, LSA_Q_LOOKUP_SIDS3 *q_s, prs_struct *ps,
			  int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_lookup_sids3");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!lsa_io_sid_enum("sids   ", &q_s->sids, ps, depth)) /* sids to be looked up */
		return False;
	if(!lsa_io_trans_names2("names  ", &q_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_uint16("level", ps, depth, &q_s->level)) /* lookup level */
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &q_s->mapped_count))
		return False;
	if(!prs_uint32("unknown1", ps, depth, &q_s->unknown1))
		return False;
	if(!prs_uint32("unknown2", ps, depth, &q_s->unknown2))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool lsa_io_trans_names(const char *desc, LSA_TRANS_NAME_ENUM *trn,
                prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_trans_names");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("num_entries    ", ps, depth, &trn->num_entries))
		return False;
	if(!prs_uint32("ptr_trans_names", ps, depth, &trn->ptr_trans_names))
		return False;

	if (trn->ptr_trans_names != 0) {
		if(!prs_uint32("num_entries2   ", ps, depth, 
			       &trn->num_entries2))
			return False;

		if (trn->num_entries2 != trn->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && trn->num_entries2) {
			if ((trn->name = PRS_ALLOC_MEM(ps, LSA_TRANS_NAME, trn->num_entries2)) == NULL) {
				return False;
			}

			if ((trn->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, trn->num_entries2)) == NULL) {
				return False;
			}
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!lsa_io_trans_name(t, &trn->name[i], ps, depth)) /* translated name */
				return False;
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!smb_io_unistr2(t, &trn->uni_name[i], trn->name[i].hdr_name.buffer, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
		}
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool lsa_io_trans_names2(const char *desc, LSA_TRANS_NAME_ENUM2 *trn,
                prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_trans_names2");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("num_entries    ", ps, depth, &trn->num_entries))
		return False;
	if(!prs_uint32("ptr_trans_names", ps, depth, &trn->ptr_trans_names))
		return False;

	if (trn->ptr_trans_names != 0) {
		if(!prs_uint32("num_entries2   ", ps, depth, 
			       &trn->num_entries2))
			return False;

		if (trn->num_entries2 != trn->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && trn->num_entries2) {
			if ((trn->name = PRS_ALLOC_MEM(ps, LSA_TRANS_NAME2, trn->num_entries2)) == NULL) {
				return False;
			}

			if ((trn->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, trn->num_entries2)) == NULL) {
				return False;
			}
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!lsa_io_trans_name2(t, &trn->name[i], ps, depth)) /* translated name */
				return False;
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!smb_io_unistr2(t, &trn->uni_name[i], trn->name[i].hdr_name.buffer, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
		}
	}

	return True;
}


/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_sids(const char *desc, LSA_R_LOOKUP_SIDS *r_s, 
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_lookup_sids");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_dom_ref", ps, depth, &r_s->ptr_dom_ref))
		return False;

	if (r_s->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref ("dom_ref", r_s->dom_ref, ps, depth)) /* domain reference info */
			return False;

	if(!lsa_io_trans_names("names  ", &r_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &r_s->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_s->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_sids2(const char *desc, LSA_R_LOOKUP_SIDS2 *r_s, 
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_lookup_sids2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_dom_ref", ps, depth, &r_s->ptr_dom_ref))
		return False;

	if (r_s->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref ("dom_ref", r_s->dom_ref, ps, depth)) /* domain reference info */
			return False;

	if(!lsa_io_trans_names2("names  ", &r_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &r_s->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_s->status))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_sids3(const char *desc, LSA_R_LOOKUP_SIDS3 *r_s, 
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_lookup_sids3");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_dom_ref", ps, depth, &r_s->ptr_dom_ref))
		return False;

	if (r_s->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref ("dom_ref", r_s->dom_ref, ps, depth)) /* domain reference info */
			return False;

	if(!lsa_io_trans_names2("names  ", &r_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &r_s->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_s->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_q_lookup_names(TALLOC_CTX *mem_ctx, LSA_Q_LOOKUP_NAMES *q_l, 
			 POLICY_HND *hnd, int num_names, const char **names, 
			 int level)
{
	unsigned int i;

	DEBUG(5, ("init_q_lookup_names\n"));

	ZERO_STRUCTP(q_l);

	q_l->pol = *hnd;
	q_l->num_entries = num_names;
	q_l->num_entries2 = num_names;
	q_l->lookup_level = level;

	if (num_names) {
		if ((q_l->uni_name = TALLOC_ZERO_ARRAY(mem_ctx, UNISTR2, num_names)) == NULL) {
			DEBUG(3, ("init_q_lookup_names(): out of memory\n"));
			return;
		}

		if ((q_l->hdr_name = TALLOC_ZERO_ARRAY(mem_ctx, UNIHDR, num_names)) == NULL) {
			DEBUG(3, ("init_q_lookup_names(): out of memory\n"));
			return;
		}
	} else {
		q_l->uni_name = NULL;
		q_l->hdr_name = NULL;
	}

	for (i = 0; i < num_names; i++) {
		init_unistr2(&q_l->uni_name[i], names[i], UNI_FLAGS_NONE);
		init_uni_hdr(&q_l->hdr_name[i], &q_l->uni_name[i]);
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool lsa_io_q_lookup_names(const char *desc, LSA_Q_LOOKUP_NAMES *q_r, 
			   prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &q_r->pol, ps, depth)) /* policy handle */
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries    ", ps, depth, &q_r->num_entries))
		return False;
	if(!prs_uint32("num_entries2   ", ps, depth, &q_r->num_entries2))
		return False;

	if (UNMARSHALLING(ps)) {
		if (q_r->num_entries) {
			if ((q_r->hdr_name = PRS_ALLOC_MEM(ps, UNIHDR, q_r->num_entries)) == NULL)
				return False;
			if ((q_r->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, q_r->num_entries)) == NULL)
				return False;
		}
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unihdr("hdr_name", &q_r->hdr_name[i], ps, depth)) /* pointer names */
			return False;
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("dom_name", &q_r->uni_name[i], q_r->hdr_name[i].buffer, ps, depth)) /* names to be looked up */
			return False;
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_trans_entries ", ps, depth, &q_r->num_trans_entries))
		return False;
	if(!prs_uint32("ptr_trans_sids ", ps, depth, &q_r->ptr_trans_sids))
		return False;
	if(!prs_uint16("lookup_level   ", ps, depth, &q_r->lookup_level))
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("mapped_count   ", ps, depth, &q_r->mapped_count))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_names(const char *desc, LSA_R_LOOKUP_NAMES *out, prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_dom_ref", ps, depth, &out->ptr_dom_ref))
		return False;

	if (out->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref("", out->dom_ref, ps, depth))
			return False;

	if(!prs_uint32("num_entries", ps, depth, &out->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &out->ptr_entries))
		return False;

	if (out->ptr_entries != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &out->num_entries2))
			return False;

		if (out->num_entries2 != out->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && out->num_entries2) {
			if ((out->dom_rid = PRS_ALLOC_MEM(ps, DOM_RID, out->num_entries2))
			    == NULL) {
				DEBUG(3, ("lsa_io_r_lookup_names(): out of memory\n"));
				return False;
			}
		}

		for (i = 0; i < out->num_entries2; i++)
			if(!smb_io_dom_rid("", &out->dom_rid[i], ps, depth)) /* domain RIDs being looked up */
				return False;
	}

	if(!prs_uint32("mapped_count", ps, depth, &out->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &out->status))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool lsa_io_q_lookup_names2(const char *desc, LSA_Q_LOOKUP_NAMES2 *q_r, 
			   prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &q_r->pol, ps, depth)) /* policy handle */
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries    ", ps, depth, &q_r->num_entries))
		return False;
	if(!prs_uint32("num_entries2   ", ps, depth, &q_r->num_entries2))
		return False;

	if (UNMARSHALLING(ps)) {
		if (q_r->num_entries) {
			if ((q_r->hdr_name = PRS_ALLOC_MEM(ps, UNIHDR, q_r->num_entries)) == NULL)
				return False;
			if ((q_r->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, q_r->num_entries)) == NULL)
				return False;
		}
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unihdr("hdr_name", &q_r->hdr_name[i], ps, depth)) /* pointer names */
			return False;
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("dom_name", &q_r->uni_name[i], q_r->hdr_name[i].buffer, ps, depth)) /* names to be looked up */
			return False;
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_trans_entries ", ps, depth, &q_r->num_trans_entries))
		return False;
	if(!prs_uint32("ptr_trans_sids ", ps, depth, &q_r->ptr_trans_sids))
		return False;
	if(!prs_uint16("lookup_level   ", ps, depth, &q_r->lookup_level))
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("mapped_count   ", ps, depth, &q_r->mapped_count))
		return False;
	if(!prs_uint32("unknown1   ", ps, depth, &q_r->unknown1))
		return False;
	if(!prs_uint32("unknown2   ", ps, depth, &q_r->unknown2))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_names2(const char *desc, LSA_R_LOOKUP_NAMES2 *out, prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names2");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_dom_ref", ps, depth, &out->ptr_dom_ref))
		return False;

	if (out->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref("", out->dom_ref, ps, depth))
			return False;

	if(!prs_uint32("num_entries", ps, depth, &out->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &out->ptr_entries))
		return False;

	if (out->ptr_entries != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &out->num_entries2))
			return False;

		if (out->num_entries2 != out->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && out->num_entries2) {
			if ((out->dom_rid = PRS_ALLOC_MEM(ps, DOM_RID2, out->num_entries2))
			    == NULL) {
				DEBUG(3, ("lsa_io_r_lookup_names2(): out of memory\n"));
				return False;
			}
		}

		for (i = 0; i < out->num_entries2; i++)
			if(!smb_io_dom_rid2("", &out->dom_rid[i], ps, depth)) /* domain RIDs being looked up */
				return False;
	}

	if(!prs_uint32("mapped_count", ps, depth, &out->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &out->status))
		return False;

	return True;
}

/*******************************************************************
 Internal lsa data type io.
 Following pass must read DOM_SID2 types.
********************************************************************/

bool smb_io_lsa_translated_sids3(const char *desc, LSA_TRANSLATED_SID3 *q_r, 
			   prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_lsa_translated_sids3");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint8 ("sid_type ", ps, depth, &q_r->sid_type ))
		return False;
	if(!prs_align(ps))
		return False;
	/* Second pass will read/write these. */
	if (!smb_io_dom_sid2_p("sid_header", ps, depth, &q_r->sid2))
		return False;
	if(!prs_uint32("sid_idx ", ps, depth, &q_r->sid_idx ))
		return False;
	if(!prs_uint32("unknown ", ps, depth, &q_r->unknown ))
		return False;
	
	return True;
}

/*******************************************************************
 Identical to lsa_io_q_lookup_names2.
********************************************************************/

bool lsa_io_q_lookup_names3(const char *desc, LSA_Q_LOOKUP_NAMES3 *q_r, 
			   prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names3");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &q_r->pol, ps, depth)) /* policy handle */
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries    ", ps, depth, &q_r->num_entries))
		return False;
	if(!prs_uint32("num_entries2   ", ps, depth, &q_r->num_entries2))
		return False;

	if (UNMARSHALLING(ps)) {
		if (q_r->num_entries) {
			if ((q_r->hdr_name = PRS_ALLOC_MEM(ps, UNIHDR, q_r->num_entries)) == NULL)
				return False;
			if ((q_r->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, q_r->num_entries)) == NULL)
				return False;
		}
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unihdr("hdr_name", &q_r->hdr_name[i], ps, depth)) /* pointer names */
			return False;
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("dom_name", &q_r->uni_name[i], q_r->hdr_name[i].buffer, ps, depth)) /* names to be looked up */
			return False;
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_trans_entries ", ps, depth, &q_r->num_trans_entries))
		return False;
	if(!prs_uint32("ptr_trans_sids ", ps, depth, &q_r->ptr_trans_sids))
		return False;
	if(!prs_uint16("lookup_level   ", ps, depth, &q_r->lookup_level))
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("mapped_count   ", ps, depth, &q_r->mapped_count))
		return False;
	if(!prs_uint32("unknown1   ", ps, depth, &q_r->unknown1))
		return False;
	if(!prs_uint32("unknown2   ", ps, depth, &q_r->unknown2))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

bool lsa_io_r_lookup_names3(const char *desc, LSA_R_LOOKUP_NAMES3 *out, prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names3");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_dom_ref", ps, depth, &out->ptr_dom_ref))
		return False;

	if (out->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref("", out->dom_ref, ps, depth))
			return False;

	if(!prs_uint32("num_entries", ps, depth, &out->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &out->ptr_entries))
		return False;

	if (out->ptr_entries != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &out->num_entries2))
			return False;

		if (out->num_entries2 != out->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && out->num_entries2) {
			if ((out->trans_sids = PRS_ALLOC_MEM(ps, LSA_TRANSLATED_SID3, out->num_entries2))
			    == NULL) {
				DEBUG(3, ("lsa_io_r_lookup_names3(): out of memory\n"));
				return False;
			}
		}

		for (i = 0; i < out->num_entries2; i++) {
			if(!smb_io_lsa_translated_sids3("", &out->trans_sids[i], ps, depth)) {
				return False;
			}
		}
		/* Now process the DOM_SID2 entries. */
		for (i = 0; i < out->num_entries2; i++) {
			if (out->trans_sids[i].sid2) {
				if( !smb_io_dom_sid2("sid2", out->trans_sids[i].sid2, ps, depth) ) {
					return False;
				}
			}
		}
	}

	if(!prs_uint32("mapped_count", ps, depth, &out->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &out->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

bool lsa_io_q_lookup_names4(const char *desc, LSA_Q_LOOKUP_NAMES4 *q_r, 
			   prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names4");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_entries    ", ps, depth, &q_r->num_entries))
		return False;
	if(!prs_uint32("num_entries2   ", ps, depth, &q_r->num_entries2))
		return False;

	if (UNMARSHALLING(ps)) {
		if (q_r->num_entries) {
			if ((q_r->hdr_name = PRS_ALLOC_MEM(ps, UNIHDR, q_r->num_entries)) == NULL)
				return False;
			if ((q_r->uni_name = PRS_ALLOC_MEM(ps, UNISTR2, q_r->num_entries)) == NULL)
				return False;
		}
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unihdr("hdr_name", &q_r->hdr_name[i], ps, depth)) /* pointer names */
			return False;
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("dom_name", &q_r->uni_name[i], q_r->hdr_name[i].buffer, ps, depth)) /* names to be looked up */
			return False;
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_trans_entries ", ps, depth, &q_r->num_trans_entries))
		return False;
	if(!prs_uint32("ptr_trans_sids ", ps, depth, &q_r->ptr_trans_sids))
		return False;
	if(!prs_uint16("lookup_level   ", ps, depth, &q_r->lookup_level))
		return False;
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("mapped_count   ", ps, depth, &q_r->mapped_count))
		return False;
	if(!prs_uint32("unknown1   ", ps, depth, &q_r->unknown1))
		return False;
	if(!prs_uint32("unknown2   ", ps, depth, &q_r->unknown2))
		return False;

	return True;
}

/*******************************************************************
 Identical to lsa_io_r_lookup_names3.
********************************************************************/

bool lsa_io_r_lookup_names4(const char *desc, LSA_R_LOOKUP_NAMES4 *out, prs_struct *ps, int depth)
{
	unsigned int i;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names4");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_dom_ref", ps, depth, &out->ptr_dom_ref))
		return False;

	if (out->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref("", out->dom_ref, ps, depth))
			return False;

	if(!prs_uint32("num_entries", ps, depth, &out->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &out->ptr_entries))
		return False;

	if (out->ptr_entries != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &out->num_entries2))
			return False;

		if (out->num_entries2 != out->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps) && out->num_entries2) {
			if ((out->trans_sids = PRS_ALLOC_MEM(ps, LSA_TRANSLATED_SID3, out->num_entries2))
			    == NULL) {
				DEBUG(3, ("lsa_io_r_lookup_names4(): out of memory\n"));
				return False;
			}
		}

		for (i = 0; i < out->num_entries2; i++) {
			if(!smb_io_lsa_translated_sids3("", &out->trans_sids[i], ps, depth)) {
				return False;
			}
		}
		/* Now process the DOM_SID2 entries. */
		for (i = 0; i < out->num_entries2; i++) {
			if (out->trans_sids[i].sid2) {
				if( !smb_io_dom_sid2("sid2", out->trans_sids[i].sid2, ps, depth) ) {
					return False;
				}
			}
		}
	}

	if(!prs_uint32("mapped_count", ps, depth, &out->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &out->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LUID_ATTR structure.
********************************************************************/

bool policy_handle_is_valid(const POLICY_HND *hnd)
{
	POLICY_HND zero_pol;

	ZERO_STRUCT(zero_pol);
	return ((memcmp(&zero_pol, hnd, sizeof(POLICY_HND)) == 0) ? False : True );
}

/*******************************************************************
 Inits an LSA_Q_ENUM_ACCT_RIGHTS structure.
********************************************************************/
void init_q_enum_acct_rights(LSA_Q_ENUM_ACCT_RIGHTS *in, 
			     POLICY_HND *hnd, 
			     uint32 count, 
			     DOM_SID *sid)
{
	DEBUG(5, ("init_q_enum_acct_rights\n"));

	in->pol = *hnd;
	init_dom_sid2(&in->sid, sid);
}

/*******************************************************************
********************************************************************/
NTSTATUS init_r_enum_acct_rights( LSA_R_ENUM_ACCT_RIGHTS *out, PRIVILEGE_SET *privileges )
{
	uint32 i;
	const char *privname;
	const char **privname_array = NULL;
	int num_priv = 0;

	for ( i=0; i<privileges->count; i++ ) {
		privname = luid_to_privilege_name( &privileges->set[i].luid );
		if ( privname ) {
			if ( !add_string_to_array( talloc_tos(), privname, &privname_array, &num_priv ) )
				return NT_STATUS_NO_MEMORY;
		}
	}

	if ( num_priv ) {
		out->rights = TALLOC_P( talloc_tos(), UNISTR4_ARRAY );
		if (!out->rights) {
			return NT_STATUS_NO_MEMORY;
		}

		if ( !init_unistr4_array( out->rights, num_priv, privname_array ) ) 
			return NT_STATUS_NO_MEMORY;

		out->count = num_priv;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
reads or writes a LSA_Q_ENUM_ACCT_RIGHTS structure.
********************************************************************/
bool lsa_io_q_enum_acct_rights(const char *desc, LSA_Q_ENUM_ACCT_RIGHTS *in, prs_struct *ps, int depth)
{
	
	if (in == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_enum_acct_rights");
	depth++;

	if (!smb_io_pol_hnd("", &in->pol, ps, depth))
		return False;

	if(!smb_io_dom_sid2("sid", &in->sid, ps, depth))
		return False;

	return True;
}


/*******************************************************************
reads or writes a LSA_R_ENUM_ACCT_RIGHTS structure.
********************************************************************/
bool lsa_io_r_enum_acct_rights(const char *desc, LSA_R_ENUM_ACCT_RIGHTS *out, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_enum_acct_rights");
	depth++;

	if(!prs_uint32("count   ", ps, depth, &out->count))
		return False;

	if ( !prs_pointer("rights", ps, depth, (void*)&out->rights, sizeof(UNISTR4_ARRAY), (PRS_POINTER_CAST)prs_unistr4_array) )
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &out->status))
		return False;

	return True;
}


/*******************************************************************
 Inits an LSA_Q_ADD_ACCT_RIGHTS structure.
********************************************************************/
void init_q_add_acct_rights( LSA_Q_ADD_ACCT_RIGHTS *in, POLICY_HND *hnd, 
                             DOM_SID *sid, uint32 count, const char **rights )
{
	DEBUG(5, ("init_q_add_acct_rights\n"));

	in->pol = *hnd;
	init_dom_sid2(&in->sid, sid);
	
	in->rights = TALLOC_P( talloc_tos(), UNISTR4_ARRAY );
	if (!in->rights) {
		smb_panic("init_q_add_acct_rights: talloc fail\n");
		return;
	}
	init_unistr4_array( in->rights, count, rights );
	
	in->count = count;
}


/*******************************************************************
reads or writes a LSA_Q_ADD_ACCT_RIGHTS structure.
********************************************************************/
bool lsa_io_q_add_acct_rights(const char *desc, LSA_Q_ADD_ACCT_RIGHTS *in, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_add_acct_rights");
	depth++;

	if (!smb_io_pol_hnd("", &in->pol, ps, depth))
		return False;

	if(!smb_io_dom_sid2("sid", &in->sid, ps, depth))
		return False;

	if(!prs_uint32("count", ps, depth, &in->count))
		return False;

	if ( !prs_pointer("rights", ps, depth, (void*)&in->rights, sizeof(UNISTR4_ARRAY), (PRS_POINTER_CAST)prs_unistr4_array) )
		return False;

	return True;
}

/*******************************************************************
reads or writes a LSA_R_ENUM_ACCT_RIGHTS structure.
********************************************************************/
bool lsa_io_r_add_acct_rights(const char *desc, LSA_R_ADD_ACCT_RIGHTS *out, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_add_acct_rights");
	depth++;

	if(!prs_ntstatus("status", ps, depth, &out->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_Q_REMOVE_ACCT_RIGHTS structure.
********************************************************************/

void init_q_remove_acct_rights(LSA_Q_REMOVE_ACCT_RIGHTS *in, 
			       POLICY_HND *hnd, 
			       DOM_SID *sid,
			       uint32 removeall,
			       uint32 count, 
			       const char **rights)
{
	DEBUG(5, ("init_q_remove_acct_rights\n"));

	in->pol = *hnd;

	init_dom_sid2(&in->sid, sid);

	in->removeall = removeall;
	in->count = count;

	in->rights = TALLOC_P( talloc_tos(), UNISTR4_ARRAY );
	if (!in->rights) {
		smb_panic("init_q_remove_acct_rights: talloc fail\n");
		return;
	}
	init_unistr4_array( in->rights, count, rights );
}

/*******************************************************************
reads or writes a LSA_Q_REMOVE_ACCT_RIGHTS structure.
********************************************************************/

bool lsa_io_q_remove_acct_rights(const char *desc, LSA_Q_REMOVE_ACCT_RIGHTS *in, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_remove_acct_rights");
	depth++;

	if (!smb_io_pol_hnd("", &in->pol, ps, depth))
		return False;

	if(!smb_io_dom_sid2("sid", &in->sid, ps, depth))
		return False;

	if(!prs_uint32("removeall", ps, depth, &in->removeall))
		return False;

	if(!prs_uint32("count", ps, depth, &in->count))
		return False;

	if ( !prs_pointer("rights", ps, depth, (void*)&in->rights, sizeof(UNISTR4_ARRAY), (PRS_POINTER_CAST)prs_unistr4_array) )
		return False;

	return True;
}

/*******************************************************************
reads or writes a LSA_R_ENUM_ACCT_RIGHTS structure.
********************************************************************/
bool lsa_io_r_remove_acct_rights(const char *desc, LSA_R_REMOVE_ACCT_RIGHTS *out, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_remove_acct_rights");
	depth++;

	if(!prs_ntstatus("status", ps, depth, &out->status))
		return False;

	return True;
}
