/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jeremy Allison                    2001, 2006.
 *  Copyright (C) Rafal Szczesniak                  2002,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002,
 *  Copyright (C) Simo Sorce                        2003.
 *  Copyright (C) Gerald (Jerry) Carter             2005.
 *  Copyright (C) Volker Lendecke                   2005.
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

/* This is the implementation of the lsa server code. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

extern PRIVS privs[];

struct lsa_info {
	DOM_SID sid;
	uint32 access;
};

struct generic_mapping lsa_generic_mapping = {
	POLICY_READ,
	POLICY_WRITE,
	POLICY_EXECUTE,
	POLICY_ALL_ACCESS
};

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_lsa_info(void *ptr)
{
	struct lsa_info *lsa = (struct lsa_info *)ptr;

	SAFE_FREE(lsa);
}

/***************************************************************************
Init dom_query
 ***************************************************************************/

static void init_dom_query_3(DOM_QUERY_3 *d_q, const char *dom_name, DOM_SID *dom_sid)
{
	d_q->buffer_dom_name = (dom_name != NULL) ? 1 : 0; /* domain buffer pointer */
	d_q->buffer_dom_sid = (dom_sid != NULL) ? 1 : 0;  /* domain sid pointer */

	/* this string is supposed to be non-null terminated. */
	/* But the maxlen in this UNISTR2 must include the terminating null. */
	init_unistr2(&d_q->uni_domain_name, dom_name, UNI_BROKEN_NON_NULL);

	/*
	 * I'm not sure why this really odd combination of length
	 * values works, but it does appear to. I need to look at
	 * this *much* more closely - but at the moment leave alone
	 * until it's understood. This allows a W2k client to join
	 * a domain with both odd and even length names... JRA.
	 */

	/*
	 * IMPORTANT NOTE !!!!
	 * The two fields below probably are reversed in meaning, ie.
	 * the first field is probably the str_len, the second the max
	 * len. Both are measured in bytes anyway.
	 */

	d_q->uni_dom_str_len = d_q->uni_domain_name.uni_max_len * 2;
	d_q->uni_dom_max_len = d_q->uni_domain_name.uni_str_len * 2;

	if (dom_sid != NULL)
		init_dom_sid2(&d_q->dom_sid, dom_sid);
}

/***************************************************************************
Init dom_query
 ***************************************************************************/

static void init_dom_query_5(DOM_QUERY_5 *d_q, const char *dom_name, DOM_SID *dom_sid)
{
	init_dom_query_3(d_q, dom_name, dom_sid);
}

/***************************************************************************
 init_dom_ref - adds a domain if it's not already in, returns the index.
***************************************************************************/

static int init_dom_ref(DOM_R_REF *ref, const char *dom_name, DOM_SID *dom_sid)
{
	int num = 0;

	if (dom_name != NULL) {
		for (num = 0; num < ref->num_ref_doms_1; num++) {
			if (sid_equal(dom_sid, &ref->ref_dom[num].ref_dom.sid))
				return num;
		}
	} else {
		num = ref->num_ref_doms_1;
	}

	if (num >= MAX_REF_DOMAINS) {
		/* index not found, already at maximum domain limit */
		return -1;
	}

	ref->num_ref_doms_1 = num+1;
	ref->ptr_ref_dom  = 1;
	ref->max_entries = MAX_REF_DOMAINS;
	ref->num_ref_doms_2 = num+1;

	ref->hdr_ref_dom[num].ptr_dom_sid = 1; /* dom sid cannot be NULL. */

	init_unistr2(&ref->ref_dom[num].uni_dom_name, dom_name, UNI_FLAGS_NONE);
	init_uni_hdr(&ref->hdr_ref_dom[num].hdr_dom_name, &ref->ref_dom[num].uni_dom_name);

	init_dom_sid2(&ref->ref_dom[num].ref_dom, dom_sid );

	return num;
}

/***************************************************************************
 lookup_lsa_rids. Must be called as root for lookup_name to work.
 ***************************************************************************/

static NTSTATUS lookup_lsa_rids(TALLOC_CTX *mem_ctx,
			DOM_R_REF *ref,
			DOM_RID *prid,
			uint32 num_entries,
			const UNISTR2 *name,
			int flags,
			uint32 *pmapped_count)
{
	uint32 mapped_count, i;

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	mapped_count = 0;
	*pmapped_count = 0;

	for (i = 0; i < num_entries; i++) {
		DOM_SID sid;
		uint32 rid;
		int dom_idx;
		char *full_name;
		const char *domain;
		enum lsa_SidType type = SID_NAME_UNKNOWN;

		/* Split name into domain and user component */

		full_name = rpcstr_pull_unistr2_talloc(mem_ctx, &name[i]);
		if (full_name == NULL) {
			DEBUG(0, ("pull_ucs2_talloc failed\n"));
			return NT_STATUS_NO_MEMORY;
		}

		DEBUG(5, ("lookup_lsa_rids: looking up name %s\n", full_name));

		/* We can ignore the result of lookup_name, it will not touch
		   "type" if it's not successful */

		lookup_name(mem_ctx, full_name, flags, &domain, NULL,
			    &sid, &type);

		switch (type) {
		case SID_NAME_USER:
		case SID_NAME_DOM_GRP:
		case SID_NAME_DOMAIN:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:
			DEBUG(5, ("init_lsa_rids: %s found\n", full_name));
			/* Leave these unchanged */
			break;
		default:
			/* Don't hand out anything but the list above */
			DEBUG(5, ("init_lsa_rids: %s not found\n", full_name));
			type = SID_NAME_UNKNOWN;
			break;
		}

		rid = 0;
		dom_idx = -1;

		if (type != SID_NAME_UNKNOWN) {
			sid_split_rid(&sid, &rid);
			dom_idx = init_dom_ref(ref, domain, &sid);
			mapped_count++;
		}

		init_dom_rid(&prid[i], rid, type, dom_idx);
	}

	*pmapped_count = mapped_count;
	return NT_STATUS_OK;
}

/***************************************************************************
 lookup_lsa_sids. Must be called as root for lookup_name to work.
 ***************************************************************************/

static NTSTATUS lookup_lsa_sids(TALLOC_CTX *mem_ctx,
			DOM_R_REF *ref,
			LSA_TRANSLATED_SID3 *trans_sids,
			uint32 num_entries,
			const UNISTR2 *name,
			int flags,
			uint32 *pmapped_count)
{
	uint32 mapped_count, i;

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	mapped_count = 0;
	*pmapped_count = 0;

	for (i = 0; i < num_entries; i++) {
		DOM_SID sid;
		uint32 rid;
		int dom_idx;
		char *full_name;
		const char *domain;
		enum lsa_SidType type = SID_NAME_UNKNOWN;

		/* Split name into domain and user component */

		full_name = rpcstr_pull_unistr2_talloc(mem_ctx, &name[i]);
		if (full_name == NULL) {
			DEBUG(0, ("pull_ucs2_talloc failed\n"));
			return NT_STATUS_NO_MEMORY;
		}

		DEBUG(5, ("init_lsa_sids: looking up name %s\n", full_name));

		/* We can ignore the result of lookup_name, it will not touch
		   "type" if it's not successful */

		lookup_name(mem_ctx, full_name, flags, &domain, NULL,
			    &sid, &type);

		switch (type) {
		case SID_NAME_USER:
		case SID_NAME_DOM_GRP:
		case SID_NAME_DOMAIN:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:
			DEBUG(5, ("init_lsa_sids: %s found\n", full_name));
			/* Leave these unchanged */
			break;
		default:
			/* Don't hand out anything but the list above */
			DEBUG(5, ("init_lsa_sids: %s not found\n", full_name));
			type = SID_NAME_UNKNOWN;
			break;
		}

		rid = 0;
		dom_idx = -1;

		if (type != SID_NAME_UNKNOWN) {
			DOM_SID domain_sid;
			sid_copy(&domain_sid, &sid);
			sid_split_rid(&domain_sid, &rid);
			dom_idx = init_dom_ref(ref, domain, &domain_sid);
			mapped_count++;
		}

		/* Initialize the LSA_TRANSLATED_SID3 return. */
		trans_sids[i].sid_type = type;
		trans_sids[i].sid2 = TALLOC_P(mem_ctx, DOM_SID2);
		if (trans_sids[i].sid2 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		init_dom_sid2(trans_sids[i].sid2, &sid);
		trans_sids[i].sid_idx = dom_idx;
	}

	*pmapped_count = mapped_count;
	return NT_STATUS_OK;
}

/***************************************************************************
 init_reply_lookup_names
 ***************************************************************************/

static void init_reply_lookup_names(LSA_R_LOOKUP_NAMES *r_l,
                DOM_R_REF *ref, uint32 num_entries,
                DOM_RID *rid, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->dom_rid      = rid;

	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 init_reply_lookup_names2
 ***************************************************************************/

static void init_reply_lookup_names2(LSA_R_LOOKUP_NAMES2 *r_l,
                DOM_R_REF *ref, uint32 num_entries,
                DOM_RID2 *rid, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->dom_rid      = rid;

	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 init_reply_lookup_names3
 ***************************************************************************/

static void init_reply_lookup_names3(LSA_R_LOOKUP_NAMES3 *r_l,
                DOM_R_REF *ref, uint32 num_entries,
                LSA_TRANSLATED_SID3 *trans_sids, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->trans_sids   = trans_sids;

	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 init_reply_lookup_names4
 ***************************************************************************/

static void init_reply_lookup_names4(LSA_R_LOOKUP_NAMES4 *r_l,
                DOM_R_REF *ref, uint32 num_entries,
                LSA_TRANSLATED_SID3 *trans_sids, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->trans_sids   = trans_sids;

	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 Init_reply_lookup_sids.
 ***************************************************************************/

static void init_reply_lookup_sids2(LSA_R_LOOKUP_SIDS2 *r_l,
				DOM_R_REF *ref,
				LSA_TRANS_NAME_ENUM2 *names,
				uint32 mapped_count)
{
	r_l->ptr_dom_ref  = ref ? 1 : 0;
	r_l->dom_ref      = ref;
	r_l->names        = names;
	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 Init_reply_lookup_sids.
 ***************************************************************************/

static void init_reply_lookup_sids3(LSA_R_LOOKUP_SIDS3 *r_l,
				DOM_R_REF *ref,
				LSA_TRANS_NAME_ENUM2 *names,
				uint32 mapped_count)
{
	r_l->ptr_dom_ref  = ref ? 1 : 0;
	r_l->dom_ref      = ref;
	r_l->names        = names;
	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 Init_reply_lookup_sids.
 ***************************************************************************/

static NTSTATUS init_reply_lookup_sids(TALLOC_CTX *mem_ctx,
				LSA_R_LOOKUP_SIDS *r_l,
				DOM_R_REF *ref,
				LSA_TRANS_NAME_ENUM2 *names,
				uint32 mapped_count)
{
	LSA_TRANS_NAME_ENUM *oldnames = TALLOC_ZERO_P(mem_ctx, LSA_TRANS_NAME_ENUM);

	if (!oldnames) {
		return NT_STATUS_NO_MEMORY;
	}

	oldnames->num_entries = names->num_entries;
	oldnames->ptr_trans_names = names->ptr_trans_names;
	oldnames->num_entries2 = names->num_entries2;
	oldnames->uni_name = names->uni_name;

	if (names->num_entries) {
		int i;

		oldnames->name = TALLOC_ARRAY(oldnames, LSA_TRANS_NAME, names->num_entries);

		if (!oldnames->name) {
			return NT_STATUS_NO_MEMORY;
		}
		for (i = 0; i < names->num_entries; i++) {
			oldnames->name[i].sid_name_use = names->name[i].sid_name_use;
			oldnames->name[i].hdr_name = names->name[i].hdr_name;
			oldnames->name[i].domain_idx = names->name[i].domain_idx;
		}
	}

	r_l->ptr_dom_ref  = ref ? 1 : 0;
	r_l->dom_ref      = ref;
	r_l->names        = oldnames;
	r_l->mapped_count = mapped_count;
	return NT_STATUS_OK;
}

static NTSTATUS lsa_get_generic_sd(TALLOC_CTX *mem_ctx, SEC_DESC **sd, size_t *sd_size)
{
	DOM_SID local_adm_sid;
	DOM_SID adm_sid;

	SEC_ACE ace[3];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;

	init_sec_access(&mask, POLICY_EXECUTE);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	sid_copy(&adm_sid, get_global_sam_sid());
	sid_append_rid(&adm_sid, DOMAIN_GROUP_RID_ADMINS);
	init_sec_access(&mask, POLICY_ALL_ACCESS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	sid_copy(&local_adm_sid, &global_sid_Builtin);
	sid_append_rid(&local_adm_sid, BUILTIN_ALIAS_RID_ADMINS);
	init_sec_access(&mask, POLICY_ALL_ACCESS);
	init_sec_ace(&ace[2], &local_adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if((psa = make_sec_acl(mem_ctx, NT4_ACL_REVISION, 3, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if((*sd = make_sec_desc(mem_ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, &adm_sid, NULL, NULL, psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

#if 0	/* AD DC work in ongoing in Samba 4 */

/***************************************************************************
 Init_dns_dom_info.
***************************************************************************/

static void init_dns_dom_info(LSA_DNS_DOM_INFO *r_l, const char *nb_name,
			      const char *dns_name, const char *forest_name,
			      struct GUID *dom_guid, DOM_SID *dom_sid)
{
	if (nb_name && *nb_name) {
		init_unistr2(&r_l->uni_nb_dom_name, nb_name, UNI_FLAGS_NONE);
		init_uni_hdr(&r_l->hdr_nb_dom_name, &r_l->uni_nb_dom_name);
		r_l->hdr_nb_dom_name.uni_max_len += 2;
		r_l->uni_nb_dom_name.uni_max_len += 1;
	}
	
	if (dns_name && *dns_name) {
		init_unistr2(&r_l->uni_dns_dom_name, dns_name, UNI_FLAGS_NONE);
		init_uni_hdr(&r_l->hdr_dns_dom_name, &r_l->uni_dns_dom_name);
		r_l->hdr_dns_dom_name.uni_max_len += 2;
		r_l->uni_dns_dom_name.uni_max_len += 1;
	}

	if (forest_name && *forest_name) {
		init_unistr2(&r_l->uni_forest_name, forest_name, UNI_FLAGS_NONE);
		init_uni_hdr(&r_l->hdr_forest_name, &r_l->uni_forest_name);
		r_l->hdr_forest_name.uni_max_len += 2;
		r_l->uni_forest_name.uni_max_len += 1;
	}

	/* how do we init the guid ? probably should write an init fn */
	if (dom_guid) {
		memcpy(&r_l->dom_guid, dom_guid, sizeof(struct GUID));
	}
	
	if (dom_sid) {
		r_l->ptr_dom_sid = 1;
		init_dom_sid2(&r_l->dom_sid, dom_sid);
	}
}
#endif	/* AD DC work in ongoing in Samba 4 */


/***************************************************************************
 _lsa_open_policy2.
 ***************************************************************************/

NTSTATUS _lsa_open_policy2(pipes_struct *p, LSA_Q_OPEN_POL2 *q_u, LSA_R_OPEN_POL2 *r_u)
{
	struct lsa_info *info;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	uint32 des_access=q_u->des_access;
	uint32 acc_granted;
	NTSTATUS status;


	/* map the generic bits to the lsa policy ones */
	se_map_generic(&des_access, &lsa_generic_mapping);

	/* get the generic lsa policy SD until we store it */
	lsa_get_generic_sd(p->mem_ctx, &psd, &sd_size);

	if(!se_access_check(psd, p->pipe_user.nt_user_token, des_access, &acc_granted, &status)) {
		if (p->pipe_user.ut.uid != sec_initial_uid()) {
			return status;
		}
		DEBUG(4,("ACCESS should be DENIED (granted: %#010x;  required: %#010x)\n",
			 acc_granted, des_access));
		DEBUGADD(4,("but overwritten by euid == 0\n"));
	}

	/* This is needed for lsa_open_account and rpcclient .... :-) */

	if (p->pipe_user.ut.uid == sec_initial_uid())
		acc_granted = POLICY_ALL_ACCESS;

	/* associate the domain SID with the (unique) handle. */
	if ((info = SMB_MALLOC_P(struct lsa_info)) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	sid_copy(&info->sid,get_global_sam_sid());
	info->access = acc_granted;

	/* set up the LSA QUERY INFO response */
	if (!create_policy_hnd(p, &r_u->pol, free_lsa_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/***************************************************************************
 _lsa_open_policy
 ***************************************************************************/

NTSTATUS _lsa_open_policy(pipes_struct *p, LSA_Q_OPEN_POL *q_u, LSA_R_OPEN_POL *r_u)
{
	struct lsa_info *info;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	uint32 des_access=q_u->des_access;
	uint32 acc_granted;
	NTSTATUS status;


	/* map the generic bits to the lsa policy ones */
	se_map_generic(&des_access, &lsa_generic_mapping);

	/* get the generic lsa policy SD until we store it */
	lsa_get_generic_sd(p->mem_ctx, &psd, &sd_size);

	if(!se_access_check(psd, p->pipe_user.nt_user_token, des_access, &acc_granted, &status)) {
		if (geteuid() != 0) {
			return status;
		}
		DEBUG(4,("ACCESS should be DENIED (granted: %#010x;  required: %#010x)\n",
			 acc_granted, des_access));
		DEBUGADD(4,("but overwritten by euid == 0\n"));
		acc_granted = des_access;
	}

	/* associate the domain SID with the (unique) handle. */
	if ((info = SMB_MALLOC_P(struct lsa_info)) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	sid_copy(&info->sid,get_global_sam_sid());
	info->access = acc_granted;

	/* set up the LSA QUERY INFO response */
	if (!create_policy_hnd(p, &r_u->pol, free_lsa_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/***************************************************************************
 _lsa_enum_trust_dom - this needs fixing to do more than return NULL ! JRA.
 ufff, done :)  mimir
 ***************************************************************************/

NTSTATUS _lsa_enum_trust_dom(pipes_struct *p, LSA_Q_ENUM_TRUST_DOM *q_u,
			     LSA_R_ENUM_TRUST_DOM *r_u)
{
	struct lsa_info *info;
	uint32 next_idx;
	struct trustdom_info **domains;

	/*
	 * preferred length is set to 5 as a "our" preferred length
	 * nt sets this parameter to 2
	 * update (20.08.2002): it's not preferred length, but preferred size!
	 * it needs further investigation how to optimally choose this value
	 */
	uint32 max_num_domains =
		q_u->preferred_len < 5 ? q_u->preferred_len : 10;
	uint32 num_domains;
	NTSTATUS nt_status;
	uint32 num_thistime;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */
	if (!(info->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	nt_status = pdb_enum_trusteddoms(p->mem_ctx, &num_domains, &domains);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (q_u->enum_context < num_domains) {
		num_thistime = MIN(num_domains, max_num_domains);

		r_u->status = STATUS_MORE_ENTRIES;

		if (q_u->enum_context + num_thistime > num_domains) {
			num_thistime = num_domains - q_u->enum_context;
			r_u->status = NT_STATUS_OK;
		}

		next_idx = q_u->enum_context + num_thistime;
	} else {
		num_thistime = 0;
		next_idx = 0xffffffff;
		r_u->status = NT_STATUS_NO_MORE_ENTRIES;
	}
		
	/* set up the lsa_enum_trust_dom response */

	init_r_enum_trust_dom(p->mem_ctx, r_u, next_idx,
			      num_thistime, domains+q_u->enum_context);

	return r_u->status;
}

/***************************************************************************
 _lsa_query_info. See the POLICY_INFOMATION_CLASS docs at msdn.
 ***************************************************************************/

NTSTATUS _lsa_query_info(pipes_struct *p, LSA_Q_QUERY_INFO *q_u, LSA_R_QUERY_INFO *r_u)
{
	struct lsa_info *handle;
	LSA_INFO_CTR *ctr = &r_u->ctr;
	DOM_SID domain_sid;
	const char *name;
	DOM_SID *sid = NULL;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	switch (q_u->info_class) {
	case 0x02:
		{

		uint32 policy_def = LSA_AUDIT_POLICY_ALL;
		
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_AUDIT_INFORMATION)) {
			DEBUG(10,("_lsa_query_info: insufficient access rights\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		/* fake info: We audit everything. ;) */
		ctr->info.id2.ptr = 1;
		ctr->info.id2.auditing_enabled = True;
		ctr->info.id2.count1 = ctr->info.id2.count2 = LSA_AUDIT_NUM_CATEGORIES;

		if ((ctr->info.id2.auditsettings = TALLOC_ZERO_ARRAY(p->mem_ctx, uint32, LSA_AUDIT_NUM_CATEGORIES)) == NULL)
			return NT_STATUS_NO_MEMORY;

		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_ACCOUNT_MANAGEMENT] = policy_def;
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_FILE_AND_OBJECT_ACCESS] = policy_def; 
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_LOGON] = policy_def; 
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_PROCCESS_TRACKING] = policy_def; 
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_SECURITY_POLICY_CHANGES] = policy_def;
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_SYSTEM] = policy_def;
		ctr->info.id2.auditsettings[LSA_AUDIT_CATEGORY_USE_OF_USER_RIGHTS] = policy_def; 

		break;
		}
	case 0x03:
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		/* Request PolicyPrimaryDomainInformation. */
		switch (lp_server_role()) {
			case ROLE_DOMAIN_PDC:
			case ROLE_DOMAIN_BDC:
				name = get_global_sam_name();
				sid = get_global_sam_sid();
				break;
			case ROLE_DOMAIN_MEMBER:
				name = lp_workgroup();
				/* We need to return the Domain SID here. */
				if (secrets_fetch_domain_sid(lp_workgroup(), &domain_sid))
					sid = &domain_sid;
				else
					return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
				break;
			case ROLE_STANDALONE:
				name = lp_workgroup();
				sid = NULL;
				break;
			default:
				return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		init_dom_query_3(&r_u->ctr.info.id3, name, sid);
		break;
	case 0x05:
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		/* Request PolicyAccountDomainInformation. */
		name = get_global_sam_name();
		sid = get_global_sam_sid();
		init_dom_query_5(&r_u->ctr.info.id5, name, sid);
		break;
	case 0x06:
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		switch (lp_server_role()) {
			case ROLE_DOMAIN_BDC:
				/*
				 * only a BDC is a backup controller
				 * of the domain, it controls.
				 */
				ctr->info.id6.server_role = 2;
				break;
			default:
				/*
				 * any other role is a primary
				 * of the domain, it controls.
				 */
				ctr->info.id6.server_role = 3;
				break; 
		}
		break;
	default:
		DEBUG(0,("_lsa_query_info: unknown info level in Lsa Query: %d\n", q_u->info_class));
		r_u->status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	if (NT_STATUS_IS_OK(r_u->status)) {
		r_u->dom_ptr = 0x22000000; /* bizarre */
		ctr->info_class = q_u->info_class;
	}

	return r_u->status;
}

/***************************************************************************
 _lsa_lookup_sids_internal
 ***************************************************************************/

static NTSTATUS _lsa_lookup_sids_internal(pipes_struct *p,
				uint16 level,				/* input */
				int num_sids,				/* input */
				const DOM_SID2 *sid,			/* input */
				DOM_R_REF **pp_ref,			/* output */
				LSA_TRANS_NAME_ENUM2 **pp_names,	/* output */
				uint32 *pp_mapped_count)
{
	NTSTATUS status;
	int i;
	const DOM_SID **sids = NULL;
	LSA_TRANS_NAME_ENUM2 *names = NULL;
	DOM_R_REF *ref = NULL;
	uint32 mapped_count = 0;
	struct lsa_dom_info *dom_infos = NULL;
	struct lsa_name_info *name_infos = NULL;

	*pp_mapped_count = 0;
	*pp_ref = NULL;
	*pp_names = NULL;
	
	names = TALLOC_ZERO_P(p->mem_ctx, LSA_TRANS_NAME_ENUM2);
	sids = TALLOC_ARRAY(p->mem_ctx, const DOM_SID *, num_sids);
	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);

	if (sids == NULL || names == NULL || ref == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_sids; i++) {
		sids[i] = &sid[i].sid;
	}

	status = lookup_sids(p->mem_ctx, num_sids, sids, level,
				  &dom_infos, &name_infos);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_sids > 0) {
		names->name = TALLOC_ARRAY(names, LSA_TRANS_NAME2, num_sids);
		names->uni_name = TALLOC_ARRAY(names, UNISTR2, num_sids);
		if ((names->name == NULL) || (names->uni_name == NULL)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (i=0; i<MAX_REF_DOMAINS; i++) {

		if (!dom_infos[i].valid) {
			break;
		}

		if (init_dom_ref(ref, dom_infos[i].name,
				 &dom_infos[i].sid) != i) {
			DEBUG(0, ("Domain %s mentioned twice??\n",
				  dom_infos[i].name));
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	for (i=0; i<num_sids; i++) {
		struct lsa_name_info *name = &name_infos[i];

		if (name->type == SID_NAME_UNKNOWN) {
			name->dom_idx = -1;
			/* Unknown sids should return the string
			 * representation of the SID. Windows 2003 behaves
			 * rather erratic here, in many cases it returns the
			 * RID as 8 bytes hex, in others it returns the full
			 * SID. We (Jerry/VL) could not figure out which the
			 * hard cases are, so leave it with the SID.  */
			name->name = talloc_asprintf(p->mem_ctx, "%s", 
			                             sid_string_static(sids[i]));
			if (name->name == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			mapped_count += 1;
		}
		init_lsa_trans_name2(&names->name[i], &names->uni_name[i],
				    name->type, name->name, name->dom_idx);
	}

	names->num_entries = num_sids;
	names->ptr_trans_names = 1;
	names->num_entries2 = num_sids;

	status = NT_STATUS_NONE_MAPPED;
	if (mapped_count > 0) {
		status = (mapped_count < num_sids) ?
			STATUS_SOME_UNMAPPED : NT_STATUS_OK;
	}

	DEBUG(10, ("num_sids %d, mapped_count %d, status %s\n",
		   num_sids, mapped_count, nt_errstr(status)));

	*pp_mapped_count = mapped_count;
	*pp_ref = ref;
	*pp_names = names;

	return status;
}

/***************************************************************************
 _lsa_lookup_sids
 ***************************************************************************/

NTSTATUS _lsa_lookup_sids(pipes_struct *p,
			  LSA_Q_LOOKUP_SIDS *q_u,
			  LSA_R_LOOKUP_SIDS *r_u)
{
	struct lsa_info *handle;
	int num_sids = q_u->sids.num_entries;
	uint32 mapped_count = 0;
	DOM_R_REF *ref = NULL;
	LSA_TRANS_NAME_ENUM2 *names = NULL;
	NTSTATUS status;

	if ((q_u->level < 1) || (q_u->level > 6)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* check if the user has enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (num_sids >  MAX_LOOKUP_SIDS) {
		DEBUG(5,("_lsa_lookup_sids: limit of %d exceeded, requested %d\n",
			 MAX_LOOKUP_SIDS, num_sids));
		return NT_STATUS_NONE_MAPPED;
	}

	r_u->status = _lsa_lookup_sids_internal(p,
						q_u->level,
						num_sids, 
						q_u->sids.sid,
						&ref,
						&names,
						&mapped_count);

	/* Convert from LSA_TRANS_NAME_ENUM2 to LSA_TRANS_NAME_ENUM */

	status = init_reply_lookup_sids(p->mem_ctx, r_u, ref, names, mapped_count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return r_u->status;
}

/***************************************************************************
 _lsa_lookup_sids2
 ***************************************************************************/

NTSTATUS _lsa_lookup_sids2(pipes_struct *p,
			  LSA_Q_LOOKUP_SIDS2 *q_u,
			  LSA_R_LOOKUP_SIDS2 *r_u)
{
	struct lsa_info *handle;
	int num_sids = q_u->sids.num_entries;
	uint32 mapped_count = 0;
	DOM_R_REF *ref = NULL;
	LSA_TRANS_NAME_ENUM2 *names = NULL;

	if ((q_u->level < 1) || (q_u->level > 6)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (num_sids >  MAX_LOOKUP_SIDS) {
		DEBUG(5,("_lsa_lookup_sids2: limit of %d exceeded, requested %d\n",
			 MAX_LOOKUP_SIDS, num_sids));
		return NT_STATUS_NONE_MAPPED;
	}

	r_u->status = _lsa_lookup_sids_internal(p,
						q_u->level,
						num_sids, 
						q_u->sids.sid,
						&ref,
						&names,
						&mapped_count);

	init_reply_lookup_sids2(r_u, ref, names, mapped_count);
	return r_u->status;
}

/***************************************************************************
 _lsa_lookup_sida3

 Before someone actually re-activates this, please present a sniff showing
 this call against some Windows server. I (vl) could not make it work against
 w2k3 at all.
 ***************************************************************************/

NTSTATUS _lsa_lookup_sids3(pipes_struct *p,
			  LSA_Q_LOOKUP_SIDS3 *q_u,
			  LSA_R_LOOKUP_SIDS3 *r_u)
{
	uint32 mapped_count = 0;
	DOM_R_REF *ref;
	LSA_TRANS_NAME_ENUM2 *names;

	if ((q_u->level < 1) || (q_u->level > 6)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	r_u->status = NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED;

	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);
	names = TALLOC_ZERO_P(p->mem_ctx, LSA_TRANS_NAME_ENUM2);

	if ((ref == NULL) || (names == NULL)) {
		/* We would segfault later on in lsa_io_r_lookup_sids3 anyway,
		 * so do a planned exit here. We NEEEED pidl! */
		smb_panic("talloc failed");
	}

	init_reply_lookup_sids3(r_u, ref, names, mapped_count);
	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names
 ***************************************************************************/

NTSTATUS _lsa_lookup_names(pipes_struct *p,LSA_Q_LOOKUP_NAMES *q_u, LSA_R_LOOKUP_NAMES *r_u)
{
	struct lsa_info *handle;
	UNISTR2 *names = q_u->uni_name;
	uint32 num_entries = q_u->num_entries;
	DOM_R_REF *ref;
	DOM_RID *rids;
	uint32 mapped_count = 0;
	int flags = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_names: truncating name lookup list to %d\n", num_entries));
	}
		
	/* Probably the lookup_level is some sort of bitmask. */
	if (q_u->lookup_level == 1) {
		flags = LOOKUP_NAME_ALL;
	}

	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);
	rids = TALLOC_ZERO_ARRAY(p->mem_ctx, DOM_RID, num_entries);

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle)) {
		r_u->status = NT_STATUS_INVALID_HANDLE;
		goto done;
	}

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		r_u->status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	if (!ref || !rids)
		return NT_STATUS_NO_MEMORY;

	/* set up the LSA Lookup RIDs response */
	become_root(); /* lookup_name can require root privs */
	r_u->status = lookup_lsa_rids(p->mem_ctx, ref, rids, num_entries,
				      names, flags, &mapped_count);
	unbecome_root();

done:

	if (NT_STATUS_IS_OK(r_u->status) && (num_entries != 0) ) {
		if (mapped_count == 0)
			r_u->status = NT_STATUS_NONE_MAPPED;
		else if (mapped_count != num_entries)
			r_u->status = STATUS_SOME_UNMAPPED;
	}

	init_reply_lookup_names(r_u, ref, num_entries, rids, mapped_count);
	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names2
 ***************************************************************************/

NTSTATUS _lsa_lookup_names2(pipes_struct *p, LSA_Q_LOOKUP_NAMES2 *q_u, LSA_R_LOOKUP_NAMES2 *r_u)
{
	struct lsa_info *handle;
	UNISTR2 *names = q_u->uni_name;
	uint32 num_entries = q_u->num_entries;
	DOM_R_REF *ref;
	DOM_RID *rids;
	DOM_RID2 *rids2;
	int i;
	uint32 mapped_count = 0;
	int flags = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_names2: truncating name lookup list to %d\n", num_entries));
	}
		
	/* Probably the lookup_level is some sort of bitmask. */
	if (q_u->lookup_level == 1) {
		flags = LOOKUP_NAME_ALL;
	}

	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);
	rids = TALLOC_ZERO_ARRAY(p->mem_ctx, DOM_RID, num_entries);
	rids2 = TALLOC_ZERO_ARRAY(p->mem_ctx, DOM_RID2, num_entries);

	if ((ref == NULL) || (rids == NULL) || (rids2 == NULL)) {
		r_u->status = NT_STATUS_NO_MEMORY;
		return NT_STATUS_NO_MEMORY;
	}

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle)) {
		r_u->status = NT_STATUS_INVALID_HANDLE;
		goto done;
	}

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		r_u->status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* set up the LSA Lookup RIDs response */
	become_root(); /* lookup_name can require root privs */
	r_u->status = lookup_lsa_rids(p->mem_ctx, ref, rids, num_entries,
				      names, flags, &mapped_count);
	unbecome_root();

done:

	if (NT_STATUS_IS_OK(r_u->status)) {
		if (mapped_count == 0) {
			r_u->status = NT_STATUS_NONE_MAPPED;
		} else if (mapped_count != num_entries) {
			r_u->status = STATUS_SOME_UNMAPPED;
		}
	}

	/* Convert the rids array to rids2. */
	for (i = 0; i < num_entries; i++) {
		rids2[i].type = rids[i].type;
		rids2[i].rid = rids[i].rid;
		rids2[i].rid_idx = rids[i].rid_idx;
		rids2[i].unknown = 0;
	}

	init_reply_lookup_names2(r_u, ref, num_entries, rids2, mapped_count);
	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names3.
 ***************************************************************************/

NTSTATUS _lsa_lookup_names3(pipes_struct *p, LSA_Q_LOOKUP_NAMES3 *q_u, LSA_R_LOOKUP_NAMES3 *r_u)
{
	struct lsa_info *handle;
	UNISTR2 *names = q_u->uni_name;
	uint32 num_entries = q_u->num_entries;
	DOM_R_REF *ref = NULL;
	LSA_TRANSLATED_SID3 *trans_sids = NULL;
	uint32 mapped_count = 0;
	int flags = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_names3: truncating name lookup list to %d\n", num_entries));
	}
		
	/* Probably the lookup_level is some sort of bitmask. */
	if (q_u->lookup_level == 1) {
		flags = LOOKUP_NAME_ALL;
	}

	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);
	trans_sids = TALLOC_ZERO_ARRAY(p->mem_ctx, LSA_TRANSLATED_SID3, num_entries);

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle)) {
		r_u->status = NT_STATUS_INVALID_HANDLE;
		goto done;
	}

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		r_u->status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	if (!ref || !trans_sids) {
		return NT_STATUS_NO_MEMORY;
	}

	/* set up the LSA Lookup SIDs response */
	become_root(); /* lookup_name can require root privs */
	r_u->status = lookup_lsa_sids(p->mem_ctx, ref, trans_sids, num_entries,
				      names, flags, &mapped_count);
	unbecome_root();

done:

	if (NT_STATUS_IS_OK(r_u->status)) {
		if (mapped_count == 0) {
			r_u->status = NT_STATUS_NONE_MAPPED;
		} else if (mapped_count != num_entries) {
			r_u->status = STATUS_SOME_UNMAPPED;
		}
	}

	init_reply_lookup_names3(r_u, ref, num_entries, trans_sids, mapped_count);
	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names4.
 ***************************************************************************/

NTSTATUS _lsa_lookup_names4(pipes_struct *p, LSA_Q_LOOKUP_NAMES4 *q_u, LSA_R_LOOKUP_NAMES4 *r_u)
{
	UNISTR2 *names = q_u->uni_name;
	uint32 num_entries = q_u->num_entries;
	DOM_R_REF *ref = NULL;
	LSA_TRANSLATED_SID3 *trans_sids = NULL;
	uint32 mapped_count = 0;
	int flags = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_names4: truncating name lookup list to %d\n", num_entries));
	}
		
	/* Probably the lookup_level is some sort of bitmask. */
	if (q_u->lookup_level == 1) {
		flags = LOOKUP_NAME_ALL;
	}

	/* No policy handle on this call. Restrict to crypto connections. */
	if (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) {
		DEBUG(0,("_lsa_lookup_names4: client %s not using schannel for netlogon\n",
			get_remote_machine_name() ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	ref = TALLOC_ZERO_P(p->mem_ctx, DOM_R_REF);
	trans_sids = TALLOC_ZERO_ARRAY(p->mem_ctx, LSA_TRANSLATED_SID3, num_entries);

	if (!ref || !trans_sids) {
		return NT_STATUS_NO_MEMORY;
	}

	/* set up the LSA Lookup SIDs response */
	become_root(); /* lookup_name can require root privs */
	r_u->status = lookup_lsa_sids(p->mem_ctx, ref, trans_sids, num_entries,
				      names, flags, &mapped_count);
	unbecome_root();

	if (NT_STATUS_IS_OK(r_u->status)) {
		if (mapped_count == 0) {
			r_u->status = NT_STATUS_NONE_MAPPED;
		} else if (mapped_count != num_entries) {
			r_u->status = STATUS_SOME_UNMAPPED;
		}
	}

	init_reply_lookup_names4(r_u, ref, num_entries, trans_sids, mapped_count);
	return r_u->status;
}

/***************************************************************************
 _lsa_close. Also weird - needs to check if lsa handle is correct. JRA.
 ***************************************************************************/

NTSTATUS _lsa_Close(pipes_struct *p, struct policy_handle *handle)
{
	if (!find_policy_by_hnd(p, handle, NULL)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	close_policy_hnd(p, handle);
	return NT_STATUS_OK;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_OpenSecret(pipes_struct *p, struct policy_handle *handle,
			 struct lsa_String name, uint32_t access_mask,
			 struct policy_handle *sec_handle)
{
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_OpenTrustedDomain(pipes_struct *p, struct policy_handle *handle,
				struct dom_sid2 *sid, uint32_t access_mask,
				struct policy_handle *trustdom_handle)
{
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_CreateTrustedDomain(pipes_struct *p,
				  struct policy_handle *handle,
				  struct lsa_DomainInfo *info,
				  uint32_t access_mask,
				  struct policy_handle *trustdom_handle)
{
	return NT_STATUS_ACCESS_DENIED;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_CreateSecret(pipes_struct *p, struct policy_handle *handle,
			   struct lsa_String name, uint32_t access_mask,
			   struct policy_handle *sec_handle)
{
	return NT_STATUS_ACCESS_DENIED;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_SetSecret(pipes_struct *p, struct policy_handle *sec_handle,
			struct lsa_DATA_BUF *new_val,
			struct lsa_DATA_BUF *old_val)
{
	return NT_STATUS_ACCESS_DENIED;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_delete_object(pipes_struct *p, LSA_Q_DELETE_OBJECT *q_u, LSA_R_DELETE_OBJECT *r_u)
{
	return NT_STATUS_ACCESS_DENIED;
}

/***************************************************************************
_lsa_enum_privs.
 ***************************************************************************/

NTSTATUS _lsa_enum_privs(pipes_struct *p, LSA_Q_ENUM_PRIVS *q_u, LSA_R_ENUM_PRIVS *r_u)
{
	struct lsa_info *handle;
	uint32 i;
	uint32 enum_context = q_u->enum_context;
	int num_privs = count_all_privileges();
	LSA_PRIV_ENTRY *entries = NULL;
	LUID_ATTR luid;

	/* remember that the enum_context starts at 0 and not 1 */

	if ( enum_context >= num_privs )
		return NT_STATUS_NO_MORE_ENTRIES;
		
	DEBUG(10,("_lsa_enum_privs: enum_context:%d total entries:%d\n", 
		enum_context, num_privs));
	
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights
	   I don't know if it's the right one. not documented.  */

	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	if ( !(entries = TALLOC_ZERO_ARRAY(p->mem_ctx, LSA_PRIV_ENTRY, num_privs )) )
		return NT_STATUS_NO_MEMORY;

	for (i = 0; i < num_privs; i++) {
		if( i < enum_context) {
			init_unistr2(&entries[i].name, NULL, UNI_FLAGS_NONE);
			init_uni_hdr(&entries[i].hdr_name, &entries[i].name);
			
			entries[i].luid_low = 0;
			entries[i].luid_high = 0;
		} else {
			init_unistr2(&entries[i].name, privs[i].name, UNI_FLAGS_NONE);
			init_uni_hdr(&entries[i].hdr_name, &entries[i].name);
			
			luid = get_privilege_luid( &privs[i].se_priv );
			
			entries[i].luid_low = luid.luid.low;
			entries[i].luid_high = luid.luid.high;
		}
	}

	enum_context = num_privs;
	
	init_lsa_r_enum_privs(r_u, enum_context, num_privs, entries);

	return NT_STATUS_OK;
}

/***************************************************************************
_lsa_priv_get_dispname.
 ***************************************************************************/

NTSTATUS _lsa_priv_get_dispname(pipes_struct *p, LSA_Q_PRIV_GET_DISPNAME *q_u, LSA_R_PRIV_GET_DISPNAME *r_u)
{
	struct lsa_info *handle;
	fstring name_asc;
	const char *description;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 */
	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	unistr2_to_ascii(name_asc, &q_u->name, sizeof(name_asc));

	DEBUG(10,("_lsa_priv_get_dispname: name = %s\n", name_asc));

	description = get_privilege_dispname( name_asc );
	
	if ( description ) {
		DEBUG(10,("_lsa_priv_get_dispname: display name = %s\n", description));
		
		init_unistr2(&r_u->desc, description, UNI_FLAGS_NONE);
		init_uni_hdr(&r_u->hdr_desc, &r_u->desc);

		r_u->ptr_info = 0xdeadbeef;
		r_u->lang_id = q_u->lang_id;
		
		return NT_STATUS_OK;
	} else {
		DEBUG(10,("_lsa_priv_get_dispname: doesn't exist\n"));
		
		r_u->ptr_info = 0;
		
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}
}

/***************************************************************************
_lsa_enum_accounts.
 ***************************************************************************/

NTSTATUS _lsa_enum_accounts(pipes_struct *p, LSA_Q_ENUM_ACCOUNTS *q_u, LSA_R_ENUM_ACCOUNTS *r_u)
{
	struct lsa_info *handle;
	DOM_SID *sid_list;
	int i, j, num_entries;
	LSA_SID_ENUM *sids=&r_u->sids;
	NTSTATUS ret;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	sid_list = NULL;
	num_entries = 0;

	/* The only way we can currently find out all the SIDs that have been
	   privileged is to scan all privileges */

	if (!NT_STATUS_IS_OK(ret = privilege_enumerate_accounts(&sid_list, &num_entries))) {
		return ret;
	}

	if (q_u->enum_context >= num_entries)
		return NT_STATUS_NO_MORE_ENTRIES;

	sids->ptr_sid = TALLOC_ZERO_ARRAY(p->mem_ctx, uint32, num_entries-q_u->enum_context);
	sids->sid = TALLOC_ZERO_ARRAY(p->mem_ctx, DOM_SID2, num_entries-q_u->enum_context);

	if (sids->ptr_sid==NULL || sids->sid==NULL) {
		SAFE_FREE(sid_list);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = q_u->enum_context, j = 0; i < num_entries; i++, j++) {
		init_dom_sid2(&(*sids).sid[j], &sid_list[i]);
		(*sids).ptr_sid[j] = 1;
	}

	SAFE_FREE(sid_list);

	init_lsa_r_enum_accounts(r_u, num_entries);

	return NT_STATUS_OK;
}


NTSTATUS _lsa_unk_get_connuser(pipes_struct *p, LSA_Q_UNK_GET_CONNUSER *q_u, LSA_R_UNK_GET_CONNUSER *r_u)
{
	const char *username, *domname;
	user_struct *vuser = get_valid_user_struct(p->vuid);
  
	if (vuser == NULL)
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;

	if (vuser->guest) {
		/*
		 * I'm 99% sure this is not the right place to do this,
		 * global_sid_Anonymous should probably be put into the token
		 * instead of the guest id -- vl
		 */
		if (!lookup_sid(p->mem_ctx, &global_sid_Anonymous,
				&domname, &username, NULL)) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		username = vuser->user.smb_name;
		domname = vuser->user.domain;
	}
  
	r_u->ptr_user_name = 1;
	init_unistr2(&r_u->uni2_user_name, username, UNI_STR_TERMINATE);
	init_uni_hdr(&r_u->hdr_user_name, &r_u->uni2_user_name);

	r_u->unk1 = 1;
  
	r_u->ptr_dom_name = 1;
	init_unistr2(&r_u->uni2_dom_name, domname,  UNI_STR_TERMINATE);
	init_uni_hdr(&r_u->hdr_dom_name, &r_u->uni2_dom_name);

	r_u->status = NT_STATUS_OK;
  
	return r_u->status;
}

/***************************************************************************
 Lsa Create Account 
 ***************************************************************************/

NTSTATUS _lsa_create_account(pipes_struct *p, LSA_Q_CREATEACCOUNT *q_u, LSA_R_CREATEACCOUNT *r_u)
{
	struct lsa_info *handle;
	struct lsa_info *info;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 * but guessed with rpcclient.
	 */
	if (!(handle->access & POLICY_GET_PRIVATE_INFORMATION)) {
		DEBUG(10, ("_lsa_create_account: No POLICY_GET_PRIVATE_INFORMATION access right!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* check to see if the pipe_user is a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) ) {
		DEBUG(10, ("_lsa_create_account: The use is not a Domain Admin, deny access!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}
		
	if ( is_privileged_sid( &q_u->sid.sid ) ) {
		DEBUG(10, ("_lsa_create_account: Policy account already exists!\n"));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/* associate the user/group SID with the (unique) handle. */
	
	if ((info = SMB_MALLOC_P(struct lsa_info)) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	info->sid = q_u->sid.sid;
	info->access = q_u->access;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->pol, free_lsa_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(10, ("_lsa_create_account: call privileges code to create an account\n"));
	return privilege_create_account( &info->sid );
}


/***************************************************************************
 Lsa Open Account
 ***************************************************************************/

NTSTATUS _lsa_open_account(pipes_struct *p, LSA_Q_OPENACCOUNT *q_u, LSA_R_OPENACCOUNT *r_u)
{
	struct lsa_info *handle;
	struct lsa_info *info;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 * but guessed with rpcclient.
	 */
	if (!(handle->access & POLICY_GET_PRIVATE_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	/* TODO: Fis the parsing routine before reenabling this check! */
	#if 0
	if (!lookup_sid(&handle->sid, dom_name, name, &type))
		return NT_STATUS_ACCESS_DENIED;
	#endif
	/* associate the user/group SID with the (unique) handle. */
	if ((info = SMB_MALLOC_P(struct lsa_info)) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	info->sid = q_u->sid.sid;
	info->access = q_u->access;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->pol, free_lsa_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/***************************************************************************
 For a given SID, enumerate all the privilege this account has.
 ***************************************************************************/

NTSTATUS _lsa_enum_privsaccount(pipes_struct *p, prs_struct *ps, LSA_Q_ENUMPRIVSACCOUNT *q_u, LSA_R_ENUMPRIVSACCOUNT *r_u)
{
	struct lsa_info *info=NULL;
	SE_PRIV mask;
	PRIVILEGE_SET privileges;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	if ( !get_privileges_for_sids( &mask, &info->sid, 1 ) ) 
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	privilege_set_init( &privileges );

	if ( se_priv_to_privilege_set( &privileges, &mask ) ) {

		DEBUG(10,("_lsa_enum_privsaccount: %s has %d privileges\n", 
			sid_string_static(&info->sid), privileges.count));

		r_u->status = init_lsa_r_enum_privsaccount(ps->mem_ctx, r_u, privileges.set, privileges.count, 0);
	}
	else
		r_u->status = NT_STATUS_NO_SUCH_PRIVILEGE;

	privilege_set_free( &privileges );

	return r_u->status;
}

/***************************************************************************
 
 ***************************************************************************/

NTSTATUS _lsa_getsystemaccount(pipes_struct *p, LSA_Q_GETSYSTEMACCOUNT *q_u, LSA_R_GETSYSTEMACCOUNT *r_u)
{
	struct lsa_info *info=NULL;

	/* find the connection policy handle. */

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!lookup_sid(p->mem_ctx, &info->sid, NULL, NULL, NULL))
		return NT_STATUS_OK;

	/*
	  0x01 -> Log on locally
	  0x02 -> Access this computer from network
	  0x04 -> Log on as a batch job
	  0x10 -> Log on as a service
	  
	  they can be ORed together
	*/

	r_u->access = PR_LOG_ON_LOCALLY | PR_ACCESS_FROM_NETWORK;

	return NT_STATUS_OK;
}

/***************************************************************************
  update the systemaccount information
 ***************************************************************************/

NTSTATUS _lsa_setsystemaccount(pipes_struct *p, LSA_Q_SETSYSTEMACCOUNT *q_u, LSA_R_SETSYSTEMACCOUNT *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* check to see if the pipe_user is a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) )
		return NT_STATUS_ACCESS_DENIED;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

	return pdb_update_group_mapping_entry(&map);
}

/***************************************************************************
 For a given SID, add some privileges.
 ***************************************************************************/

NTSTATUS _lsa_addprivs(pipes_struct *p, LSA_Q_ADDPRIVS *q_u, LSA_R_ADDPRIVS *r_u)
{
	struct lsa_info *info = NULL;
	SE_PRIV mask;
	PRIVILEGE_SET *set = NULL;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	/* check to see if the pipe_user is root or a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( p->pipe_user.ut.uid != sec_initial_uid() 
		&& !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) )
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	set = &q_u->set;

	if ( !privilege_set_to_se_priv( &mask, set ) )
		return NT_STATUS_NO_SUCH_PRIVILEGE;

	if ( !grant_privilege( &info->sid, &mask ) ) {
		DEBUG(3,("_lsa_addprivs: grant_privilege(%s) failed!\n",
			sid_string_static(&info->sid) ));
		DEBUG(3,("Privilege mask:\n"));
		dump_se_priv( DBGC_ALL, 3, &mask );
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	return NT_STATUS_OK;
}

/***************************************************************************
 For a given SID, remove some privileges.
 ***************************************************************************/

NTSTATUS _lsa_removeprivs(pipes_struct *p, LSA_Q_REMOVEPRIVS *q_u, LSA_R_REMOVEPRIVS *r_u)
{
	struct lsa_info *info = NULL;
	SE_PRIV mask;
	PRIVILEGE_SET *set = NULL;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* check to see if the pipe_user is root or a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( p->pipe_user.ut.uid != sec_initial_uid()
		&& !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) ) 
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	set = &q_u->set;

	if ( !privilege_set_to_se_priv( &mask, set ) )
		return NT_STATUS_NO_SUCH_PRIVILEGE;

	if ( !revoke_privilege( &info->sid, &mask ) ) {
		DEBUG(3,("_lsa_removeprivs: revoke_privilege(%s) failed!\n",
			sid_string_static(&info->sid) ));
		DEBUG(3,("Privilege mask:\n"));
		dump_se_priv( DBGC_ALL, 3, &mask );
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	return NT_STATUS_OK;
}

/***************************************************************************
 For a given SID, remove some privileges.
 ***************************************************************************/

NTSTATUS _lsa_query_secobj(pipes_struct *p, LSA_Q_QUERY_SEC_OBJ *q_u, LSA_R_QUERY_SEC_OBJ *r_u)
{
	struct lsa_info *handle=NULL;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	NTSTATUS status;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;


	switch (q_u->sec_info) {
	case 1:
		/* SD contains only the owner */

		status=lsa_get_generic_sd(p->mem_ctx, &psd, &sd_size);
		if(!NT_STATUS_IS_OK(status))
			return NT_STATUS_NO_MEMORY;


		if((r_u->buf = make_sec_desc_buf(p->mem_ctx, sd_size, psd)) == NULL)
			return NT_STATUS_NO_MEMORY;
		break;
	case 4:
		/* SD contains only the ACL */

		status=lsa_get_generic_sd(p->mem_ctx, &psd, &sd_size);
		if(!NT_STATUS_IS_OK(status))
			return NT_STATUS_NO_MEMORY;

		if((r_u->buf = make_sec_desc_buf(p->mem_ctx, sd_size, psd)) == NULL)
			return NT_STATUS_NO_MEMORY;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	r_u->ptr=1;

	return r_u->status;
}

#if 0 	/* AD DC work in ongoing in Samba 4 */

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_query_info2(pipes_struct *p, LSA_Q_QUERY_INFO2 *q_u, LSA_R_QUERY_INFO2 *r_u)
{
	struct lsa_info *handle;
	const char *nb_name;
	char *dns_name = NULL;
	char *forest_name = NULL;
	DOM_SID *sid = NULL;
	struct GUID guid;
	fstring dnsdomname;

	ZERO_STRUCT(guid);
	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&handle))
		return NT_STATUS_INVALID_HANDLE;

	switch (q_u->info_class) {
	case 0x0c:
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		/* Request PolicyPrimaryDomainInformation. */
		switch (lp_server_role()) {
			case ROLE_DOMAIN_PDC:
			case ROLE_DOMAIN_BDC:
				nb_name = get_global_sam_name();
				/* ugly temp hack for these next two */

				/* This should be a 'netbios domain -> DNS domain' mapping */
				dnsdomname[0] = '\0';
				get_mydnsdomname(dnsdomname);
				strlower_m(dnsdomname);
				
				dns_name = dnsdomname;
				forest_name = dnsdomname;

				sid = get_global_sam_sid();
				secrets_fetch_domain_guid(lp_workgroup(), &guid);
				break;
			default:
				return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		init_dns_dom_info(&r_u->info.dns_dom_info, nb_name, dns_name, 
				  forest_name,&guid,sid);
		break;
	default:
		DEBUG(0,("_lsa_query_info2: unknown info level in Lsa Query: %d\n", q_u->info_class));
		r_u->status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	if (NT_STATUS_IS_OK(r_u->status)) {
		r_u->ptr = 0x1;
		r_u->info_class = q_u->info_class;
	}

	return r_u->status;
}
#endif	/* AD DC work in ongoing in Samba 4 */

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_add_acct_rights(pipes_struct *p, LSA_Q_ADD_ACCT_RIGHTS *q_u, LSA_R_ADD_ACCT_RIGHTS *r_u)
{
	struct lsa_info *info = NULL;
	int i = 0;
	DOM_SID sid;
	fstring privname;
	UNISTR4_ARRAY *uni_privnames = q_u->rights;
	

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	/* check to see if the pipe_user is a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( p->pipe_user.ut.uid != sec_initial_uid()
		&& !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) ) 
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* according to an NT4 PDC, you can add privileges to SIDs even without
	   call_lsa_create_account() first.  And you can use any arbitrary SID. */
	   
	sid_copy( &sid, &q_u->sid.sid );
	
	/* just a little sanity check */
	
	if ( q_u->count != uni_privnames->count ) {
		DEBUG(0,("_lsa_add_acct_rights: count != number of UNISTR2 elements!\n"));
		return NT_STATUS_INVALID_HANDLE;	
	}
		
	for ( i=0; i<q_u->count; i++ ) {
		UNISTR4 *uni4_str = &uni_privnames->strings[i];

		/* only try to add non-null strings */

		if ( !uni4_str->string )
			continue;

		rpcstr_pull( privname, uni4_str->string->buffer, sizeof(privname), -1, STR_TERMINATE );
		
		if ( !grant_privilege_by_name( &sid, privname ) ) {
			DEBUG(2,("_lsa_add_acct_rights: Failed to add privilege [%s]\n", privname ));
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return NT_STATUS_OK;
}

/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_remove_acct_rights(pipes_struct *p, LSA_Q_REMOVE_ACCT_RIGHTS *q_u, LSA_R_REMOVE_ACCT_RIGHTS *r_u)
{
	struct lsa_info *info = NULL;
	int i = 0;
	DOM_SID sid;
	fstring privname;
	UNISTR4_ARRAY *uni_privnames = q_u->rights;
	

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	/* check to see if the pipe_user is a Domain Admin since 
	   account_pol.tdb was already opened as root, this is all we have */
	   
	if ( p->pipe_user.ut.uid != sec_initial_uid()
		&& !nt_token_check_domain_rid( p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS ) )
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	sid_copy( &sid, &q_u->sid.sid );

	if ( q_u->removeall ) {
		if ( !revoke_all_privileges( &sid ) ) 
			return NT_STATUS_ACCESS_DENIED;
	
		return NT_STATUS_OK;
	}
	
	/* just a little sanity check */
	
	if ( q_u->count != uni_privnames->count ) {
		DEBUG(0,("_lsa_add_acct_rights: count != number of UNISTR2 elements!\n"));
		return NT_STATUS_INVALID_HANDLE;	
	}
		
	for ( i=0; i<q_u->count; i++ ) {
		UNISTR4 *uni4_str = &uni_privnames->strings[i];

		/* only try to add non-null strings */

		if ( !uni4_str->string )
			continue;

		rpcstr_pull( privname, uni4_str->string->buffer, sizeof(privname), -1, STR_TERMINATE );
		
		if ( !revoke_privilege_by_name( &sid, privname ) ) {
			DEBUG(2,("_lsa_remove_acct_rights: Failed to revoke privilege [%s]\n", privname ));
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return NT_STATUS_OK;
}


/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_enum_acct_rights(pipes_struct *p, LSA_Q_ENUM_ACCT_RIGHTS *q_u, LSA_R_ENUM_ACCT_RIGHTS *r_u)
{
	struct lsa_info *info = NULL;
	DOM_SID sid;
	PRIVILEGE_SET privileges;
	SE_PRIV mask;
	

	/* find the connection policy handle. */
	
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	/* according to an NT4 PDC, you can add privileges to SIDs even without
	   call_lsa_create_account() first.  And you can use any arbitrary SID. */
	   
	sid_copy( &sid, &q_u->sid.sid );
	
	if ( !get_privileges_for_sids( &mask, &sid, 1 ) )
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	privilege_set_init( &privileges );

	if ( se_priv_to_privilege_set( &privileges, &mask ) ) {

		DEBUG(10,("_lsa_enum_acct_rights: %s has %d privileges\n", 
			sid_string_static(&sid), privileges.count));

		r_u->status = init_r_enum_acct_rights( r_u, &privileges );
	}
	else 
		r_u->status = NT_STATUS_NO_SUCH_PRIVILEGE;

	privilege_set_free( &privileges );

	return r_u->status;
}


/***************************************************************************
 ***************************************************************************/

NTSTATUS _lsa_lookup_priv_value(pipes_struct *p, LSA_Q_LOOKUP_PRIV_VALUE *q_u, LSA_R_LOOKUP_PRIV_VALUE *r_u)
{
	struct lsa_info *info = NULL;
	fstring name;
	LUID_ATTR priv_luid;
	SE_PRIV mask;
	
	/* find the connection policy handle. */
	
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	unistr2_to_ascii(name, &q_u->privname.unistring, sizeof(name));
	
	DEBUG(10,("_lsa_lookup_priv_value: name = %s\n", name));

	if ( !se_priv_from_name( name, &mask ) )
		return NT_STATUS_NO_SUCH_PRIVILEGE;

	priv_luid = get_privilege_luid( &mask );

	r_u->luid.low  = priv_luid.luid.low;
	r_u->luid.high = priv_luid.luid.high;
		

	return NT_STATUS_OK;
}


/*
 * From here on the server routines are just dummy ones to make smbd link with
 * librpc/gen_ndr/srv_lsa.c. These routines are actually never called, we are
 * pulling the server stubs across one by one.
 */ 

NTSTATUS _lsa_Delete(pipes_struct *p, struct policy_handle *handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumPrivs(pipes_struct *p, struct policy_handle *handle, uint32_t *resume_handle, uint32_t max_count, struct lsa_PrivArray *_privs)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QuerySecurity(pipes_struct *p, struct policy_handle *handle, uint32_t sec_info, struct sec_desc_buf *sdbuf)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetSecObj(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_ChangePassword(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_OpenPolicy(pipes_struct *p, uint16_t *system_name, struct lsa_ObjectAttribute *attr, uint32_t access_mask, struct policy_handle *handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryInfoPolicy(pipes_struct *p, struct policy_handle *handle, uint16_t level, union lsa_PolicyInformation *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetInfoPolicy(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_ClearAuditLog(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CreateAccount(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *sid, uint32_t access_mask, struct policy_handle *acct_handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumAccounts(pipes_struct *p, struct policy_handle *handle, uint32_t *resume_handle, uint32_t num_entries, struct lsa_SidArray *sids)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumTrustDom(pipes_struct *p, struct policy_handle *handle, uint32_t *resume_handle, uint32_t max_size, struct lsa_DomainList *domains)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupNames(pipes_struct *p, struct policy_handle *handle, uint32_t num_names, struct lsa_String *names, struct lsa_RefDomainList *domains, struct lsa_TransSidArray *sids, uint16_t level, uint32_t *count)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupSids(pipes_struct *p, struct policy_handle *handle, struct lsa_SidArray *sids, struct lsa_RefDomainList *domains, struct lsa_TransNameArray *names, uint16_t level, uint32_t *count)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_OpenAccount(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *sid, uint32_t access_mask, struct policy_handle *acct_handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumPrivsAccount(pipes_struct *p, struct policy_handle *handle, struct lsa_PrivilegeSet *_privs)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_AddPrivilegesToAccount(pipes_struct *p, struct policy_handle *handle, struct lsa_PrivilegeSet *_privs)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_RemovePrivilegesFromAccount(pipes_struct *p, struct policy_handle *handle, uint8_t remove_all, struct lsa_PrivilegeSet *_privs)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_GetQuotasForAccount(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetQuotasForAccount(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_GetSystemAccessAccount(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetSystemAccessAccount(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryTrustedDomainInfo(pipes_struct *p, struct policy_handle *trustdom_handle, enum lsa_TrustDomInfoEnum level, union lsa_TrustedDomainInfo *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetInformationTrustedDomain(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QuerySecret(pipes_struct *p, struct policy_handle *sec_handle, struct lsa_DATA_BUF_PTR *new_val, NTTIME *new_mtime, struct lsa_DATA_BUF_PTR *old_val, NTTIME *old_mtime)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupPrivValue(pipes_struct *p, struct policy_handle *handle, struct lsa_String *name, struct lsa_LUID *luid)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupPrivName(pipes_struct *p, struct policy_handle *handle, struct lsa_LUID *luid, struct lsa_StringLarge *name)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupPrivDisplayName(pipes_struct *p, struct policy_handle *handle, struct lsa_String *name, struct lsa_StringLarge *disp_name, uint16_t *language_id, uint16_t unknown)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_DeleteObject(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumAccountsWithUserRight(pipes_struct *p, struct policy_handle *handle, struct lsa_String *name, struct lsa_SidArray *sids)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumAccountRights(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *sid, struct lsa_RightSet *rights)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_AddAccountRights(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *sid, struct lsa_RightSet *rights)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_RemoveAccountRights(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *sid, uint32_t unknown, struct lsa_RightSet *rights)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryTrustedDomainInfoBySid(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *dom_sid, enum lsa_TrustDomInfoEnum level, union lsa_TrustedDomainInfo *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetTrustedDomainInfo(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_DeleteTrustedDomain(pipes_struct *p, struct policy_handle *handle, struct dom_sid2 *dom_sid)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_StorePrivateData(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_RetrievePrivateData(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_OpenPolicy2(pipes_struct *p, const char *system_name, struct lsa_ObjectAttribute *attr, uint32_t access_mask, struct policy_handle *handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_GetUserName(pipes_struct *p, const char *system_name, struct lsa_String *account_name, struct lsa_StringPointer *authority_name)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryInfoPolicy2(pipes_struct *p, struct policy_handle *handle, uint16_t level, union lsa_PolicyInformation *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetInfoPolicy2(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryTrustedDomainInfoByName(pipes_struct *p, struct policy_handle *handle, struct lsa_String trusted_domain, enum lsa_TrustDomInfoEnum level, union lsa_TrustedDomainInfo *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetTrustedDomainInfoByName(pipes_struct *p, struct policy_handle *handle, struct lsa_String trusted_domain, enum lsa_TrustDomInfoEnum level, union lsa_TrustedDomainInfo *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_EnumTrustedDomainsEx(pipes_struct *p, struct policy_handle *handle, uint32_t *resume_handle, struct lsa_DomainListEx *domains, uint32_t max_size)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CreateTrustedDomainEx(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CloseTrustedDomainEx(pipes_struct *p, struct policy_handle *handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_QueryDomainInformationPolicy(pipes_struct *p, struct policy_handle *handle, uint16_t level, union lsa_DomainInformationPolicy *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_SetDomainInformationPolicy(pipes_struct *p, struct policy_handle *handle, uint16_t level, union lsa_DomainInformationPolicy *info)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_OpenTrustedDomainByName(pipes_struct *p, struct policy_handle *handle, struct lsa_String name, uint32_t access_mask, struct policy_handle *trustdom_handle)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_TestCall(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupSids2(pipes_struct *p, struct policy_handle *handle, struct lsa_SidArray *sids, struct lsa_RefDomainList *domains, struct lsa_TransNameArray2 *names, uint16_t level, uint32_t *count, uint32_t unknown1, uint32_t unknown2)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupNames2(pipes_struct *p, struct policy_handle *handle, uint32_t num_names, struct lsa_String *names, struct lsa_RefDomainList *domains, struct lsa_TransSidArray2 *sids, uint16_t level, uint32_t *count, uint32_t unknown1, uint32_t unknown2)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CreateTrustedDomainEx2(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRWRITE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRREAD(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRENUMERATE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRWRITEDOMAINCREDENTIALS(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRREADDOMAINCREDENTIALS(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRDELETE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRGETTARGETINFO(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRPROFILELOADED(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupNames3(pipes_struct *p, struct policy_handle *handle, uint32_t num_names, struct lsa_String *names, struct lsa_RefDomainList *domains, struct lsa_TransSidArray3 *sids, uint16_t level, uint32_t *count, uint32_t unknown1, uint32_t unknown2)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRGETSESSIONTYPES(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARREGISTERAUDITEVENT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARGENAUDITEVENT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARUNREGISTERAUDITEVENT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARQUERYFORESTTRUSTINFORMATION(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARSETFORESTTRUSTINFORMATION(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_CREDRRENAME(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupSids3(pipes_struct *p, struct lsa_SidArray *sids, struct lsa_RefDomainList *domains, struct lsa_TransNameArray2 *names, uint16_t level, uint32_t *count, uint32_t unknown1, uint32_t unknown2)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LookupNames4(pipes_struct *p, uint32_t num_names, struct lsa_String *names, struct lsa_RefDomainList *domains, struct lsa_TransSidArray3 *sids, uint16_t level, uint32_t *count, uint32_t unknown1, uint32_t unknown2)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSAROPENPOLICYSCE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARADTREGISTERSECURITYEVENTSOURCE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _lsa_LSARADTREPORTSECURITYEVENT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}
