/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jeremy Allison                    2001,
 *  Copyright (C) Rafal Szczesniak                  2002,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002,
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

static void init_dom_query(DOM_QUERY *d_q, const char *dom_name, DOM_SID *dom_sid)
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
 init_dom_ref - adds a domain if it's not already in, returns the index.
***************************************************************************/

static int init_dom_ref(DOM_R_REF *ref, char *dom_name, DOM_SID *dom_sid)
{
	int num = 0;

	if (dom_name != NULL) {
		for (num = 0; num < ref->num_ref_doms_1; num++) {
			fstring domname;
			rpcstr_pull(domname, &ref->ref_dom[num].uni_dom_name, sizeof(domname), -1, 0);
			if (strequal(domname, dom_name))
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

	ref->hdr_ref_dom[num].ptr_dom_sid = dom_sid != NULL ? 1 : 0;

	init_unistr2(&ref->ref_dom[num].uni_dom_name, dom_name, UNI_FLAGS_NONE);
	init_uni_hdr(&ref->hdr_ref_dom[num].hdr_dom_name, &ref->ref_dom[num].uni_dom_name);

	init_dom_sid2(&ref->ref_dom[num].ref_dom, dom_sid );

	return num;
}

/***************************************************************************
 init_lsa_rid2s
 ***************************************************************************/

static void init_lsa_rid2s(DOM_R_REF *ref, DOM_RID2 *rid2,
				int num_entries, UNISTR2 *name,
				uint32 *mapped_count, BOOL endian)
{
	int i;
	int total = 0;
	*mapped_count = 0;

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	become_root(); /* lookup_name can require root privs */

	for (i = 0; i < num_entries; i++) {
		BOOL status = False;
		DOM_SID sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		pstring full_name;
		fstring dom_name, user;
		enum SID_NAME_USE name_type = SID_NAME_UNKNOWN;

		/* Split name into domain and user component */

		unistr2_to_ascii(full_name, &name[i], sizeof(full_name));
		split_domain_name(full_name, dom_name, user);

		/* Lookup name */

		DEBUG(5, ("init_lsa_rid2s: looking up name %s\n", full_name));

		status = lookup_name(dom_name, user, &sid, &name_type);

		if((name_type == SID_NAME_UNKNOWN) && (lp_server_role() == ROLE_DOMAIN_MEMBER)  && (strncmp(dom_name, full_name, strlen(dom_name)) != 0)) {
			DEBUG(5, ("init_lsa_rid2s: domain name not provided and local account not found, using member domain\n"));
			fstrcpy(dom_name, lp_workgroup());
			status = lookup_name(dom_name, user, &sid, &name_type);
		}

		if (name_type == SID_NAME_WKN_GRP) {
			/* BUILTIN aliases are still aliases :-) */
			name_type = SID_NAME_ALIAS;
		}

		DEBUG(5, ("init_lsa_rid2s: %s\n", status ? "found" : 
			  "not found"));

		if (status && name_type != SID_NAME_UNKNOWN) {
			sid_split_rid(&sid, &rid);
			dom_idx = init_dom_ref(ref, dom_name, &sid);
			(*mapped_count)++;
		} else {
			dom_idx = -1;
			rid = 0;
			name_type = SID_NAME_UNKNOWN;
		}

		init_dom_rid2(&rid2[total], rid, name_type, dom_idx);
		total++;
	}

	unbecome_root();
}

/***************************************************************************
 init_reply_lookup_names
 ***************************************************************************/

static void init_reply_lookup_names(LSA_R_LOOKUP_NAMES *r_l,
                DOM_R_REF *ref, uint32 num_entries,
                DOM_RID2 *rid2, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->dom_rid      = rid2;

	r_l->mapped_count = mapped_count;
}

/***************************************************************************
 Init lsa_trans_names.
 ***************************************************************************/

static void init_lsa_trans_names(TALLOC_CTX *ctx, DOM_R_REF *ref, LSA_TRANS_NAME_ENUM *trn,
				 int num_entries, DOM_SID2 *sid,
				 uint32 *mapped_count)
{
	int i;
	int total = 0;
	*mapped_count = 0;

	/* Allocate memory for list of names */

	if (num_entries > 0) {
		if (!(trn->name = (LSA_TRANS_NAME *)talloc(ctx, sizeof(LSA_TRANS_NAME) *
							  num_entries))) {
			DEBUG(0, ("init_lsa_trans_names(): out of memory\n"));
			return;
		}

		if (!(trn->uni_name = (UNISTR2 *)talloc(ctx, sizeof(UNISTR2) * 
							num_entries))) {
			DEBUG(0, ("init_lsa_trans_names(): out of memory\n"));
			return;
		}
	}

	become_root(); /* Need root to get to passdb to for local sids */

	for (i = 0; i < num_entries; i++) {
		BOOL status = False;
		DOM_SID find_sid = sid[i].sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		fstring name, dom_name;
		enum SID_NAME_USE sid_name_use = (enum SID_NAME_USE)0;

		sid_to_string(name, &find_sid);
		DEBUG(5, ("init_lsa_trans_names: looking up sid %s\n", name));

		/* Lookup sid from winbindd */

		status = lookup_sid(&find_sid, dom_name, name, &sid_name_use);

		DEBUG(5, ("init_lsa_trans_names: %s\n", status ? "found" : 
			  "not found"));

		if (!status) {
			sid_name_use = SID_NAME_UNKNOWN;
			memset(dom_name, '\0', sizeof(dom_name));
			sid_to_string(name, &find_sid);
			dom_idx = -1;

			DEBUG(10,("init_lsa_trans_names: added unknown user '%s' to "
				  "referenced list.\n", name ));
		} else {
			(*mapped_count)++;
			/* Store domain sid in ref array */
			if (find_sid.num_auths == 5) {
				sid_split_rid(&find_sid, &rid);
			}
			dom_idx = init_dom_ref(ref, dom_name, &find_sid);

			DEBUG(10,("init_lsa_trans_names: added user '%s\\%s' to "
				  "referenced list.\n", dom_name, name ));

		}

		init_lsa_trans_name(&trn->name[total], &trn->uni_name[total],
					sid_name_use, name, dom_idx);
		total++;
	}

	unbecome_root();

	trn->num_entries = total;
	trn->ptr_trans_names = 1;
	trn->num_entries2 = total;
}

/***************************************************************************
 Init_reply_lookup_sids.
 ***************************************************************************/

static void init_reply_lookup_sids(LSA_R_LOOKUP_SIDS *r_l,
                DOM_R_REF *ref, LSA_TRANS_NAME_ENUM *names,
                uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;
	r_l->names        = names;
	r_l->mapped_count = mapped_count;
}

static NTSTATUS lsa_get_generic_sd(TALLOC_CTX *mem_ctx, SEC_DESC **sd, size_t *sd_size)
{
	extern DOM_SID global_sid_World;
	extern DOM_SID global_sid_Builtin;
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

/***************************************************************************
 Init_dns_dom_info.
***************************************************************************/

static void init_dns_dom_info(LSA_DNS_DOM_INFO *r_l, const char *nb_name,
			      const char *dns_name, const char *forest_name,
			      struct uuid *dom_guid, DOM_SID *dom_sid)
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
		memcpy(&r_l->dom_guid, dom_guid, sizeof(struct uuid));
	}
	
	if (dom_sid) {
		r_l->ptr_dom_sid = 1;
		init_dom_sid2(&r_l->dom_sid, dom_sid);
	}
}

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
		if (geteuid() != 0) {
			return status;
		}
		DEBUG(4,("ACCESS should be DENIED (granted: %#010x;  required: %#010x)\n",
			 acc_granted, des_access));
		DEBUGADD(4,("but overwritten by euid == 0\n"));
		acc_granted = des_access;
	}


	/* associate the domain SID with the (unique) handle. */
	if ((info = (struct lsa_info *)malloc(sizeof(struct lsa_info))) == NULL)
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
	if ((info = (struct lsa_info *)malloc(sizeof(struct lsa_info))) == NULL)
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

NTSTATUS _lsa_enum_trust_dom(pipes_struct *p, LSA_Q_ENUM_TRUST_DOM *q_u, LSA_R_ENUM_TRUST_DOM *r_u)
{
	struct lsa_info *info;
	uint32 enum_context = q_u->enum_context;

	/*
	 * preferred length is set to 5 as a "our" preferred length
	 * nt sets this parameter to 2
	 * update (20.08.2002): it's not preferred length, but preferred size!
	 * it needs further investigation how to optimally choose this value
	 */
	uint32 max_num_domains = q_u->preferred_len < 5 ? q_u->preferred_len : 10;
	TRUSTDOM **trust_doms;
	uint32 num_domains;
	NTSTATUS nt_status;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */
	if (!(info->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	nt_status = secrets_get_trusted_domains(p->mem_ctx, (int *)&enum_context, max_num_domains, (int *)&num_domains, &trust_doms);

	if (!NT_STATUS_IS_OK(nt_status) &&
	    !NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES) &&
	    !NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MORE_ENTRIES)) {
		return nt_status;
	} else {
		r_u->status = nt_status;
	}

	/* set up the lsa_enum_trust_dom response */
	init_r_enum_trust_dom(p->mem_ctx, r_u, enum_context, max_num_domains, num_domains, trust_doms);

	return r_u->status;
}

/***************************************************************************
 _lsa_query_info. See the POLICY_INFOMATION_CLASS docs at msdn.
 ***************************************************************************/

NTSTATUS _lsa_query_info(pipes_struct *p, LSA_Q_QUERY_INFO *q_u, LSA_R_QUERY_INFO *r_u)
{
	struct lsa_info *handle;
	LSA_INFO_UNION *info = &r_u->dom;
	DOM_SID domain_sid;
	const char *name;
	DOM_SID *sid = NULL;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
		return NT_STATUS_INVALID_HANDLE;

	switch (q_u->info_class) {
	case 0x02:
		{
		unsigned int i;
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_AUDIT_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		/* fake info: We audit everything. ;) */
		info->id2.auditing_enabled = 1;
		info->id2.count1 = 7;
		info->id2.count2 = 7;
		if ((info->id2.auditsettings = (uint32 *)talloc(p->mem_ctx,7*sizeof(uint32))) == NULL)
			return NT_STATUS_NO_MEMORY;
		for (i = 0; i < 7; i++)
			info->id2.auditsettings[i] = 3;
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
		init_dom_query(&r_u->dom.id3, name, sid);
		break;
	case 0x05:
		/* check if the user have enough rights */
		if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
			return NT_STATUS_ACCESS_DENIED;

		/* Request PolicyAccountDomainInformation. */
		name = get_global_sam_name();
		sid = get_global_sam_sid();
		init_dom_query(&r_u->dom.id5, name, sid);
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
				info->id6.server_role = 2;
				break;
			default:
				/*
				 * any other role is a primary
				 * of the domain, it controls.
				 */
				info->id6.server_role = 3;
				break; 
		}
		break;
	default:
		DEBUG(0,("_lsa_query_info: unknown info level in Lsa Query: %d\n", q_u->info_class));
		r_u->status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	if (NT_STATUS_IS_OK(r_u->status)) {
		r_u->undoc_buffer = 0x22000000; /* bizarre */
		r_u->info_class = q_u->info_class;
	}

	return r_u->status;
}

/***************************************************************************
 _lsa_lookup_sids
 ***************************************************************************/

NTSTATUS _lsa_lookup_sids(pipes_struct *p, LSA_Q_LOOKUP_SIDS *q_u, LSA_R_LOOKUP_SIDS *r_u)
{
	struct lsa_info *handle;
	DOM_SID2 *sid = q_u->sids.sid;
	int num_entries = q_u->sids.num_entries;
	DOM_R_REF *ref = NULL;
	LSA_TRANS_NAME_ENUM *names = NULL;
	uint32 mapped_count = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_sids: truncating SID lookup list to %d\n", num_entries));
	}

	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	names = (LSA_TRANS_NAME_ENUM *)talloc_zero(p->mem_ctx, sizeof(LSA_TRANS_NAME_ENUM));

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle)) {
		r_u->status = NT_STATUS_INVALID_HANDLE;
		goto done;
	}

	/* check if the user have enough rights */
	if (!(handle->access & POLICY_LOOKUP_NAMES)) {
		r_u->status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}
	if (!ref || !names)
		return NT_STATUS_NO_MEMORY;

done:

	/* set up the LSA Lookup SIDs response */
	init_lsa_trans_names(p->mem_ctx, ref, names, num_entries, sid, &mapped_count);
	if (mapped_count == 0)
		r_u->status = NT_STATUS_NONE_MAPPED;
	else if (mapped_count != num_entries)
		r_u->status = STATUS_SOME_UNMAPPED;
	else
		r_u->status = NT_STATUS_OK;
	init_reply_lookup_sids(r_u, ref, names, mapped_count);

	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names
 ***************************************************************************/

NTSTATUS _lsa_lookup_names(pipes_struct *p,LSA_Q_LOOKUP_NAMES *q_u, LSA_R_LOOKUP_NAMES *r_u)
{
	struct lsa_info *handle;
	UNISTR2 *names = q_u->uni_name;
	int num_entries = q_u->num_entries;
	DOM_R_REF *ref;
	DOM_RID2 *rids;
	uint32 mapped_count = 0;

	if (num_entries >  MAX_LOOKUP_SIDS) {
		num_entries = MAX_LOOKUP_SIDS;
		DEBUG(5,("_lsa_lookup_names: truncating name lookup list to %d\n", num_entries));
	}
		
	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	rids = (DOM_RID2 *)talloc_zero(p->mem_ctx, sizeof(DOM_RID2)*num_entries);

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle)) {
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

done:

	/* set up the LSA Lookup RIDs response */
	init_lsa_rid2s(ref, rids, num_entries, names, &mapped_count, p->endian);
	if (mapped_count == 0)
		r_u->status = NT_STATUS_NONE_MAPPED;
	else if (mapped_count != num_entries)
		r_u->status = STATUS_SOME_UNMAPPED;
	else
		r_u->status = NT_STATUS_OK;
	init_reply_lookup_names(r_u, ref, num_entries, rids, mapped_count);

	return r_u->status;
}

/***************************************************************************
 _lsa_close. Also weird - needs to check if lsa handle is correct. JRA.
 ***************************************************************************/

NTSTATUS _lsa_close(pipes_struct *p, LSA_Q_CLOSE *q_u, LSA_R_CLOSE *r_u)
{
	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	close_policy_hnd(p, &q_u->pol);
	return NT_STATUS_OK;
}

/***************************************************************************
  "No more secrets Marty...." :-).
 ***************************************************************************/

NTSTATUS _lsa_open_secret(pipes_struct *p, LSA_Q_OPEN_SECRET *q_u, LSA_R_OPEN_SECRET *r_u)
{
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/***************************************************************************
_lsa_enum_privs.
 ***************************************************************************/

NTSTATUS _lsa_enum_privs(pipes_struct *p, LSA_Q_ENUM_PRIVS *q_u, LSA_R_ENUM_PRIVS *r_u)
{
	struct lsa_info *handle;
	uint32 i;

	uint32 enum_context=q_u->enum_context;
	LSA_PRIV_ENTRY *entry;
	LSA_PRIV_ENTRY *entries=NULL;

	if (enum_context >= PRIV_ALL_INDEX)
		return NT_STATUS_NO_MORE_ENTRIES;

	entries = (LSA_PRIV_ENTRY *)talloc_zero(p->mem_ctx, sizeof(LSA_PRIV_ENTRY) * (PRIV_ALL_INDEX));
	if (entries==NULL)
		return NT_STATUS_NO_MEMORY;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 */
	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	entry = entries;
	
	DEBUG(10,("_lsa_enum_privs: enum_context:%d total entries:%d\n", enum_context, PRIV_ALL_INDEX));

	for (i = 0; i < PRIV_ALL_INDEX; i++, entry++) {
		if( i<enum_context) {
			init_unistr2(&entry->name, NULL, UNI_FLAGS_NONE);
			init_uni_hdr(&entry->hdr_name, &entry->name);
			entry->luid_low = 0;
			entry->luid_high = 0;
		} else {
			init_unistr2(&entry->name, privs[i+1].priv, UNI_FLAGS_NONE);
			init_uni_hdr(&entry->hdr_name, &entry->name);
			entry->luid_low = privs[i+1].se_priv;
			entry->luid_high = 0;
		}
	}

	enum_context = PRIV_ALL_INDEX;
	init_lsa_r_enum_privs(r_u, enum_context, PRIV_ALL_INDEX, entries);

	return NT_STATUS_OK;
}

/***************************************************************************
_lsa_priv_get_dispname.
 ***************************************************************************/

NTSTATUS _lsa_priv_get_dispname(pipes_struct *p, LSA_Q_PRIV_GET_DISPNAME *q_u, LSA_R_PRIV_GET_DISPNAME *r_u)
{
	struct lsa_info *handle;
	fstring name_asc;
	int i=1;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 */
	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	unistr2_to_ascii(name_asc, &q_u->name, sizeof(name_asc));

	DEBUG(10,("_lsa_priv_get_dispname: %s", name_asc));

	while (privs[i].se_priv!=SE_PRIV_ALL && strcmp(name_asc, privs[i].priv))
		i++;
	
	if (privs[i].se_priv!=SE_PRIV_ALL) {
		DEBUG(10,(": %s\n", privs[i].description));
		init_unistr2(&r_u->desc, privs[i].description, UNI_FLAGS_NONE);
		init_uni_hdr(&r_u->hdr_desc, &r_u->desc);

		r_u->ptr_info=0xdeadbeef;
		r_u->lang_id=q_u->lang_id;
		return NT_STATUS_OK;
	} else {
		DEBUG(10,("_lsa_priv_get_dispname: doesn't exist\n"));
		r_u->ptr_info=0;
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}
}

/***************************************************************************
_lsa_enum_accounts.
 ***************************************************************************/

NTSTATUS _lsa_enum_accounts(pipes_struct *p, LSA_Q_ENUM_ACCOUNTS *q_u, LSA_R_ENUM_ACCOUNTS *r_u)
{
	struct lsa_info *handle;
	GROUP_MAP *map=NULL;
	int num_entries=0;
	LSA_SID_ENUM *sids=&r_u->sids;
	int i=0,j=0;
	BOOL ret;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 */
	if (!(handle->access & POLICY_VIEW_LOCAL_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	/* get the list of mapped groups (domain, local, builtin) */
	become_root();
	ret = pdb_enum_group_mapping(SID_NAME_UNKNOWN, &map, &num_entries, ENUM_ONLY_MAPPED);
	unbecome_root();
	if( !ret ) {
		DEBUG(3,("_lsa_enum_accounts: enumeration of groups failed!\n"));
		return NT_STATUS_OK;
	}
	

	if (q_u->enum_context >= num_entries)
		return NT_STATUS_NO_MORE_ENTRIES;

	sids->ptr_sid = (uint32 *)talloc_zero(p->mem_ctx, (num_entries-q_u->enum_context)*sizeof(uint32));
	sids->sid = (DOM_SID2 *)talloc_zero(p->mem_ctx, (num_entries-q_u->enum_context)*sizeof(DOM_SID2));

	if (sids->ptr_sid==NULL || sids->sid==NULL) {
		SAFE_FREE(map);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=q_u->enum_context, j=0; i<num_entries; i++) {
		init_dom_sid2( &(*sids).sid[j],  &map[i].sid);
		(*sids).ptr_sid[j]=1;
		j++;
	}

	SAFE_FREE(map);

	init_lsa_r_enum_accounts(r_u, j);

	return NT_STATUS_OK;
}


NTSTATUS _lsa_unk_get_connuser(pipes_struct *p, LSA_Q_UNK_GET_CONNUSER *q_u, LSA_R_UNK_GET_CONNUSER *r_u)
{
	fstring username, domname;
	user_struct *vuser = get_valid_user_struct(p->vuid);
  
	if (vuser == NULL)
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
  
	fstrcpy(username, vuser->user.smb_name);
	fstrcpy(domname, vuser->user.domain);
  
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
 
 ***************************************************************************/

NTSTATUS _lsa_open_account(pipes_struct *p, LSA_Q_OPENACCOUNT *q_u, LSA_R_OPENACCOUNT *r_u)
{
	struct lsa_info *handle;
	struct lsa_info *info;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
		return NT_STATUS_INVALID_HANDLE;

	/* check if the user have enough rights */

	/*
	 * I don't know if it's the right one. not documented.
	 * but guessed with rpcclient.
	 */
	if (!(handle->access & POLICY_GET_PRIVATE_INFORMATION))
		return NT_STATUS_ACCESS_DENIED;

	/* associate the user/group SID with the (unique) handle. */
	if ((info = (struct lsa_info *)malloc(sizeof(struct lsa_info))) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	info->sid = q_u->sid.sid;
	info->access = q_u->access;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->pol, free_lsa_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/***************************************************************************
 For a given SID, enumerate all the privilege this account has.
 ***************************************************************************/

NTSTATUS _lsa_enum_privsaccount(pipes_struct *p, prs_struct *ps, LSA_Q_ENUMPRIVSACCOUNT *q_u, LSA_R_ENUMPRIVSACCOUNT *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	LUID_ATTR *set=NULL;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

#if 0 /* privileges currently not implemented! */
	DEBUG(10,("_lsa_enum_privsaccount: %d privileges\n", map.priv_set->count));
	if (map.priv_set->count!=0) {
	
		set=(LUID_ATTR *)talloc(map.priv_set->mem_ctx, map.priv_set.count*sizeof(LUID_ATTR));
		if (set == NULL) {
			destroy_privilege(&map.priv_set);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < map.priv_set.count; i++) {
			set[i].luid.low = map.priv_set->set[i].luid.low;
			set[i].luid.high = map.priv_set->set[i].luid.high;
			set[i].attr = map.priv_set->set[i].attr;
			DEBUG(10,("_lsa_enum_privsaccount: priv %d: %d:%d:%d\n", i, 
				   set[i].luid.high, set[i].luid.low, set[i].attr));
		}
	}

	init_lsa_r_enum_privsaccount(ps->mem_ctx, r_u, set, map.priv_set->count, 0);	
	destroy_privilege(&map.priv_set);	
#endif

	init_lsa_r_enum_privsaccount(ps->mem_ctx, r_u, set, 0, 0);

	return r_u->status;
}

/***************************************************************************
 
 ***************************************************************************/

NTSTATUS _lsa_getsystemaccount(pipes_struct *p, LSA_Q_GETSYSTEMACCOUNT *q_u, LSA_R_GETSYSTEMACCOUNT *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

	/*
	  0x01 -> Log on locally
	  0x02 -> Access this computer from network
	  0x04 -> Log on as a batch job
	  0x10 -> Log on as a service
	  
	  they can be ORed together
	*/

	r_u->access = PR_LOG_ON_LOCALLY | PR_ACCESS_FROM_NETWORK;

	return r_u->status;
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
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

	if(!pdb_update_group_mapping_entry(&map))
		return NT_STATUS_NO_SUCH_GROUP;

	return r_u->status;
}

/***************************************************************************
 For a given SID, add some privileges.
 ***************************************************************************/

NTSTATUS _lsa_addprivs(pipes_struct *p, LSA_Q_ADDPRIVS *q_u, LSA_R_ADDPRIVS *r_u)
{
#if 0
	struct lsa_info *info = NULL;
	GROUP_MAP map;
	int i = 0;
	LUID_ATTR *luid_attr = NULL;
	PRIVILEGE_SET *set = NULL;
#endif

	r_u->status = NT_STATUS_OK;

#if 0 /* privileges are not implemented */
	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

	set = &q_u->set;

	for (i = 0; i < set->count; i++) {
		luid_attr = &set->set[i];
		
		/* check if the privilege is already there */
		if (check_priv_in_privilege(map.priv_set, *luid_attr)){
			destroy_privilege(&map.priv_set);
		}
		
		add_privilege(map.priv_set, *luid_attr);
	}

	if(!pdb_update_group_mapping_entry(&map))
		return NT_STATUS_NO_SUCH_GROUP;
	
	destroy_privilege(&map.priv_set);	

#endif
	return r_u->status;
}

/***************************************************************************
 For a given SID, remove some privileges.
 ***************************************************************************/

NTSTATUS _lsa_removeprivs(pipes_struct *p, LSA_Q_REMOVEPRIVS *q_u, LSA_R_REMOVEPRIVS *r_u)
{
#if 0
	struct lsa_info *info = NULL;
	GROUP_MAP map;
	int i=0;
	LUID_ATTR *luid_attr = NULL;
	PRIVILEGE_SET *set = NULL;
#endif

	r_u->status = NT_STATUS_OK;

#if 0 /* privileges are not implemented */
	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!pdb_getgrsid(&map, info->sid))
		return NT_STATUS_NO_SUCH_GROUP;

	if (q_u->allrights != 0) {
		/* log it and return, until I see one myself don't do anything */
		DEBUG(5,("_lsa_removeprivs: trying to remove all privileges ?\n"));
		return NT_STATUS_OK;
	}

	if (q_u->ptr == 0) {
		/* log it and return, until I see one myself don't do anything */
		DEBUG(5,("_lsa_removeprivs: no privileges to remove ?\n"));
		return NT_STATUS_OK;
	}

	set = &q_u->set;

	for (i = 0; i < set->count; i++) {
		luid_attr = &set->set[i];
		
		/* if we don't have the privilege, we're trying to remove, give up */
		/* what else can we do ??? JFM. */
		if (!check_priv_in_privilege(map.priv_set, *luid_attr)){
			destroy_privilege(&map.priv_set);
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		
		remove_privilege(map.priv_set, *luid_attr);
	}

	if(!pdb_update_group_mapping_entry(&map))
		return NT_STATUS_NO_SUCH_GROUP;
	
	destroy_privilege(&map.priv_set);	
#endif
	return r_u->status;
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
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
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


NTSTATUS _lsa_query_info2(pipes_struct *p, LSA_Q_QUERY_INFO2 *q_u, LSA_R_QUERY_INFO2 *r_u)
{
	struct lsa_info *handle;
	const char *nb_name;
	char *dns_name = NULL;
	char *forest_name = NULL;
	DOM_SID *sid = NULL;
	struct uuid guid;
	fstring dnsdomname;

	ZERO_STRUCT(guid);
	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&handle))
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
