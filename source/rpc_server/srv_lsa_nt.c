/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    2001.
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

extern DOM_SID global_sam_sid;
extern fstring global_myworkgroup;
extern pstring global_myname;

static PRIVS privs[] = {
    {SE_PRIV_NONE, "no_privs", "No privilege"},
    {SE_PRIV_ADD_USERS, "add_users", "add users"},
    {SE_PRIV_ADD_MACHINES, "add_computers", "add computers to domain"},
    {SE_PRIV_PRINT_OPERATOR, "print_op", "printer operator"},
    {SE_PRIV_ALL, "all_privs", "all privileges"}
};

struct lsa_info {
    DOM_SID sid;
    uint32 access;
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

static void init_dom_query(DOM_QUERY *d_q, char *dom_name, DOM_SID *dom_sid)
{
	int domlen = (dom_name != NULL) ? strlen(dom_name) : 0;

	/*
	 * I'm not sure why this really odd combination of length
	 * values works, but it does appear to. I need to look at
	 * this *much* more closely - but at the moment leave alone
	 * until it's understood. This allows a W2k client to join
	 * a domain with both odd and even length names... JRA.
	 */

	d_q->uni_dom_str_len = domlen ? ((domlen + 1) * 2) : 0;
	d_q->uni_dom_max_len = domlen * 2;
	d_q->buffer_dom_name = domlen != 0 ? 1 : 0; /* domain buffer pointer */
	d_q->buffer_dom_sid = dom_sid != NULL ? 1 : 0;  /* domain sid pointer */

	/* this string is supposed to be character short */
	init_unistr2(&d_q->uni_domain_name, dom_name, domlen);
	d_q->uni_domain_name.uni_max_len++;

	if (dom_sid != NULL)
		init_dom_sid2(&d_q->dom_sid, dom_sid);
}

/***************************************************************************
 init_dom_ref - adds a domain if it's not already in, returns the index.
***************************************************************************/

static int init_dom_ref(DOM_R_REF *ref, char *dom_name, DOM_SID *dom_sid)
{
	int num = 0;
	int len;

	if (dom_name != NULL) {
		for (num = 0; num < ref->num_ref_doms_1; num++) {
			fstring domname;
			fstrcpy(domname, dos_unistr2_to_str(&ref->ref_dom[num].uni_dom_name));
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

	len = (dom_name != NULL) ? strlen(dom_name) : 0;
	if(dom_name != NULL && len == 0)
		len = 1;

	init_uni_hdr(&ref->hdr_ref_dom[num].hdr_dom_name, len);
	ref->hdr_ref_dom[num].ptr_dom_sid = dom_sid != NULL ? 1 : 0;

	init_unistr2(&ref->ref_dom[num].uni_dom_name, dom_name, len);
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

	for (i = 0; i < num_entries; i++) {
		BOOL status = False;
		DOM_SID sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		pstring full_name;
		fstring dom_name, user;
		enum SID_NAME_USE name_type = SID_NAME_UNKNOWN;

		/* Split name into domain and user component */

		pstrcpy(full_name, dos_unistr2_to_str(&name[i]));
		dos_to_unix(full_name); /* full name should be in unix charset. */
		split_domain_name(full_name, dom_name, user);

		/* Lookup name */

		DEBUG(5, ("init_lsa_rid2s: looking up name %s\n", full_name));

		status = lookup_name(full_name, &sid, &name_type);

		DEBUG(5, ("init_lsa_rid2s: %s\n", status ? "found" : 
			  "not found"));

		if (status) {
			sid_split_rid(&sid, &rid);
			dom_idx = init_dom_ref(ref, dom_name, &sid);
			(*mapped_count)++;
		} else {
			dom_idx = -1;
			rid = 0xffffffff;
			name_type = SID_NAME_UNKNOWN;
		}

		init_dom_rid2(&rid2[total], rid, name_type, dom_idx);
		total++;
	}
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

	if (mapped_count == 0)
		r_l->status = NT_STATUS_NONE_MAPPED;
	else
		r_l->status = NT_STATUS_OK;
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

		memset(dom_name, '\0', sizeof(dom_name));
		memset(name, '\0', sizeof(name));

		status = lookup_sid(&find_sid, dom_name, name, &sid_name_use);

		DEBUG(5, ("init_lsa_trans_names: %s\n", status ? "found" : 
			  "not found"));

		if (!status) {
			sid_name_use = SID_NAME_UNKNOWN;
		}

		/* Store domain sid in ref array */

		if (find_sid.num_auths == 5) {
			sid_split_rid(&find_sid, &rid);
		}

		/* unistr routines take dos codepage strings */

		unix_to_dos(dom_name);
		unix_to_dos(name);

		dom_idx = init_dom_ref(ref, dom_name, &find_sid);

		DEBUG(10,("init_lsa_trans_names: added user '%s\\%s' to "
			  "referenced list.\n", dom_name, name ));

		(*mapped_count)++;

		init_lsa_trans_name(&trn->name[total], &trn->uni_name[total],
					sid_name_use, name, dom_idx);
		total++;
	}

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

	if (mapped_count == 0)
		r_l->status = NT_STATUS_NONE_MAPPED;
	else
		r_l->status = NT_STATUS_OK;
}

/***************************************************************************
 _lsa_open_policy2.
 ***************************************************************************/

NTSTATUS _lsa_open_policy2(pipes_struct *p, LSA_Q_OPEN_POL2 *q_u, LSA_R_OPEN_POL2 *r_u)
{
	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* set up the LSA QUERY INFO response */
	if (!create_policy_hnd(p, &r_u->pol, NULL, NULL))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/***************************************************************************
 _lsa_open_policy
 ***************************************************************************/

NTSTATUS _lsa_open_policy(pipes_struct *p, LSA_Q_OPEN_POL *q_u, LSA_R_OPEN_POL *r_u)
{
	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* set up the LSA QUERY INFO response */
	if (!create_policy_hnd(p, &r_u->pol, NULL, NULL))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/***************************************************************************
 _lsa_enum_trust_dom - this needs fixing to do more than return NULL ! JRA.
 ***************************************************************************/

NTSTATUS _lsa_enum_trust_dom(pipes_struct *p, LSA_Q_ENUM_TRUST_DOM *q_u, LSA_R_ENUM_TRUST_DOM *r_u)
{
	uint32 enum_context = 0;
	char *dom_name = NULL;
	DOM_SID *dom_sid = NULL;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	/* set up the LSA QUERY INFO response */
	init_r_enum_trust_dom(p->mem_ctx, r_u, enum_context, dom_name, dom_sid,
	      dom_name != NULL ? NT_STATUS_OK : NT_STATUS_NO_MORE_ENTRIES);

	return r_u->status;
}

/***************************************************************************
 _lsa_query_info. See the POLICY_INFOMATION_CLASS docs at msdn.
 ***************************************************************************/

NTSTATUS _lsa_query_info(pipes_struct *p, LSA_Q_QUERY_INFO *q_u, LSA_R_QUERY_INFO *r_u)
{
	LSA_INFO_UNION *info = &r_u->dom;
	DOM_SID domain_sid;
	fstring dos_domain;
	fstring dos_myname;
	char *name = NULL;
	DOM_SID *sid = NULL;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	fstrcpy(dos_myname, global_myname);
	unix_to_dos(dos_myname);

	fstrcpy(dos_domain, global_myworkgroup);
	unix_to_dos(dos_domain);

	switch (q_u->info_class) {
	case 0x02:
		{
			unsigned int i;
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
		/* Request PolicyPrimaryDomainInformation. */
		switch (lp_server_role()) {
			case ROLE_DOMAIN_PDC:
			case ROLE_DOMAIN_BDC:
				name = dos_domain;
				sid = &global_sam_sid;
				break;
			case ROLE_DOMAIN_MEMBER:
				name = dos_domain;
				/* We need to return the Domain SID here. */
				if (secrets_fetch_domain_sid(dos_domain,
							     &domain_sid))
					sid = &domain_sid;
				else
					return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
				break;
			case ROLE_STANDALONE:
				name = dos_domain;
				sid = NULL;
				break;
			default:
				return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		init_dom_query(&r_u->dom.id3, name, sid);
		break;
	case 0x05:
		/* Request PolicyAccountDomainInformation. */
		switch (lp_server_role()) {
			case ROLE_DOMAIN_PDC:
			case ROLE_DOMAIN_BDC:
				name = dos_domain;
				sid = &global_sam_sid;
				break;
			case ROLE_DOMAIN_MEMBER:
				name = dos_myname;
				sid = &global_sam_sid;
				break;
			case ROLE_STANDALONE:
				name = dos_myname;
				sid = &global_sam_sid;
				break;
			default:
				return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		init_dom_query(&r_u->dom.id5, name, sid);
		break;
	case 0x06:
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
	DOM_SID2 *sid = q_u->sids.sid;
	int num_entries = q_u->sids.num_entries;
	DOM_R_REF *ref = NULL;
	LSA_TRANS_NAME_ENUM *names = NULL;
	uint32 mapped_count = 0;

	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	names = (LSA_TRANS_NAME_ENUM *)talloc_zero(p->mem_ctx, sizeof(LSA_TRANS_NAME_ENUM));

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		r_u->status = NT_STATUS_INVALID_HANDLE;

	if ((!ref || !names) && NT_STATUS_IS_OK(r_u->status))
		r_u->status = NT_STATUS_NO_MEMORY;

	/* set up the LSA Lookup SIDs response */
	init_lsa_trans_names(p->mem_ctx, ref, names, num_entries, sid, &mapped_count);
	init_reply_lookup_sids(r_u, ref, names, mapped_count);

	return r_u->status;
}

/***************************************************************************
lsa_reply_lookup_names
 ***************************************************************************/

NTSTATUS _lsa_lookup_names(pipes_struct *p,LSA_Q_LOOKUP_NAMES *q_u, LSA_R_LOOKUP_NAMES *r_u)
{
	UNISTR2 *names = q_u->uni_name;
	int num_entries = q_u->num_entries;
	DOM_R_REF *ref;
	DOM_RID2 *rids;
	uint32 mapped_count = 0;

	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	rids = (DOM_RID2 *)talloc_zero(p->mem_ctx, sizeof(DOM_RID2)*MAX_LOOKUP_SIDS);

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		r_u->status = NT_STATUS_INVALID_HANDLE;

	if ((!ref || !rids) && NT_STATUS_IS_OK(r_u->status))
		r_u->status = NT_STATUS_NO_MEMORY;

	/* set up the LSA Lookup RIDs response */
	init_lsa_rid2s(ref, rids, num_entries, names, &mapped_count, p->endian);
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
	uint32 i;

	uint32 enum_context=q_u->enum_context;
	LSA_PRIV_ENTRY *entry;
	LSA_PRIV_ENTRY *entries;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	if (enum_context >= PRIV_ALL_INDEX)
		return NT_STATUS_UNABLE_TO_FREE_VM;

	entries = (LSA_PRIV_ENTRY *)talloc_zero(p->mem_ctx, sizeof(LSA_PRIV_ENTRY) * (PRIV_ALL_INDEX-enum_context));
	if (entries==NULL)
		return NT_STATUS_NO_MEMORY;

	entry = entries;
	for (i = 0; i < PRIV_ALL_INDEX-enum_context; i++, entry++) {
		init_uni_hdr(&entry->hdr_name, strlen(privs[i+1-enum_context].priv));
		init_unistr2(&entry->name, privs[i+1-enum_context].priv, strlen(privs[i+1-enum_context].priv) );
		entry->luid_low = privs[i+1-enum_context].se_priv;
		entry->luid_high = 1;
	}

	init_lsa_r_enum_privs(r_u, i+enum_context, PRIV_ALL_INDEX-enum_context, entries);

	return NT_STATUS_OK;
}

/***************************************************************************
_lsa_priv_get_dispname.
 ***************************************************************************/

NTSTATUS _lsa_priv_get_dispname(pipes_struct *p, LSA_Q_PRIV_GET_DISPNAME *q_u, LSA_R_PRIV_GET_DISPNAME *r_u)
{
	fstring name_asc;
	fstring desc_asc;
	int i;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	unistr2_to_dos(name_asc, &q_u->name, sizeof(name_asc));

	DEBUG(0,("_lsa_priv_get_dispname: %s", name_asc));

	for (i=1; privs[i].se_priv!=SE_PRIV_ALL; i++) {
		if ( strcmp(name_asc, privs[i].priv)) {
			
			fstrcpy(desc_asc, privs[i].description);
		
		}
	}
	DEBUG(0,(": %s\n", desc_asc));

	init_uni_hdr(&r_u->hdr_desc, strlen(desc_asc));
	init_unistr2(&r_u->desc, desc_asc, strlen(desc_asc) );

	r_u->ptr_info=0xdeadbeef;
	r_u->lang_id=q_u->lang_id;

	return NT_STATUS_OK;
}

NTSTATUS _lsa_unk_get_connuser(pipes_struct *p, LSA_Q_UNK_GET_CONNUSER *q_u, LSA_R_UNK_GET_CONNUSER *r_u)
{
  fstring username, domname;
  int ulen, dlen;
  user_struct *vuser = get_valid_user_struct(p->vuid);
  
  if (vuser == NULL)
    return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
  
  fstrcpy(username, vuser->user.smb_name);
  fstrcpy(domname, vuser->user.domain);
  
  ulen = strlen(username) + 1;
  dlen = strlen(domname) + 1;
  
  init_uni_hdr(&r_u->hdr_user_name, ulen);
  r_u->ptr_user_name = 1;
  init_unistr2(&r_u->uni2_user_name, username, ulen);

  r_u->unk1 = 1;
  
  init_uni_hdr(&r_u->hdr_dom_name, dlen);
  r_u->ptr_dom_name = 1;
  init_unistr2(&r_u->uni2_dom_name, domname, dlen);

  r_u->status = NT_STATUS_OK;
  
  return r_u->status;
}

/***************************************************************************
 
 ***************************************************************************/

NTSTATUS _lsa_open_account(pipes_struct *p, LSA_Q_OPENACCOUNT *q_u, LSA_R_OPENACCOUNT *r_u)
{
	struct lsa_info *info;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

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
 
 ***************************************************************************/

NTSTATUS _lsa_getsystemaccount(pipes_struct *p, LSA_Q_GETSYSTEMACCOUNT *q_u, LSA_R_GETSYSTEMACCOUNT *r_u)
{
	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	r_u->access=3;

	return r_u->status;
}
