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
extern PRIVS privs[];

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

		unistr2_to_ascii(full_name, &name[i], sizeof(full_name));
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
	char *name = NULL;
	DOM_SID *sid = NULL;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

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
				name = global_myworkgroup;
				sid = &global_sam_sid;
				break;
			case ROLE_DOMAIN_MEMBER:
				name = global_myworkgroup;
				/* We need to return the Domain SID here. */
				if (secrets_fetch_domain_sid(global_myworkgroup,
							     &domain_sid))
					sid = &domain_sid;
				else
					return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
				break;
			case ROLE_STANDALONE:
				name = global_myworkgroup;
				sid = NULL; /* Tell it we're not in a domain. */
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
				name = global_myworkgroup;
				sid = &global_sam_sid;
				break;
			case ROLE_DOMAIN_MEMBER:
				name = global_myworkgroup;
				sid = &global_sam_sid;
				break;
			case ROLE_STANDALONE:
				name = global_myworkgroup;
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

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	names = (LSA_TRANS_NAME_ENUM *)talloc_zero(p->mem_ctx, sizeof(LSA_TRANS_NAME_ENUM));

	if (!ref || !names)
		return NT_STATUS_NO_MEMORY;

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

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	ref = (DOM_R_REF *)talloc_zero(p->mem_ctx, sizeof(DOM_R_REF));
	rids = (DOM_RID2 *)talloc_zero(p->mem_ctx, sizeof(DOM_RID2)*MAX_LOOKUP_SIDS);

	if (!ref || !rids)
		return NT_STATUS_NO_MEMORY;

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
	LSA_PRIV_ENTRY *entries=NULL;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	if (enum_context >= PRIV_ALL_INDEX)
		return NT_STATUS_NO_MORE_ENTRIES;

	entries = (LSA_PRIV_ENTRY *)talloc_zero(p->mem_ctx, sizeof(LSA_PRIV_ENTRY) * (PRIV_ALL_INDEX));
	if (entries==NULL)
		return NT_STATUS_NO_MEMORY;

	entry = entries;
	
	DEBUG(10,("_lsa_enum_privs: enum_context:%d total entries:%d\n", enum_context, PRIV_ALL_INDEX));

	for (i = 0; i < PRIV_ALL_INDEX; i++, entry++) {
		if( i<enum_context) {
			init_uni_hdr(&entry->hdr_name, 0);
			init_unistr2(&entry->name, NULL, 0 );
			entry->luid_low = 0;
			entry->luid_high = 0;
		} else {
			init_uni_hdr(&entry->hdr_name, strlen(privs[i+1].priv));
			init_unistr2(&entry->name, privs[i+1].priv, strlen(privs[i+1].priv) );
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
	fstring name_asc;
	int i=1;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	unistr2_to_ascii(name_asc, &q_u->name, sizeof(name_asc));

	DEBUG(10,("_lsa_priv_get_dispname: %s", name_asc));

	while (privs[i].se_priv!=SE_PRIV_ALL && strcmp(name_asc, privs[i].priv))
		i++;
	
	if (privs[i].se_priv!=SE_PRIV_ALL) {
		DEBUG(10,(": %s\n", privs[i].description));
		init_uni_hdr(&r_u->hdr_desc, strlen(privs[i].description));
		init_unistr2(&r_u->desc, privs[i].description, strlen(privs[i].description) );

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
	GROUP_MAP *map=NULL;
	int num_entries=0;
	LSA_SID_ENUM *sids=&r_u->sids;
	int i=0,j=0;

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	/* get the list of mapped groups (domain, local, builtin) */
	if(!enum_group_mapping(SID_NAME_UNKNOWN, &map, &num_entries, ENUM_ONLY_MAPPED))
		return NT_STATUS_OK;

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
 For a given SID, enumerate all the privilege this account has.
 ***************************************************************************/

NTSTATUS _lsa_enum_privsaccount(pipes_struct *p, LSA_Q_ENUMPRIVSACCOUNT *q_u, LSA_R_ENUMPRIVSACCOUNT *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	int i=0;

	LUID_ATTR *set=NULL;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!get_group_map_from_sid(info->sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	DEBUG(10,("_lsa_enum_privsaccount: %d privileges\n", map.priv_set.count));
	if (map.priv_set.count!=0) {
	
		set=(LUID_ATTR *)talloc(p->mem_ctx, map.priv_set.count*sizeof(LUID_ATTR));
		if (set == NULL) {
			free_privilege(&map.priv_set);	
			return NT_STATUS_NO_MEMORY;
		}

		for (i=0; i<map.priv_set.count; i++) {
			set[i].luid.low=map.priv_set.set[i].luid.low;
			set[i].luid.high=map.priv_set.set[i].luid.high;
			set[i].attr=map.priv_set.set[i].attr;
			DEBUG(10,("_lsa_enum_privsaccount: priv %d: %d:%d:%d\n", i, 
				   set[i].luid.high, set[i].luid.low, set[i].attr));
		}
	}

	init_lsa_r_enum_privsaccount(r_u, set, map.priv_set.count, 0);	
	free_privilege(&map.priv_set);	

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

	if (!get_group_map_from_sid(info->sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	/*
	  0x01 -> Log on locally
	  0x02 -> Access this computer from network
	  0x04 -> Log on as a batch job
	  0x10 -> Log on as a service
	  
	  they can be ORed together
	*/

	r_u->access=map.systemaccount;

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

	if (!get_group_map_from_sid(info->sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	map.systemaccount=q_u->access;

	if(!add_mapping_entry(&map, TDB_REPLACE))
		return NT_STATUS_NO_SUCH_GROUP;

	return r_u->status;
}

/***************************************************************************
 For a given SID, add some privileges.
 ***************************************************************************/

NTSTATUS _lsa_addprivs(pipes_struct *p, LSA_Q_ADDPRIVS *q_u, LSA_R_ADDPRIVS *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	int i=0;

	LUID_ATTR *luid_attr=NULL;
	PRIVILEGE_SET *set=NULL;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!get_group_map_from_sid(info->sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	set=&q_u->set;

	for (i=0; i<set->count; i++) {
		luid_attr=&set->set[i];
		
		/* check if the privilege is already there */
		if (check_priv_in_privilege(&map.priv_set, *luid_attr)){
			free_privilege(&map.priv_set);
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		
		add_privilege(&map.priv_set, *luid_attr);
	}

	if(!add_mapping_entry(&map, TDB_REPLACE))
		return NT_STATUS_NO_SUCH_GROUP;
	
	free_privilege(&map.priv_set);	

	return r_u->status;
}

/***************************************************************************
 For a given SID, remove some privileges.
 ***************************************************************************/

NTSTATUS _lsa_removeprivs(pipes_struct *p, LSA_Q_REMOVEPRIVS *q_u, LSA_R_REMOVEPRIVS *r_u)
{
	struct lsa_info *info=NULL;
	GROUP_MAP map;
	int i=0;

	LUID_ATTR *luid_attr=NULL;
	PRIVILEGE_SET *set=NULL;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!get_group_map_from_sid(info->sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	if (q_u->allrights!=0) {
		/* log it and return, until I see one myself don't do anything */
		DEBUG(5,("_lsa_removeprivs: trying to remove all privileges ?\n"));
		return NT_STATUS_OK;
	}

	if (q_u->ptr==0) {
		/* log it and return, until I see one myself don't do anything */
		DEBUG(5,("_lsa_removeprivs: no privileges to remove ?\n"));
		return NT_STATUS_OK;
	}

	set=&q_u->set;

	for (i=0; i<set->count; i++) {
		luid_attr=&set->set[i];
		
		/* if we don't have the privilege, we're trying to remove, give up */
		/* what else can we do ??? JFM. */
		if (!check_priv_in_privilege(&map.priv_set, *luid_attr)){
			free_privilege(&map.priv_set);
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		
		remove_privilege(&map.priv_set, *luid_attr);
	}

	if(!add_mapping_entry(&map, TDB_REPLACE))
		return NT_STATUS_NO_SUCH_GROUP;
	
	free_privilege(&map.priv_set);	

	return r_u->status;
}

