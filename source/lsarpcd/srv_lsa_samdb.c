
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jeremy Allison               1998-2000.
 *  Copyright (C) Elrond                            2000.
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
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

/****************************************************************************
 set secret tdb database
****************************************************************************/
static BOOL set_tdbsecdb(struct policy_cache *cache, POLICY_HND *hnd,
				TDB_CONTEXT *tdb)
{
	if (tdb != NULL)
	{
		if (set_policy_state(cache, hnd, tdb_close, (void*)tdb))
		{
			return True;
		}
		tdb_close(tdb);
		return False;
	}
	DEBUG(3,("Error setting policy secret database\n"));
	return False;
}

/****************************************************************************
  get tdb database handle
****************************************************************************/
static BOOL get_tdbsecdb(struct policy_cache *cache, const POLICY_HND *hnd,
				TDB_CONTEXT **tdb)
{
	(*tdb) = (TDB_CONTEXT*)get_policy_state_info(cache, hnd);

	return True;
}

typedef struct tdb_sec_info
{
	UNISTR2 name;
	TDB_CONTEXT *tdb;

} TDB_SEC_INFO;

static void secnamefree(void*inf)
{
	TDB_SEC_INFO *dev = (TDB_SEC_INFO*)inf;
	if (dev != NULL)
	{
		tdb_close(dev->tdb);
	}
	safe_free(dev);
}

/****************************************************************************
  set tdb secret name
****************************************************************************/
BOOL set_tdbsecname(struct policy_cache *cache, POLICY_HND *hnd,
				TDB_CONTEXT *tdb,
				const UNISTR2 *name)
{
	TDB_SEC_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		copy_unistr2(&dev->name, name);
		dev->tdb = tdb;
		if (set_policy_state(cache, hnd, secnamefree, (void*)dev))
		{
			if (DEBUGLVL(3))
			{
				fstring tmp;
				unistr2_to_ascii(tmp, name, sizeof(tmp)-1);
				DEBUG(3,("setting tdb secret name=%s\n", tmp));
			}
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3,("Error setting tdb secret name\n"));
	return False;
}

/****************************************************************************
  get tdb secret name
****************************************************************************/
BOOL get_tdbsecname(struct policy_cache *cache, const POLICY_HND *hnd,
				TDB_CONTEXT **tdb,
				UNISTR2 *name)
{
	TDB_SEC_INFO *dev = (TDB_SEC_INFO*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		if (name != NULL)
		{
			copy_unistr2(name, &dev->name);
		}
		if (tdb != NULL)
		{
			(*tdb) = dev->tdb;
		}
		return True;
	}

	DEBUG(3,("Error getting policy rid\n"));
	return False;
}
/***************************************************************************
lsa_reply_open_policy2
 ***************************************************************************/
uint32 _lsa_open_policy2(const UNISTR2 *server_name, POLICY_HND *hnd,
				const LSA_OBJ_ATTR *attr,
				uint32 des_access)
{
	if (hnd == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), hnd, des_access))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
lsa_reply_open_policy
 ***************************************************************************/
uint32 _lsa_open_policy(const UNISTR2 *server_name, POLICY_HND *hnd,
				const LSA_OBJ_ATTR *attr,
				uint32 des_access)
{
	if (hnd == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), hnd, des_access))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
_lsa_enum_trust_dom
 ***************************************************************************/
uint32 _lsa_enum_trust_dom(POLICY_HND *hnd, uint32 *enum_ctx,
			   uint32 *num_doms, UNISTR2 **uni_names,
			   DOM_SID ***sids)
{
	/* Should send on something good */
	
	*enum_ctx = 0;
	*num_doms = 0;
	*uni_names = NULL;
	*sids = NULL;

	return 0x80000000 | NT_STATUS_UNABLE_TO_FREE_VM;
}

/***************************************************************************
make_lsa_rid2s
 ***************************************************************************/
static uint32 get_remote_sid(const char *dom_name, char *find_name,
			     DOM_SID *sid, uint32 *rid, uint32 *sid_name_use)
{
	fstring srv_name;
	fstring dummy;
	uint32 status;

	DEBUG(10, ("lookup remote name: %s %s\n",
	           dom_name, find_name));

	if (! get_any_dc_name(dom_name, srv_name))
	{
		return NT_STATUS_NONE_MAPPED;
	}
	if (strequal(srv_name, "\\\\."))
	{
		DEBUG(0, ("WARNING: infinite loop in lsarpcd !\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	status = lookup_lsa_name(dom_name, find_name,
				 sid, sid_name_use);

	if (status == NT_STATUS_NOPROBLEMO &&
	   (!sid_split_rid(sid, rid) ||
	    !map_domain_sid_to_name(sid, dummy)))
	{
		status = NT_STATUS_NONE_MAPPED;
	}
	return status;
}

static void make_lsa_rid2s(DOM_R_REF *ref,
				DOM_RID2 *rid2,
				int num_entries, UNISTR2 name[MAX_LOOKUP_SIDS],
				uint32 *mapped_count)
{
	int i;
	int total = 0;
	(*mapped_count) = 0;

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	for (i = 0; i < num_entries; i++)
	{
		uint32 status = NT_STATUS_NOPROBLEMO;
		DOM_SID find_sid;
		DOM_SID sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		char *find_name = NULL;
		fstring dom_name;
		fstring full_name;
		uint32 sid_name_use = SID_NAME_UNKNOWN;

		unistr2_to_ascii(full_name, &name[i], sizeof(full_name)-1);
		find_name = strdup(full_name);

		if (!split_domain_name(full_name, dom_name, find_name))
		{
			status = NT_STATUS_NONE_MAPPED;
		}
		if (status == NT_STATUS_NOPROBLEMO && map_domain_name_to_sid(&find_sid,
		                                            &find_name))
		{
			sid_name_use = SID_NAME_DOMAIN;
			dom_idx = make_dom_ref(ref, dom_name, &find_sid);
			rid = 0xffffffff;
			sid_copy(&sid, &find_sid);
		}
		else if (status == NT_STATUS_NOPROBLEMO)
		{
			uint32 ret;
			ret = lookup_sam_domainname("\\\\.",
						    dom_name, &find_sid);

			if (ret == NT_STATUS_NOPROBLEMO)
			{
				pstring tmp;
				sid_to_string(tmp, &find_sid);
				DEBUG(10,("lookup sam name: %s %s\n",
				           tmp, find_name));
				status = lookup_sam_name(NULL,
				                         &find_sid,
				                         find_name,
							 &rid, &sid_name_use);
				sid_copy(&sid, &find_sid);
			}
			else
			{
				status = get_remote_sid(dom_name, find_name,
							&sid, &rid,
							&sid_name_use);
			}
		}

		if (status == NT_STATUS_NOPROBLEMO)
		{
			dom_idx = make_dom_ref(ref, find_name, &sid);
		}

		if (status == NT_STATUS_NOPROBLEMO)
		{
			(*mapped_count)++;
		}
		else
		{
			dom_idx = -1;
			rid = 0xffffffff;
			sid_name_use = SID_NAME_UNKNOWN;
		}

		make_dom_rid2(&rid2[total], rid, sid_name_use, dom_idx);
		total++;

		if (find_name != NULL)
		{
			free(find_name);
		}
	}
}

/***************************************************************************
make_reply_lookup_names
 ***************************************************************************/
static void make_reply_lookup_names(LSA_R_LOOKUP_NAMES *r_l,
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
	{
		r_l->status = NT_STATUS_NONE_MAPPED;
	}
	else
	{
		r_l->status = NT_STATUS_NOPROBLEMO;
	}
}

/***************************************************************************
_lsa_lookup_sids
 ***************************************************************************/
uint32 _lsa_lookup_sids(const POLICY_HND *hnd,
			uint32 num_entries, DOM_SID2 *sid,
			const LOOKUP_LEVEL *level,
			DOM_R_REF *ref,
			LSA_TRANS_NAME_ENUM *trn,
			uint32 *mapped_count)
{
	int i;
	int total = 0;
	uint32 status = 0x0;

	(*mapped_count) = 0;

	if (find_policy_by_hnd(get_global_hnd_cache(), hnd) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	for (i = 0; i < num_entries; i++)
	{
		uint32 status1 = NT_STATUS_NOPROBLEMO;
		DOM_SID find_sid = sid[i].sid;
		DOM_SID tmp_sid  = sid[i].sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		fstring name;
		fstring dom_name;
		uint32 sid_name_use = 0;
		
		memset(dom_name, 0, sizeof(dom_name));
		memset(name    , 0, sizeof(name    ));

		if (map_domain_sid_to_name(&find_sid, dom_name))
		{
			sid_name_use = SID_NAME_DOMAIN;
			name[0] = 0;
		}
		else if (sid_split_rid         (&find_sid, &rid) &&
			 map_domain_sid_to_name(&find_sid, dom_name))
		{
			if (sid_equal(&find_sid, &global_sam_sid) ||
			    sid_equal(&find_sid, &global_sid_S_1_5_20))
			{
				status1 = lookup_sam_rid(dom_name,
				             &find_sid, rid,
				             name, &sid_name_use);
			}
			else
			{
				status1 = lookup_lsa_sid(dom_name,
				             &tmp_sid,
				             name, &sid_name_use);
			}
		}
		else
		{
			status1 = NT_STATUS_NONE_MAPPED;
		}

		dom_idx = make_dom_ref(ref, dom_name, &find_sid);

		if (status1 == NT_STATUS_NOPROBLEMO)
		{
			(*mapped_count)++;
		}
		else
		{
			snprintf(name, sizeof(name), "%08x", rid);
			sid_name_use = SID_NAME_UNKNOWN;
		}
		make_lsa_trans_name(&(trn->name    [total]),
		                    &(trn->uni_name[total]),
		                    sid_name_use, name, dom_idx);
		total++;
	}

	trn->num_entries = total;
	trn->ptr_trans_names = 1;
	trn->num_entries2 = total;

	if ((status == 0x0) && ((*mapped_count) == 0))
	{
		status = NT_STATUS_NONE_MAPPED;
	}

	return status;
}

/***************************************************************************
lsa_reply_lookup_names
 ***************************************************************************/
static void lsa_reply_lookup_names(prs_struct *rdata,
				UNISTR2 names[MAX_LOOKUP_SIDS], int num_entries)
{
	LSA_R_LOOKUP_NAMES r_l;
	DOM_R_REF ref;
	DOM_RID2 rids[MAX_LOOKUP_SIDS];
	uint32 mapped_count = 0;

	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	ZERO_STRUCT(rids);

	/* set up the LSA Lookup RIDs response */
	make_lsa_rid2s(&ref, rids, num_entries, names, &mapped_count);
	make_reply_lookup_names(&r_l, &ref, num_entries, rids, mapped_count);

	/* store the response in the SMB stream */
	lsa_io_r_lookup_names("", &r_l, rdata, 0);
}

/***************************************************************************
_lsa_query_info
 ***************************************************************************/
uint32 _lsa_query_info_pol(POLICY_HND *hnd, uint16 info_class,
			   fstring domain_name, DOM_SID *domain_sid)
{
	fstring name;
	uint32 status = NT_STATUS_NOPROBLEMO;
	const DOM_SID *sid = NULL;

	memset(name, 0, sizeof(name));

	if (find_policy_by_hnd(get_global_hnd_cache(), hnd) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (info_class)
	{
		case 0x03:
		{
			extern pstring global_myworkgroup;
			fstrcpy(name, global_myworkgroup);
			sid = &global_member_sid;
			break;
		}
		case 0x05:
		{
			fstrcpy(name, global_sam_name);
			sid = &global_sam_sid;
			break;
		}
		default:
		{
			DEBUG(3, ("unknown info level in Lsa Query: %d\n",
			          info_class));
			status = NT_STATUS_INVALID_INFO_CLASS;
		}
	}
	if (domain_sid && sid)
	{
		sid_copy(domain_sid, sid);
	}
	if (domain_name)
	{
		fstrcpy(domain_name, name);
	}

	return status;
}

/***************************************************************************
_lsa_lookup_names
 ***************************************************************************/
static void _lsa_lookup_names( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata )
{
	LSA_Q_LOOKUP_NAMES q_l;
	ZERO_STRUCT(q_l);

	/* grab the info class and policy handle */
	lsa_io_q_lookup_names("", &q_l, data, 0);

	SMB_ASSERT_ARRAY(q_l.uni_name, q_l.num_entries);

	lsa_reply_lookup_names(rdata, q_l.uni_name, q_l.num_entries);
}

/***************************************************************************
_lsa_close
 ***************************************************************************/
uint32 _lsa_close(POLICY_HND *hnd)
{
	if (!close_policy_hnd(get_global_hnd_cache(), hnd))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
 _lsa_query_secret
 ***************************************************************************/
uint32 _lsa_query_secret(const POLICY_HND *hnd_secret,
				STRING2 *curval, NTTIME *curtime,
				STRING2 *oldval, NTTIME *oldtime)
{
	TDB_CONTEXT *tdb = NULL;
	UNISTR2 secret_name;
	LSA_SECRET *sec = NULL;
	uchar user_sess_key[16];

	if (!pol_get_usr_sesskey(get_global_hnd_cache(), hnd_secret,
	                         user_sess_key))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	dump_data_pw("sess_key:", user_sess_key, 16);

	ZERO_STRUCT(sec);
	ZERO_STRUCT(secret_name);

	if (!get_tdbsecname(get_global_hnd_cache(), hnd_secret, &tdb,
	                    &secret_name))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!tdb_lookup_secret(tdb, &secret_name, &sec))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (sec == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}
		
	if (curtime != NULL)
	{
		(*curtime) = sec->curinfo.last_update;
	}
	if (oldtime != NULL)
	{
		(*oldtime) = sec->oldinfo.last_update;
	}
	if (curval != NULL)
	{
		if (!nt_encrypt_string2(curval, &sec->curinfo.value.enc_secret,
		                        user_sess_key))
		{
			safe_free(sec);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (oldval != NULL)
	{
		if (!nt_encrypt_string2(oldval, &sec->oldinfo.value.enc_secret,
		                        user_sess_key))
		{
			safe_free(sec);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	safe_free(sec);
	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
 _lsa_create_secret
 ***************************************************************************/
uint32 _lsa_create_secret(const POLICY_HND *hnd,
			const UNISTR2 *secret_name, uint32 des_access,
			POLICY_HND *hnd_secret)
{
	TDB_CONTEXT *tdb;
	LSA_SECRET sec;
	NTTIME ntt;

	ZERO_STRUCT(sec);

	tdb = open_secret_db(O_RDWR);
	if (tdb == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (tdb_lookup_secret(tdb, secret_name, NULL))
	{
		DEBUG(10,("_lsa_create_secret: secret exists\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
		hnd, hnd_secret, des_access))
	{
		tdb_close(tdb);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!set_tdbsecname(get_global_hnd_cache(), hnd_secret, tdb, secret_name))
	{
		close_policy_hnd(get_global_hnd_cache(), hnd_secret);
		return NT_STATUS_ACCESS_DENIED;
	}

	unix_to_nt_time(&ntt, time(NULL));

	sec.curinfo.ptr_update = 1;
	sec.curinfo.last_update = ntt;

	sec.oldinfo.ptr_update = 1;
	sec.oldinfo.last_update = ntt;

	if (!tdb_store_secret(tdb, secret_name, &sec))
	{
		close_policy_hnd(get_global_hnd_cache(), hnd_secret);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
 _lsa_open_secret
 ***************************************************************************/
uint32 _lsa_open_secret(const POLICY_HND *hnd,
			const UNISTR2 *secret_name, uint32 des_access,
			POLICY_HND *hnd_secret)
{
	TDB_CONTEXT *tdb;

	tdb = open_secret_db(O_RDWR);
	if (tdb == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!tdb_lookup_secret(tdb, secret_name, NULL))
	{
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
		hnd, hnd_secret, des_access))
	{
		tdb_close(tdb);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!set_tdbsecname(get_global_hnd_cache(), hnd_secret, tdb, secret_name))
	{
		close_policy_hnd(get_global_hnd_cache(), hnd_secret);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}
