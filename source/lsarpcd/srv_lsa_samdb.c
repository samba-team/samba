
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
#include "rpc_client.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

/****************************************************************************
 set secret tdb database
****************************************************************************/
static BOOL set_tdbsecdb(struct policy_cache *cache, POLICY_HND * hnd,
			 TDB_CONTEXT * tdb)
{
	if (tdb != NULL)
	{
		if (set_policy_state(cache, hnd, tdb_close, (void *)tdb))
		{
			return True;
		}
		tdb_close(tdb);
		return False;
	}
	DEBUG(3, ("Error setting policy secret database\n"));
	return False;
}

/****************************************************************************
  get tdb database handle
****************************************************************************/
static BOOL get_tdbsecdb(struct policy_cache *cache, const POLICY_HND * hnd,
			 TDB_CONTEXT ** tdb)
{
	(*tdb) = (TDB_CONTEXT *) get_policy_state_info(cache, hnd);

	return True;
}

typedef struct tdb_sec_info
{
	UNISTR2 name;
	TDB_CONTEXT *tdb;

}
TDB_SEC_INFO;

static void secnamefree(void *inf)
{
	TDB_SEC_INFO *dev = (TDB_SEC_INFO *) inf;
	if (dev != NULL)
	{
		tdb_close(dev->tdb);
	}
	safe_free(dev);
}

/****************************************************************************
  set tdb secret name
****************************************************************************/
static BOOL set_tdbsecname(struct policy_cache *cache, POLICY_HND * hnd,
			   TDB_CONTEXT * tdb, const UNISTR2 * name)
{
	TDB_SEC_INFO *dev = malloc(sizeof(*dev));

	if (dev != NULL)
	{
		copy_unistr2(&dev->name, name);
		dev->tdb = tdb;
		if (set_policy_state(cache, hnd, secnamefree, (void *)dev))
		{
			if (DEBUGLVL(3))
			{
				fstring tmp;
				unistr2_to_ascii(tmp, name, sizeof(tmp) - 1);
				DEBUG(3,
				      ("setting tdb secret name=%s\n", tmp));
			}
			return True;
		}
		free(dev);
		return False;
	}
	DEBUG(3, ("Error setting tdb secret name\n"));
	return False;
}

/****************************************************************************
  get tdb secret name
****************************************************************************/
static BOOL get_tdbsecname(struct policy_cache *cache, const POLICY_HND * hnd,
			   TDB_CONTEXT ** tdb, UNISTR2 * name)
{
	TDB_SEC_INFO *dev =
		(TDB_SEC_INFO *) get_policy_state_info(cache, hnd);

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

	DEBUG(3, ("Error getting policy rid\n"));
	return False;
}

/***************************************************************************
lsa_reply_open_policy2
 ***************************************************************************/
uint32 _lsa_open_policy2(const UNISTR2 * server_name, POLICY_HND * hnd,
			 const LSA_OBJ_ATTR * attr, uint32 des_access)
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

	policy_hnd_set_name(get_global_hnd_cache(), hnd, "open_policy2");

	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
lsa_reply_open_policy
 ***************************************************************************/
uint32 _lsa_open_policy(const UNISTR2 * server_name, POLICY_HND * hnd,
			const LSA_OBJ_ATTR * attr, uint32 des_access)
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

	policy_hnd_set_name(get_global_hnd_cache(), hnd, "open_policy");

	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
_lsa_enum_trust_dom
 ***************************************************************************/
uint32 _lsa_enum_trust_dom(POLICY_HND * hnd, uint32 * enum_ctx,
			   uint32 * num_doms, UNISTR2 ** uni_names,
			   DOM_SID *** sids)
{
	/* Should send on something good */

	*enum_ctx = 0;
	*num_doms = 0;
	*uni_names = NULL;
	*sids = NULL;

	return 0x80000000 | NT_STATUS_UNABLE_TO_FREE_VM;
}

/***************************************************************************
_lsa_lookup_names
 ***************************************************************************/
static uint32 get_remote_sid(const char *dom_name, char *find_name,
			     DOM_SID * sid, uint32 * rid,
			     uint32 * sid_name_use)
{
	fstring srv_name;
	fstring dummy;
	uint32 status;

	DEBUG(10, ("lookup remote name: %s %s\n", dom_name, find_name));

	if (!get_any_dc_name(dom_name, srv_name))
	{
		return NT_STATUS_NONE_MAPPED;
	}
	if (strequal(srv_name, "\\\\."))
	{
		DEBUG(0, ("WARNING: infinite loop in lsarpcd !\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	status = lookup_lsa_name(dom_name, find_name, sid, sid_name_use);

	if (status == NT_STATUS_NOPROBLEMO &&
	    (!sid_split_rid(sid, rid) || !map_domain_sid_to_name(sid, dummy)))
	{
		status = NT_STATUS_NONE_MAPPED;
	}
	return status;
}

uint32 _lsa_lookup_names(const POLICY_HND * pol,
			 uint32 num_entries, const UNISTR2 * name,
			 DOM_R_REF * ref, DOM_RID2 ** ret_rid2,
			 uint32 * mapped_count)
{
	int i;
	int total = 0;
	DOM_RID2 *rid2;

	(*mapped_count) = 0;

	rid2 = g_new(DOM_RID2, num_entries);
	(*ret_rid2) = rid2;

	for (i = 0; i < num_entries; i++)
	{
		uint32 status1 = NT_STATUS_NOPROBLEMO;
		DOM_SID find_sid;
		DOM_SID sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		char *find_name = NULL;
		fstring dom_name;
		fstring full_name;
		uint32 sid_name_use = SID_NAME_UNKNOWN;

		unistr2_to_ascii(full_name, &name[i], sizeof(full_name) - 1);
		find_name = strdup(full_name);

		if (!split_domain_name(full_name, dom_name, find_name))
		{
			status1 = NT_STATUS_NONE_MAPPED;
		}
		if (status1 == NT_STATUS_NOPROBLEMO
		    && map_domain_name_to_sid(&find_sid, &find_name))
		{
			sid_name_use = SID_NAME_DOMAIN;
			dom_idx = make_dom_ref(ref, dom_name, &find_sid);
			rid = 0xffffffff;
			sid_copy(&sid, &find_sid);
		}
		else if (status1 == NT_STATUS_NOPROBLEMO)
		{
			uint32 ret;
			ret = lookup_sam_domainname("\\\\.",
						    dom_name, &find_sid);

			if (ret == NT_STATUS_NOPROBLEMO)
			{
				pstring tmp;
				sid_to_string(tmp, &find_sid);
				DEBUG(10, ("lookup sam name: %s %s\n",
					   tmp, find_name));
				status1 = lookup_sam_name(NULL,
							  &find_sid,
							  find_name,
							  &rid,
							  &sid_name_use);
				sid_copy(&sid, &find_sid);
			}
			else
			{
				status1 = get_remote_sid(dom_name, find_name,
							 &sid, &rid,
							 &sid_name_use);
			}
		}

		if (status1 == NT_STATUS_NOPROBLEMO)
		{
			dom_idx = make_dom_ref(ref, find_name, &sid);
		}

		if (status1 == NT_STATUS_NOPROBLEMO)
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

	if ((*mapped_count) == 0)
	{
		return NT_STATUS_NONE_MAPPED;
	}
	else
	{
		return NT_STATUS_NOPROBLEMO;
	}
}

/***************************************************************************
_lsa_lookup_sids
 ***************************************************************************/
uint32 _lsa_lookup_sids(const POLICY_HND * hnd,
			uint32 num_entries, DOM_SID2 * sid,
			const LOOKUP_LEVEL * level,
			DOM_R_REF * ref,
			LSA_TRANS_NAME_ENUM * trn, uint32 * mapped_count)
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
		DOM_SID tmp_sid = sid[i].sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		fstring name;
		fstring dom_name;
		uint32 sid_name_use = 0;

		memset(dom_name, 0, sizeof(dom_name));
		memset(name, 0, sizeof(name));

		if (map_wk_sid_to_name(&find_sid, dom_name, &sid_name_use))
		{
			/*
			 * it is currently better to put
			 * the name also here
			 */
			fstrcpy(name, dom_name);
			if (sid_name_use == SID_NAME_WKN_GRP)
			{
				sid_split_rid(&find_sid, &rid);
				dom_name[0] = 0;
				map_domain_sid_to_name(&find_sid, dom_name);
			}
		}
		else if (sid_split_rid(&find_sid, &rid) &&
			 map_domain_sid_to_name(&find_sid, dom_name))
		{
			if (sid_equal(&find_sid, &global_sam_sid) ||
			    sid_equal(&find_sid, global_sid_builtin))
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
		make_lsa_trans_name(&(trn->name[total]),
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
make_dom_query
 ***************************************************************************/
static void make_dom_query(DOM_QUERY *d_q, const char *dom_name,
			   const DOM_SID *dom_sid)
{
	fstring sid_str;
	int domlen = strlen(dom_name);

	d_q->uni_dom_str_len = (domlen + 1) * 2;
	d_q->uni_dom_max_len = domlen * 2;

	d_q->buffer_dom_name = domlen != 0 ? 1 : 0;	/* domain buffer pointer */
	d_q->buffer_dom_sid = dom_sid != NULL ? 1 : 0;	/* domain sid pointer */

	/* this string is supposed to be character short */
	make_unistr2(&(d_q->uni_domain_name), dom_name, domlen);
	d_q->uni_domain_name.uni_max_len++;

	sid_to_string(sid_str, dom_sid);
	make_dom_sid2(&(d_q->dom_sid), dom_sid);
}


/***************************************************************************
_lsa_query_info
 ***************************************************************************/
uint32 _lsa_query_info_pol(POLICY_HND * hnd, uint16 info_class,
			   LSA_INFO_UNION *info)
{
	uint32 status = NT_STATUS_NOPROBLEMO;

	if (find_policy_by_hnd(get_global_hnd_cache(), hnd) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (info_class)
	{
		case 0x02:
		{
			unsigned int i;
			/* fake info: We audit everything. ;) */
			info->id2.auditing_enabled = 1;
			info->id2.count1 = 7;
			info->id2.count2 = 7;
			info->id2.auditsettings = g_new(uint32, 7);
			for (i = 0; i < 7; i++)
				info->id2.auditsettings[i] = 3;
			break;
		}
		case 0x03:
		{
			extern fstring global_myworkgroup;
			make_dom_query(&info->id3, global_myworkgroup,
				       &global_member_sid);
			break;
		}
		case 0x05:
		{
			make_dom_query(&info->id3, global_sam_name,
				       &global_sam_sid);
			break;
		}
		default:
		{
			DEBUG(3, ("unknown info level in Lsa Query: %d\n",
				  info_class));
			status = NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return status;
}

/***************************************************************************
_lsa_close
 ***************************************************************************/
uint32 _lsa_close(POLICY_HND * hnd)
{
	if (!close_policy_hnd(get_global_hnd_cache(), hnd))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
 _lsa_set_secret
 ***************************************************************************/
uint32 _lsa_set_secret(const POLICY_HND * hnd_secret,
		       const STRING2 * val, uint32 unknown)
{
	TDB_CONTEXT *tdb = NULL;
	UNISTR2 secret_name;
	LSA_SECRET *sec = NULL;
	uchar user_sess_key[16];
	NTTIME ntt;

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

	if (tdb_writelock(tdb) != 0)
	{
		DEBUG(10, ("_lsa_set_secret: write lock denied\n"));
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

	/* store old info */
	memcpy(&sec->oldinfo, &sec->curinfo, sizeof(sec->oldinfo));

	/* decode and store new value, update time */
	if (!nt_decrypt_string2(&sec->curinfo.value.enc_secret, val,
				user_sess_key))
	{
		safe_free(sec);
		return NT_STATUS_INVALID_PARAMETER;
	}
	else
	{
		sec->curinfo.ptr_value = 1;
		make_strhdr2(&sec->curinfo.value.hdr_secret,
			     sec->curinfo.value.enc_secret.str_max_len,
			     sec->curinfo.value.enc_secret.str_str_len, 1);
		sec->curinfo.value.ptr_secret = 1;
	}

	unix_to_nt_time(&ntt, time(NULL));
	sec->curinfo.ptr_update = 1;
	sec->curinfo.last_update = ntt;

	/* store new secret */
	if (!tdb_store_secret(tdb, &secret_name, sec))
	{
		safe_free(sec);
		return NT_STATUS_ACCESS_DENIED;
	}

	tdb_writeunlock(tdb);

	safe_free(sec);
	return NT_STATUS_NOPROBLEMO;
}

/***************************************************************************
 _lsa_query_secret
 ***************************************************************************/
uint32 _lsa_query_secret(const POLICY_HND * hnd_secret,
			 STRING2 * curval, NTTIME * curtime,
			 STRING2 * oldval, NTTIME * oldtime)
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
		if (!nt_encrypt_string2(curval,
					&sec->curinfo.value.enc_secret,
					user_sess_key))
		{
			safe_free(sec);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (oldval != NULL)
	{
		if (!nt_encrypt_string2(oldval,
					&sec->oldinfo.value.enc_secret,
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
uint32 _lsa_create_secret(const POLICY_HND * hnd,
			  const UNISTR2 * secret_name, uint32 des_access,
			  POLICY_HND * hnd_secret)
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
		DEBUG(10, ("_lsa_create_secret: secret exists\n"));
		/* XXX - shouldn't tdb be closed here? (Elrond) */
		return NT_STATUS_ACCESS_DENIED;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
				  hnd, hnd_secret, des_access))
	{
		tdb_close(tdb);
		return NT_STATUS_ACCESS_DENIED;
	}

	policy_hnd_set_name(get_global_hnd_cache(),
			    hnd_secret, "secret (create)");

	if (!set_tdbsecname(get_global_hnd_cache(),
			    hnd_secret, tdb, secret_name))
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
uint32 _lsa_open_secret(const POLICY_HND * hnd,
			const UNISTR2 * secret_name, uint32 des_access,
			POLICY_HND * hnd_secret)
{
	TDB_CONTEXT *tdb;

	tdb = open_secret_db(O_RDWR);
	if (tdb == NULL)
	{
		DEBUG(0,
		      ("_lsa_open_secret: couldn't open secret_db. Possible attack?"));
		DEBUG(0,
		      ("\nuid=%d, gid=%d, euid=%d, egid=%d\n", (int)getuid(),
		       (int)getgid(), (int)geteuid(), (int)getegid()));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!tdb_lookup_secret(tdb, secret_name, NULL))
	{
		/* XXX - shouldn't tdb be closed here? (Elrond) */
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
				  hnd, hnd_secret, des_access))
	{
		tdb_close(tdb);
		return NT_STATUS_ACCESS_DENIED;
	}

	policy_hnd_set_name(get_global_hnd_cache(),
			    hnd_secret, "secret (open)");

	if (!set_tdbsecname(get_global_hnd_cache(),
			    hnd_secret, tdb, secret_name))
	{
		close_policy_hnd(get_global_hnd_cache(), hnd_secret);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

#define LSA_NUM_PRIVS 23
static const struct privs
{
	uint32 num;
	const char *name;
} privs[LSA_NUM_PRIVS+1] = {
	{  2, "SeCreateTokenPrivilege" },
	{  3, "SeAssignPrimaryTokenPrivilege" },
	{  4, "SeLockMemoryPrivilege" },
	{  5, "SeIncreaseQuotaPrivilege" },
	{  6, "SeMachineAccountPrivilege" },
	{  7, "SeTcbPrivilege" },
	{  8, "SeSecurityPrivilege" },
	{  9, "SeTakeOwnershipPrivilege" },
	{ 10, "SeLoadDriverPrivilege" },
	{ 11, "SeSystemProfilePrivilege" },
	{ 12, "SeSystemtimePrivilege" },
	{ 13, "SeProfileSingleProcessPrivilege" },
	{ 14, "SeIncreaseBasePriorityPrivilege" },
	{ 15, "SeCreatePagefilePrivilege" },
	{ 16, "SeCreatePermanentPrivilege" },
	{ 17, "SeBackupPrivilege" },
	{ 18, "SeRestorePrivilege" },
	{ 19, "SeShutdownPrivilege" },
	{ 20, "SeDebugPrivilege" },
	{ 21, "SeAuditPrivilege" },
	{ 22, "SeSystemEnvironmentPrivilege" },
	{ 23, "SeChangeNotifyPrivilege" },
	{ 24, "SeRemoteShutdownPrivilege" },
	{  0, NULL }
};

uint32 _lsa_enum_privs(POLICY_HND *hnd, uint32 unk0, uint32 unk1,
		       uint32 *count, LSA_PRIV_ENTRY **entries)
{
	uint32 i;
	LSA_PRIV_ENTRY *entry;

	if (hnd == NULL || count == NULL || entries == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	if (unk0 == 0x17)
		/* no idea at all, what's happening here */
		return NT_STATUS_UNABLE_TO_FREE_VM;

	if (unk0 != 0)
		return NT_STATUS_INVALID_INFO_CLASS;

	if (find_policy_by_hnd(get_global_hnd_cache(), hnd) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	(*entries) = g_new(LSA_PRIV_ENTRY, LSA_NUM_PRIVS);
	if (! *entries)
		return NT_STATUS_NO_MEMORY;

	*count = LSA_NUM_PRIVS;

	entry = *entries;
	for (i = 0; privs[i].name && i < LSA_NUM_PRIVS; i++, entry++)
	{
		unistr2_assign_ascii_str(&entry->name, privs[i].name);
		entry->luid_low = privs[i].num;
		entry->luid_high = 0;
	}

	return NT_STATUS_NOPROBLEMO;
}

uint32 _lsa_priv_get_dispname(const POLICY_HND *hnd,
			      const UNISTR2 *name,
			      uint16 lang_id, uint16 lang_id_sys,
			      UNISTR2 **desc, uint16 *ret_lang_id)
{
	char *name_asc;
	fstring desc_asc;
	if (hnd == NULL || name == NULL || desc == NULL || ret_lang_id == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	name_asc = unistr2_to_ascii(NULL, name, 0);

	fstrcpy(desc_asc, "Privilege ");
	fstrcat(desc_asc, name_asc);
	safe_free(name_asc);

	(*desc) = unistr2_new(desc_asc);
	(*ret_lang_id) = 0x0;

	return NT_STATUS_NOPROBLEMO;
}
