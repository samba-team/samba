/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker               2000
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
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

typedef struct sam_data_info
{
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;
	uint32 num_sam_entries;
	uint32 start_idx;
	uint32 current_idx;;

} SAM_DATA;

/******************************************************************
makes a SAMR_R_ENUM_DOMAINS structure.
********************************************************************/
static int tdb_domain_traverse(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	prs_struct key;
	UNISTR2 *str;
	SAM_DATA *data = (SAM_DATA*)state;
	uint32 num_sam_entries = data->num_sam_entries + 1;
	SAM_ENTRY *sam;

	DEBUG(5,("tdb_domain_traverse: idx: %d %d\n",
					data->current_idx,
					num_sam_entries));

	dump_data_pw("sid:\n"   , dbuf.dptr, dbuf.dsize);
	dump_data_pw("domain:\n", kbuf.dptr, kbuf.dsize);

	/* skip first requested items */
	if (data->current_idx < data->start_idx)
	{
		data->current_idx++;
		return 0;
	}

	data->sam = (SAM_ENTRY*)Realloc(data->sam,
	                    num_sam_entries * sizeof(data->sam[0]));
	data->uni_name = (UNISTR2*)Realloc(data->uni_name,
	                    num_sam_entries * sizeof(data->uni_name[0]));

	if (data->sam == NULL || data->uni_name == NULL)
	{
		DEBUG(0,("NULL pointers in make_enum_domains\n"));
		return -1;
	}

	sam = &data->sam[data->num_sam_entries];
	str = &data->uni_name[data->num_sam_entries];

	ZERO_STRUCTP(sam);
	ZERO_STRUCTP(str);

	prs_create(&key, kbuf.dptr, kbuf.dsize, 4, True);

	if (smb_io_unistr2("dom", str, True, &key, 0))
	{
		sam->rid = 0x0;
		make_uni_hdr(&sam->hdr_name, str->uni_str_len);

		data->num_sam_entries++;
	}

	return 0;
}

/*******************************************************************
 samr_reply_enum_domains
 ********************************************************************/
uint32 _samr_enum_domains(const POLICY_HND *pol, uint32 *start_idx, 
				uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_users)
{
	TDB_CONTEXT *sam_tdb = NULL;
	SAM_DATA state;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &sam_tdb, NULL))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_domains:\n"));

	ZERO_STRUCT(state);

	state.start_idx = (*start_idx);
	tdb_traverse(sam_tdb, tdb_domain_traverse, (void*)&state);

	(*sam) = state.sam;
	(*uni_acct_name) = state.uni_name;
	(*start_idx) += state.num_sam_entries;
	(*num_sam_users) = state.num_sam_entries;

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 tdb_samr_connect
 ********************************************************************/
static uint32 tdb_samr_connect( POLICY_HND *pol, uint32 ace_perms)
{
	TDB_CONTEXT *sam_tdb = NULL;

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	policy_hnd_set_name(get_global_hnd_cache(), pol, "sam_connect");

	become_root(True);
	sam_tdb = tdb_open(passdb_path("sam.tdb"), 0, 0, O_RDONLY, 0644);
	unbecome_root(True);

	if (sam_tdb == NULL)
	{
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* associate the domain SID with the (unique) handle. */
	if (!set_tdbsid(get_global_hnd_cache(), pol, sam_tdb,
	                                             &global_sid_S_1_1))
	{
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_connect_anon
 ********************************************************************/
uint32 _samr_connect_anon(const UNISTR2 *srv_name, uint32 access_mask,
				POLICY_HND *connect_pol)

{
	return tdb_samr_connect(connect_pol, access_mask);
}

/*******************************************************************
 _samr_connect
 ********************************************************************/
uint32 _samr_connect(const UNISTR2 *srv_name, uint32 access_mask,
				POLICY_HND *connect_pol)
{
	return tdb_samr_connect(connect_pol, access_mask);
}

static uint32 tdb_lookup_domain(TDB_CONTEXT *tdb,
				const UNISTR2* uni_domain,
				DOM_SID *sid)
{
	prs_struct key;
	prs_struct data;
	UNISTR2 uni_dom_copy;

	copy_unistr2(&uni_dom_copy, uni_domain);

	prs_init(&key, 0, 4, False);
	if (!smb_io_unistr2("dom", &uni_dom_copy, True, &key, 0))
	{
		return NT_STATUS_NO_MEMORY;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!smb_io_dom_sid("sid", sid, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
_samr_lookup_domain
********************************************************************/
uint32 _samr_lookup_domain(const POLICY_HND *connect_pol,
				const UNISTR2 *uni_domain,
				DOM_SID *dom_sid)
{
	TDB_CONTEXT *sam_tdb = NULL;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbsid(get_global_hnd_cache(), connect_pol, &sam_tdb, NULL))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	{
		fstring domain;
		unistr2_to_ascii(domain, uni_domain, sizeof(domain));
		DEBUG(5, ("Lookup Domain: %s\n", domain));
	}

	return tdb_lookup_domain(sam_tdb, uni_domain, dom_sid);
}

/*******************************************************************
 _samr_close
 ********************************************************************/
uint32 _samr_close(POLICY_HND *hnd)
{
	/* set up the SAMR unknown_1 response */

	/* close the policy handle */
	if (close_policy_hnd(get_global_hnd_cache(), hnd))
	{
		ZERO_STRUCTP(hnd);
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_OBJECT_NAME_INVALID;
}

/*******************************************************************
 samr_reply_chgpasswd_user
 ********************************************************************/
uint32 _samr_chgpasswd_user( const UNISTR2 *uni_dest_host,
				const UNISTR2 *uni_user_name,
				const char nt_newpass[516],
				const uchar nt_oldhash[16],
				const char lm_newpass[516],
				const uchar lm_oldhash[16])
{
	fstring user_name;
	fstring wks;

	unistr2_to_ascii(user_name, uni_user_name, sizeof(user_name)-1);
	unistr2_to_ascii(wks, uni_dest_host, sizeof(wks)-1);

	DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

#if 0
	if (!pass_oem_change(user_name,
	                     lm_newpass, lm_oldhash,
	                     nt_newpass, nt_oldhash))
#endif
	{
		return NT_STATUS_WRONG_PASSWORD;
	}

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_get_dom_pwinfo
 ********************************************************************/
uint32 _samr_get_dom_pwinfo(const UNISTR2 *uni_srv_name,
				uint16 *unk_0, uint16 *unk_1, uint16 *unk_2)
{
	/* absolutely no idea what to do, here */
	*unk_0 = 0;
	*unk_1 = 0;
	*unk_2 = 0;

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_sec_obj
 ********************************************************************/
uint32 _samr_query_sec_obj(const POLICY_HND *pol, SEC_DESC_BUF *buf)
{
	uint32 rid;
	DOM_SID usr_sid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, &tdb, NULL, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_copy(&usr_sid, &global_sam_sid);
	sid_append_rid(&usr_sid, rid);

	DEBUG(5,("samr_query_sec_obj: %d\n", __LINE__));

	return samr_make_usr_obj_sd(buf, &usr_sid);;
}
