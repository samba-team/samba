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

} SAM_DATA;

/******************************************************************
makes a SAMR_R_ENUM_DOMAINS structure.
********************************************************************/
static int tdb_domain_traverse(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	DOM_SID sid;
	uint32 rid;
	UNISTR2 *str;
	SAM_DATA *data = (SAM_DATA*)state;
	uint32 num_sam_entries = data->num_sam_entries + 1;
	SAM_ENTRY *sam;

	DEBUG(5,("tdb_domain_traverse: %d\n", num_sam_entries));

	dump_data_pw("sid:\n"   , dbuf.dptr, dbuf.dsize);
	dump_data_pw("domain:\n", kbuf.dptr, kbuf.dsize);

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

	memcpy(&sid, dbuf.dptr, sizeof(sid));
	copy_unistr2(str, (const UNISTR2*)kbuf.dptr);

	if (sid_split_rid(&sid, &rid))
	{
		sam->rid = rid;
	}

	data->num_sam_entries++;

	make_uni_hdr(&sam->hdr_name, str->uni_str_len);

	return 0x0;
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

	tdb_traverse(sam_tdb, tdb_domain_traverse, (void*)&state);

	(*sam) = state.sam;
	(*uni_acct_name) = state.uni_name;
	(*start_idx) += state.num_sam_entries;
	(*num_sam_users) = state.num_sam_entries;

	return 0x0;
}

static BOOL create_domain(TDB_CONTEXT *tdb, char* domain, DOM_SID *sid)
{
	TDB_DATA key;
	TDB_DATA data;
	UNISTR2 uni_domain;
	UNISTR2 uni_dom_upper;

	DEBUG(10,("creating domain %s\n", domain));

	make_unistr2(&uni_domain, domain, strlen(domain));

	key.dptr = (char*)&uni_dom_upper;
	key.dsize = sizeof(uni_dom_upper);

	data.dptr = (char*)sid;
	data.dsize = sizeof(*sid);

	return tdb_store(tdb, key, data, TDB_REPLACE) == 0;
}

/*******************************************************************
 tdb_samr_connect
 ********************************************************************/
static uint32 tdb_samr_connect( POLICY_HND *pol, uint32 ace_perms)
{
	TDB_CONTEXT *sam_tdb = NULL;

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(), pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	become_root(True);
	sam_tdb = tdb_open(passdb_path("sam.tdb"), 0, 0, O_RDWR, 0600);
	unbecome_root(True);

	if (sam_tdb == NULL)
	{
		fstring dom_name;

		DEBUG(0,("HACKALERT - tdb_samr_connect: creating sam.tdb\n"));

		become_root(True);
		sam_tdb = tdb_open(passdb_path("sam.tdb"), 0, 0, O_RDWR | O_CREAT, 0600);
		unbecome_root(True);

		if (sam_tdb == NULL)
		{
			close_policy_hnd(get_global_hnd_cache(), pol);
			return NT_STATUS_ACCESS_DENIED;
		}
		fstrcpy(dom_name, global_sam_name);
		strupper(dom_name);
		create_domain(sam_tdb, dom_name, &global_sam_sid);
		create_domain(sam_tdb, "BUILTIN", &global_sid_S_1_5_20);
	}

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

	return 0x0;
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

static BOOL tdb_lookup_domain(TDB_CONTEXT *tdb,
				const UNISTR2* uni_domain,
				DOM_SID *sid)
{
	TDB_DATA key;
	TDB_DATA data;
	UNISTR2 uni_dom_copy;

	copy_unistr2(&uni_dom_copy, uni_domain);

	key.dptr = (char*)&uni_dom_copy;
	key.dsize = sizeof(uni_dom_copy);

	data = tdb_fetch(tdb, key);

	if (data.dptr == NULL)
	{
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	if (data.dsize != sizeof(*sid))
	{
		free(data.dptr);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	memcpy(sid, data.dptr, sizeof(*sid));
	free(data.dptr);

	return 0x0;
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
		bzero(hnd, sizeof(*hnd));
		return 0x0;
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

	if (!pass_oem_change(user_name,
	                     lm_newpass, lm_oldhash,
	                     nt_newpass, nt_oldhash))
	{
		return NT_STATUS_WRONG_PASSWORD;
	}

	return 0x0;
}


/*******************************************************************
 samr_reply_unknown_38
 ********************************************************************/
uint32 _samr_unknown_38(const UNISTR2 *uni_srv_name,
				uint16 *unk_0, uint16 *unk_1, uint16 *unk_2)
{
	/* absolutely no idea what to do, here */
	*unk_0 = 0;
	*unk_1 = 0;
	*unk_2 = 0;

	return 0x0;
}
