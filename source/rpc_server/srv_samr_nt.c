/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Marc Jacobsen						1999.
 *  Copyright (C) Jeremy Allison               2001-2002.
 *  Copyright (C) Jean François Micouleau      1998-2001.
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

/*
 * This is the implementation of the SAMR code.
 */

#include "includes.h"

extern fstring global_myworkgroup;
extern pstring global_myname;
extern DOM_SID global_sam_sid;
extern DOM_SID global_sid_Builtin;

extern rid_name domain_group_rids[];
extern rid_name domain_alias_rids[];
extern rid_name builtin_alias_rids[];

typedef struct _disp_info {
	BOOL user_dbloaded;
	uint32 num_user_account;
	DISP_USER_INFO *disp_user_info;
	BOOL group_dbloaded;
	uint32 num_group_account;
	DISP_GROUP_INFO *disp_group_info;
} DISP_INFO;

struct samr_info {
	/* for use by the \PIPE\samr policy */
	DOM_SID sid;
	uint32 status; /* some sort of flag.  best to record it.  comes from opnum 0x39 */
	DISP_INFO disp_info;
};

/*******************************************************************
 Create a samr_info struct.
 ********************************************************************/

static struct samr_info *get_samr_info_by_sid(DOM_SID *psid)
{
	struct samr_info *info;
	fstring sid_str;

	if ((info = (struct samr_info *)malloc(sizeof(struct samr_info))) == NULL)
		return NULL;

	ZERO_STRUCTP(info);
	if (psid) {
		DEBUG(10,("get_samr_info_by_sid: created new info for sid %s\n", sid_to_string(sid_str, psid) ));
		sid_copy( &info->sid, psid);
	} else {
		DEBUG(10,("get_samr_info_by_sid: created new info for NULL sid.\n"));
	}
	return info;
}

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_samr_db(struct samr_info *info)
{
	int i;

	if (info->disp_info.group_dbloaded) {
		for (i=0; i<info->disp_info.num_group_account; i++)
			SAFE_FREE(info->disp_info.disp_group_info[i].grp);

		SAFE_FREE(info->disp_info.disp_group_info);
	}

	if (info->disp_info.user_dbloaded){
		for (i=0; i<info->disp_info.num_user_account; i++)
			pdb_free_sam(info->disp_info.disp_user_info[i].sam);

		SAFE_FREE(info->disp_info.disp_user_info);
	}

	info->disp_info.user_dbloaded=False;
	info->disp_info.group_dbloaded=False;
	info->disp_info.num_group_account=0;
	info->disp_info.num_user_account=0;
}

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_samr_info(void *ptr)
{
	struct samr_info *info=(struct samr_info *) ptr;

	free_samr_db(info);
	SAFE_FREE(info);
}

/*******************************************************************
 Ensure password info is never given out. Paranioa... JRA.
 ********************************************************************/

static void samr_clear_passwd_fields( SAM_USER_INFO_21 *pass, int num_entries)
{
	int i;

	if (!pass)
		return;

	for (i = 0; i < num_entries; i++) {
		memset(&pass[i].lm_pwd, '\0', sizeof(pass[i].lm_pwd));
		memset(&pass[i].nt_pwd, '\0', sizeof(pass[i].nt_pwd));
	}
}

static void samr_clear_sam_passwd(SAM_ACCOUNT *sam_pass)
{
	if (!sam_pass)
		return;

	if (sam_pass->lm_pw)
		memset(sam_pass->lm_pw, '\0', 16);
	if (sam_pass->nt_pw)
		memset(sam_pass->nt_pw, '\0', 16);
}

static NTSTATUS load_sampwd_entries(struct samr_info *info, uint16 acb_mask)
{
	SAM_ACCOUNT *pwd = NULL;
	DISP_USER_INFO *pwd_array = NULL;

	DEBUG(10,("load_sampwd_entries\n"));

	/* if the snapshoot is already loaded, return */
	if (info->disp_info.user_dbloaded==True) {
		DEBUG(10,("load_sampwd_entries: already in memory\n"));
		return NT_STATUS_OK;
	}

	if (!pdb_setsampwent(False)) {
		DEBUG(0, ("load_sampwd_entries: Unable to open passdb.\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	for (pdb_init_sam(&pwd); pdb_getsampwent(pwd) == True; pwd=NULL, pdb_init_sam(&pwd) ) {
		
		if (acb_mask != 0 && !(pwd->acct_ctrl & acb_mask)) {
			pdb_free_sam(pwd);
			DEBUG(5,(" acb_mask %x reject\n", acb_mask));
			continue;
		}

		/* Realloc some memory for the array of ptr to the SAM_ACCOUNT structs */
		if (info->disp_info.num_user_account % MAX_SAM_ENTRIES == 0) {
		
			DEBUG(10,("load_sampwd_entries: allocating more memory\n"));
			pwd_array=(DISP_USER_INFO *)Realloc(info->disp_info.disp_user_info, 
			                  (info->disp_info.num_user_account+MAX_SAM_ENTRIES)*sizeof(DISP_USER_INFO));

			if (pwd_array==NULL)
				return NT_STATUS_NO_MEMORY;

			info->disp_info.disp_user_info=pwd_array;
		}
	
		/* link the SAM_ACCOUNT to the array */
		info->disp_info.disp_user_info[info->disp_info.num_user_account].sam=pwd;

		DEBUG(10,("load_sampwd_entries: entry: %d\n", info->disp_info.num_user_account));

		info->disp_info.num_user_account++;	
	}

	pdb_endsampwent();

	/* the snapshoot is in memory, we're ready to enumerate fast */

	info->disp_info.user_dbloaded=True;

	DEBUG(12,("load_sampwd_entries: done\n"));

	return NT_STATUS_OK;
}

/*
 * This is a really ugly hack to make this interface work in the 2.2.x code. JRA.
 * Return a malloced map so we can free it.
 */

static int setup_fake_group_map(GROUP_MAP **ret_map)
{
	static GROUP_MAP static_map[2];
	static BOOL group_map_init;
	extern DOM_SID global_sam_sid;

	*ret_map = (GROUP_MAP *)malloc(sizeof(GROUP_MAP)*2);
	if (!ret_map)
		return 2;
	
	if (group_map_init) {
		memcpy( *ret_map, &static_map[0], sizeof(GROUP_MAP)*2);
		return sizeof(static_map)/sizeof(GROUP_MAP);
	}

	group_map_init = True;

	static_map[0].gid = (gid_t)-1;
	sid_copy(&static_map[0].sid, &global_sam_sid);
	sid_append_rid(&static_map[0].sid, DOMAIN_GROUP_RID_ADMINS);
	static_map[0].sid_name_use = SID_NAME_DOM_GRP;
	fstrcpy(static_map[0].nt_name, "Domain Admins");
	fstrcpy(static_map[0].comment, "Administrators for the domain");
	static_map[0].privilege = 0;

	static_map[1].gid = (gid_t)-1;
	sid_copy(&static_map[1].sid, &global_sam_sid);
	sid_append_rid(&static_map[1].sid, DOMAIN_GROUP_RID_USERS);
	static_map[1].sid_name_use = SID_NAME_DOM_GRP;
	fstrcpy(static_map[1].nt_name, "Domain Users");
	fstrcpy(static_map[1].comment, "Users in the domain");
	static_map[1].privilege = 0;

	memcpy( *ret_map, &static_map[0], sizeof(GROUP_MAP)*2);
	return sizeof(static_map)/sizeof(GROUP_MAP);
}

static NTSTATUS load_group_domain_entries(struct samr_info *info, DOM_SID *sid)
{
	GROUP_MAP *map;
	DISP_GROUP_INFO *grp_array = NULL;
	uint32 group_entries = 0;
	uint32 i;

	DEBUG(10,("load_group_domain_entries\n"));

	/* if the snapshoot is already loaded, return */
	if (info->disp_info.group_dbloaded==True) {
		DEBUG(10,("load_group_domain_entries: already in memory\n"));
		return NT_STATUS_OK;
	}

	/*
	 * This is a really ugly hack to make this interface work in the 2.2.x code. JRA.
	 */

	group_entries = setup_fake_group_map(&map);

	info->disp_info.num_group_account=group_entries;

	grp_array=(DISP_GROUP_INFO *)malloc(info->disp_info.num_group_account*sizeof(DISP_GROUP_INFO));

	if (group_entries!=0 && grp_array==NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	info->disp_info.disp_group_info=grp_array;

	for (i=0; i<group_entries; i++) {
	
		grp_array[i].grp=(DOMAIN_GRP *)malloc(sizeof(DOMAIN_GRP));
	
		fstrcpy(grp_array[i].grp->name, map[i].nt_name);
		fstrcpy(grp_array[i].grp->comment, map[i].comment);
		sid_split_rid(&map[i].sid, &grp_array[i].grp->rid);
		grp_array[i].grp->attr=SID_NAME_DOM_GRP;
	}

	SAFE_FREE(map);

	/* the snapshoot is in memory, we're ready to enumerate fast */

	info->disp_info.group_dbloaded=True;

	DEBUG(12,("load_group_domain_entries: done\n"));

	return NT_STATUS_OK;
}

/*******************************************************************
  This next function should be replaced with something that
  dynamically returns the correct user info..... JRA.
 ********************************************************************/

static NTSTATUS get_sampwd_entries(SAM_USER_INFO_21 *pw_buf, int start_idx,
                                int *total_entries, int *num_entries,
                                int max_num_entries, uint16 acb_mask)
{
	SAM_ACCOUNT *pwd = NULL;
	BOOL not_finished = True;
 
	(*num_entries) = 0;
	(*total_entries) = 0;

	if (pw_buf == NULL)
		return NT_STATUS_NO_MEMORY;

	pdb_init_sam(&pwd);

	if (!pdb_setsampwent(False)) {
		DEBUG(0, ("get_sampwd_entries: Unable to open passdb.\n"));
		pdb_free_sam(pwd);
		return NT_STATUS_ACCESS_DENIED;
	}
	
	while (((not_finished = pdb_getsampwent(pwd)) != False) 
	       && (*num_entries) < max_num_entries) 
	{
	        int user_name_len;
		
	        if (start_idx > 0) {

			pdb_reset_sam(pwd);

			/* skip the requested number of entries.
			   not very efficient, but hey...  */
			start_idx--;
			continue;
		}
		
		user_name_len = strlen(pdb_get_username(pwd))+1;
		init_unistr2(&pw_buf[(*num_entries)].uni_user_name, pdb_get_username(pwd), user_name_len);
		init_uni_hdr(&pw_buf[(*num_entries)].hdr_user_name, user_name_len);
		pw_buf[(*num_entries)].user_rid = pwd->user_rid;
		memset((char *)pw_buf[(*num_entries)].nt_pwd, '\0', 16);
		
		/* Now check if the NT compatible password is available. */
		if (pdb_get_nt_passwd(pwd))
			memcpy( pw_buf[(*num_entries)].nt_pwd , pdb_get_nt_passwd(pwd), 16);
		
		pw_buf[(*num_entries)].acb_info = pdb_get_acct_ctrl(pwd);
		
		DEBUG(5, ("entry idx: %d user %s, rid 0x%x, acb %x",
			  (*num_entries), pdb_get_username(pwd), pdb_get_user_rid(pwd), pdb_get_acct_ctrl(pwd) ));
		
		if (acb_mask == 0 || (pwd->acct_ctrl & acb_mask)) {
			DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
			(*num_entries)++;
		} else {
			DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
		}

		(*total_entries)++;
		
		pdb_reset_sam(pwd);

	}
	
	pdb_endsampwent();
	pdb_free_sam(pwd);

	if (not_finished)
		return STATUS_MORE_ENTRIES;
	else
		return NT_STATUS_OK;
}

/*******************************************************************
 _samr_close_hnd
 ********************************************************************/

NTSTATUS _samr_close_hnd(pipes_struct *p, SAMR_Q_CLOSE_HND *q_u, SAMR_R_CLOSE_HND *r_u)
{
	r_u->status = NT_STATUS_OK;

	/* close the policy handle */
	if (!close_policy_hnd(p, &q_u->pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	DEBUG(5,("samr_reply_close_hnd: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_reply_open_domain
 ********************************************************************/

NTSTATUS _samr_open_domain(pipes_struct *p, SAMR_Q_OPEN_DOMAIN *q_u, SAMR_R_OPEN_DOMAIN *r_u)
{
	struct samr_info *info;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	/* associate the domain SID with the (unique) handle. */
	if ((info = get_samr_info_by_sid(&q_u->dom_sid.sid))==NULL)
		return NT_STATUS_NO_MEMORY;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->domain_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("samr_open_domain: %d\n", __LINE__));

	return r_u->status;
}

static uint32 get_lsa_policy_samr_rid(struct samr_info *info)
{
	if (!info) {
		DEBUG(3,("Error getting policy\n"));
		return 0xffffffff;
	}

	return info->sid.sub_auths[info->sid.num_auths-1];
}

/*******************************************************************
 _samr_get_usrdom_pwinfo
 ********************************************************************/

NTSTATUS _samr_get_usrdom_pwinfo(pipes_struct *p, SAMR_Q_GET_USRDOM_PWINFO *q_u, SAMR_R_GET_USRDOM_PWINFO *r_u)
{
	struct samr_info *info = NULL;

	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->user_pol, (void **)&info)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (get_lsa_policy_samr_rid(info) == 0xffffffff) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	init_samr_r_get_usrdom_pwinfo(r_u, NT_STATUS_OK);

	DEBUG(5,("_samr_get_usrdom_pwinfo: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_make_usr_obj_sd
 ********************************************************************/

static NTSTATUS samr_make_usr_obj_sd(TALLOC_CTX *ctx, SEC_DESC_BUF **buf, DOM_SID *usr_sid)
{
	extern DOM_SID global_sid_Builtin;
	extern DOM_SID global_sid_World;
	DOM_SID adm_sid;
	DOM_SID act_sid;

	SEC_ACE ace[4];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;
	SEC_DESC *psd = NULL;
	size_t sd_size;

	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, &global_sid_Builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	init_sec_access(&mask, 0x2035b);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	init_sec_access(&mask, 0xf07ff);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[2], &act_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	init_sec_access(&mask,0x20044);
	init_sec_ace(&ace[3], usr_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 4, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if((psd = make_sec_desc(ctx, SEC_DESC_REVISION, NULL, NULL, NULL, psa, &sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if((*buf = make_sec_desc_buf(ctx, sd_size, psd)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

static BOOL get_lsa_policy_samr_sid(pipes_struct *p, POLICY_HND *pol, DOM_SID *sid)
{
	struct samr_info *info = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, pol, (void **)&info))
		return False;

	if (!info)
		return False;

	*sid = info->sid;
	return True;
}

/*******************************************************************
 _samr_query_sec_obj
 ********************************************************************/

NTSTATUS _samr_query_sec_obj(pipes_struct *p, SAMR_Q_QUERY_SEC_OBJ *q_u, SAMR_R_QUERY_SEC_OBJ *r_u)
{
	DOM_SID pol_sid;

	r_u->status = NT_STATUS_OK;

	/* Get the SID. */

	if (!get_lsa_policy_samr_sid(p, &q_u->user_pol, &pol_sid))
		return NT_STATUS_INVALID_HANDLE;

	r_u->status = samr_make_usr_obj_sd(p->mem_ctx, &r_u->buf, &pol_sid);

	if (NT_STATUS_IS_OK(r_u->status))
		r_u->ptr = 1;

	return r_u->status;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure from a user list.
********************************************************************/

static void make_user_sam_entry_list(TALLOC_CTX *ctx, SAM_ENTRY **sam_pp, UNISTR2 **uni_name_pp,
                uint32 num_sam_entries, SAM_USER_INFO_21 *pass)
{
	uint32 i;
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;

	*sam_pp = NULL;
	*uni_name_pp = NULL;

	if (num_sam_entries == 0)
		return;

	sam = (SAM_ENTRY *)talloc_zero(ctx, sizeof(SAM_ENTRY)*num_sam_entries);

	uni_name = (UNISTR2 *)talloc_zero(ctx, sizeof(UNISTR2)*num_sam_entries);

	if (sam == NULL || uni_name == NULL) {
		DEBUG(0, ("NULL pointers in SAMR_R_QUERY_DISPINFO\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++) {
		int len = pass[i].uni_user_name.uni_str_len;

		init_sam_entry(&sam[i], len, pass[i].user_rid);
		copy_unistr2(&uni_name[i], &pass[i].uni_user_name);
	}

	*sam_pp = sam;
	*uni_name_pp = uni_name;
}

/*******************************************************************
 samr_reply_enum_dom_users
 ********************************************************************/

NTSTATUS _samr_enum_dom_users(pipes_struct *p, SAMR_Q_ENUM_DOM_USERS *q_u, SAMR_R_ENUM_DOM_USERS *r_u)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int num_entries = 0;
	int total_entries = 0;
	
	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("_samr_enum_dom_users: %d\n", __LINE__));

	become_root();
	r_u->status = get_sampwd_entries(pass, q_u->start_idx, &total_entries, &num_entries,
								MAX_SAM_ENTRIES, q_u->acb_mask);
	unbecome_root();

	if (NT_STATUS_IS_ERR(r_u->status))
		return r_u->status;

	samr_clear_passwd_fields(pass, num_entries);

	/* 
	 * Note from JRA. total_entries is not being used here. Currently if there is a
	 * large user base then it looks like NT will enumerate until get_sampwd_entries
	 * returns False due to num_entries being zero. This will cause an access denied
	 * return. I don't think this is right and needs further investigation. Note that
	 * this is also the same in the TNG code (I don't think that has been tested with
	 * a very large user list as MAX_SAM_ENTRIES is set to 600).
	 * 
	 * I also think that one of the 'num_entries' return parameters is probably
	 * the "max entries" parameter - but in the TNG code they're all currently set to the same
	 * value (again I think this is wrong).
	 */

	make_user_sam_entry_list(p->mem_ctx, &r_u->sam, &r_u->uni_acct_name, num_entries, pass);

	init_samr_r_enum_dom_users(r_u, q_u->start_idx + num_entries, num_entries);

	DEBUG(5,("_samr_enum_dom_users: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure from a group list.
********************************************************************/

static void make_group_sam_entry_list(TALLOC_CTX *ctx, SAM_ENTRY **sam_pp, UNISTR2 **uni_name_pp,
                uint32 num_sam_entries, DOMAIN_GRP *grp)
{
	uint32 i;
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;

	*sam_pp = NULL;
	*uni_name_pp = NULL;

	if (num_sam_entries == 0)
		return;

	sam = (SAM_ENTRY *)talloc_zero(ctx, sizeof(SAM_ENTRY)*num_sam_entries);

	uni_name = (UNISTR2 *)talloc_zero(ctx, sizeof(UNISTR2)*num_sam_entries);

	if (sam == NULL || uni_name == NULL) {
		DEBUG(0, ("NULL pointers in SAMR_R_QUERY_DISPINFO\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++) {
		/*
		 * JRA. I think this should include the null. TNG does not.
		 */
		int len = strlen(unix_to_dos_static(grp[i].name))+1;

		init_sam_entry(&sam[i], len, grp[i].rid);
		init_unistr2(&uni_name[i], unix_to_dos_static(grp[i].name), len);
	}

	*sam_pp = sam;
	*uni_name_pp = uni_name;
}

/*******************************************************************
 Get the group entries - similar to get_sampwd_entries().
 ********************************************************************/

static NTSTATUS get_group_alias_entries(DOMAIN_GRP *d_grp, DOM_SID *sid, uint32 start_idx,
				    uint32 *p_num_entries, uint32 max_entries)
{
	fstring sid_str;
	fstring sam_sid_str;
	uint32 num_entries = 0;

	sid_to_string(sid_str, sid);
	sid_to_string(sam_sid_str, &global_sam_sid);

	*p_num_entries = 0;

	/* well-known aliases */
	if (strequal(sid_str, "S-1-5-32")) {
		const char *alias_name;
		while (!lp_hide_local_users() &&
				num_entries < max_entries && 
				((alias_name = builtin_alias_rids[num_entries].name) != NULL)) {

			fstrcpy(d_grp[num_entries].name, alias_name);
			d_grp[num_entries].rid = builtin_alias_rids[num_entries].rid;

			num_entries++;
		}
	} else if (strequal(sid_str, sam_sid_str) && !lp_hide_local_users()) {
		fstring name;
		char *sep;
		struct sys_grent *glist;
		struct sys_grent *grp;

		sep = lp_winbind_separator();

		/* local aliases */
		/* we return the UNIX groups here.  This seems to be the right */
		/* thing to do, since NT member servers return their local     */
		/* groups in the same situation.                               */

		/* use getgrent_list() to retrieve the list of groups to avoid
		 * problems with getgrent possible infinite loop by internal
		 * libc grent structures overwrites by called functions */
		grp = glist = getgrent_list();
		if (grp == NULL)
			return NT_STATUS_NO_MEMORY;

		for (;(num_entries < max_entries) && (grp != NULL); grp = grp->next) {
			int i;
			uint32 trid;

			fstrcpy(name,grp->gr_name);
			DEBUG(10,("get_group_alias_entries: got group %s\n", name ));

			/* Don't return winbind groups as they are not local! */

			if (strchr(name, *sep) != NULL) {
				DEBUG(10,("get_group_alias_entries: not returing %s, not local.\n", name ));
				continue;
			}

			/* Don't return user private groups... */
			if (Get_Pwnam(name, False) != 0) {
				DEBUG(10,("get_group_alias_entries: not returing %s, clashes with user.\n", name ));
				continue;
			}

			trid = pdb_gid_to_group_rid(grp->gr_gid);
			for( i = 0; i < num_entries; i++)
				if ( d_grp[i].rid == trid )
					break;

			if ( i < num_entries )
				continue; /* rid was there, dup! */

			/* JRA - added this for large group db enumeration... */

			if (start_idx > 0) {
				/* skip the requested number of entries.
					not very efficient, but hey...
				*/
				start_idx--;
				continue;
			}

			fstrcpy(d_grp[num_entries].name, name);
			d_grp[num_entries].rid = trid;
			num_entries++;
		}

		grent_free(glist);
	}

	*p_num_entries = num_entries;

	if (num_entries >= max_entries)
		return STATUS_MORE_ENTRIES;
	return NT_STATUS_OK;
}

/*******************************************************************
 Get the group entries - similar to get_sampwd_entries().
 ********************************************************************/

static NTSTATUS get_group_domain_entries(DOMAIN_GRP *d_grp, DOM_SID *sid, uint32 start_idx,
				     uint32 *p_num_entries, uint32 max_entries)
{
	fstring sid_str;
	fstring sam_sid_str;
	uint32 num_entries = 0;
	fstring name="Domain Admins";
	fstring comment="Just to make it work !";

	sid_to_string(sid_str, sid);
	sid_to_string(sam_sid_str, &global_sam_sid);

	*p_num_entries = 0;

	fstrcpy(d_grp[0].name, name);
	fstrcpy(d_grp[0].comment, comment);
	d_grp[0].rid = DOMAIN_GROUP_RID_ADMINS;
	d_grp[0].attr=SID_NAME_DOM_GRP;

	fstrcpy(d_grp[1].name, "Domain Users");
	fstrcpy(d_grp[1].comment, "Just to make it work !");
	d_grp[1].rid = DOMAIN_GROUP_RID_USERS;
	d_grp[1].attr=SID_NAME_DOM_GRP;

	num_entries = 2;

	*p_num_entries = num_entries;

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_reply_enum_dom_groups
 Only reply with one group - domain admins. This must be fixed for
 a real PDC. JRA.
 ********************************************************************/

NTSTATUS _samr_enum_dom_groups(pipes_struct *p, SAMR_Q_ENUM_DOM_GROUPS *q_u, SAMR_R_ENUM_DOM_GROUPS *r_u)
{
	DOMAIN_GRP grp[2];
	uint32 num_entries;
	DOM_SID sid;

	r_u->status = NT_STATUS_OK;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("samr_reply_enum_dom_groups: %d\n", __LINE__));

	get_group_domain_entries(grp, &sid, q_u->start_idx, &num_entries, MAX_SAM_ENTRIES);

	make_group_sam_entry_list(p->mem_ctx, &r_u->sam, &r_u->uni_grp_name, num_entries, grp);

	init_samr_r_enum_dom_groups(r_u, q_u->start_idx, num_entries);

	DEBUG(5,("samr_enum_dom_groups: %d\n", __LINE__));

	return r_u->status;
}


/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/

NTSTATUS _samr_enum_dom_aliases(pipes_struct *p, SAMR_Q_ENUM_DOM_ALIASES *q_u, SAMR_R_ENUM_DOM_ALIASES *r_u)
{
	DOMAIN_GRP grp[MAX_SAM_ENTRIES];
	uint32 num_entries = 0;
	fstring sid_str;
	DOM_SID sid;
	
	r_u->status = NT_STATUS_OK;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	sid_to_string(sid_str, &sid);
	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	r_u->status = get_group_alias_entries(grp, &sid, q_u->start_idx,
						&num_entries, MAX_SAM_ENTRIES);
	if (NT_STATUS_IS_ERR(r_u->status))
		return r_u->status;

	make_group_sam_entry_list(p->mem_ctx, &r_u->sam, &r_u->uni_grp_name, num_entries, grp);

	init_samr_r_enum_dom_aliases(r_u, q_u->start_idx + num_entries, num_entries);

	DEBUG(5,("samr_enum_dom_aliases: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/
NTSTATUS _samr_query_dispinfo(pipes_struct *p, SAMR_Q_QUERY_DISPINFO *q_u, SAMR_R_QUERY_DISPINFO *r_u)
{
	struct samr_info *info = NULL;
	uint32 struct_size=0x20; /* W2K always reply that, client doesn't care */
	uint16 acb_mask;
	
	uint32 max_entries=q_u->max_entries;
	uint32 enum_context=q_u->start_idx;
	uint32 max_size=q_u->max_size;

	SAM_DISPINFO_CTR *ctr;
	uint32 temp_size=0, total_data_size=0;
	NTSTATUS disp_ret;
	uint32 num_account = 0;
	enum remote_arch_types ra_type = get_remote_arch();
	int max_sam_entries;

	max_sam_entries = (ra_type == RA_WIN95) ? MAX_SAM_ENTRIES_W95 : MAX_SAM_ENTRIES_W2K;

	DEBUG(5, ("samr_reply_query_dispinfo: %d\n", __LINE__));
	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->domain_pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	/*
	 * calculate how many entries we will return.
	 * based on 
	 * - the number of entries the client asked
	 * - our limit on that
	 * - the starting point (enumeration context)
	 * - the buffer size the client will accept
	 */

	/*
	 * We are a lot more like W2K. Instead of reading the SAM
	 * each time to find the records we need to send back,
	 * we read it once and link that copy to the sam handle.
	 * For large user list (over the MAX_SAM_ENTRIES)
	 * it's a definitive win.
	 * second point to notice: between enumerations
	 * our sam is now the same as it's a snapshoot.
	 * third point: got rid of the static SAM_USER_21 struct
	 * no more intermediate.
	 * con: it uses much more memory, as a full copy is stored
	 * in memory.
	 *
	 * If you want to change it, think twice and think
	 * of the second point , that's really important.
	 *
	 * JFM, 12/20/2001
	 */

	/* Get what we need from the password database */

	if (q_u->switch_level==2)
		acb_mask = ACB_WSTRUST;
	else
		acb_mask = ACB_NORMAL;

	/* Get what we need from the password database */
	switch (q_u->switch_level) {
		case 0x1:
		case 0x2:
		case 0x4:
			become_root();		
			r_u->status=load_sampwd_entries(info, acb_mask);
			unbecome_root();
			if (NT_STATUS_IS_ERR(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_sampwd_entries failed\n"));
				return r_u->status;
			}
			num_account = info->disp_info.num_user_account;
			break;
		case 0x3:
		case 0x5:
			r_u->status = load_group_domain_entries(info, &info->sid);
			if (NT_STATUS_IS_ERR(r_u->status))
				return r_u->status;
			num_account = info->disp_info.num_group_account;
			break;
		default:
			DEBUG(0,("_samr_query_dispinfo: Unknown info level (%u)\n", (unsigned int)q_u->switch_level ));
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* first limit the number of entries we will return */
	if(max_entries > max_sam_entries) {
		DEBUG(5, ("samr_reply_query_dispinfo: client requested %d entries, limiting to %d\n", max_entries, max_sam_entries));
		max_entries = max_sam_entries;
	}

	if (enum_context > num_account) {
		DEBUG(5, ("samr_reply_query_dispinfo: enumeration handle over total entries\n"));
		return NT_STATUS_OK;
	}

	/* verify we won't overflow */
	if (max_entries > num_account-enum_context) {
		max_entries = num_account-enum_context;
		DEBUG(5, ("samr_reply_query_dispinfo: only %d entries to return\n", max_entries));
	}

	/* calculate the size and limit on the number of entries we will return */
	temp_size=max_entries*struct_size;
	
	if (temp_size>max_size) {
		max_entries=MIN((max_size/struct_size),max_entries);
		DEBUG(5, ("samr_reply_query_dispinfo: buffer size limits to only %d entries\n", max_entries));
	}

	if (!(ctr = (SAM_DISPINFO_CTR *)talloc_zero(p->mem_ctx,sizeof(SAM_DISPINFO_CTR))))
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(ctr);

	/* Now create reply structure */
	switch (q_u->switch_level) {
	case 0x1:
		if (max_entries) {
			if (!(ctr->sam.info1 = (SAM_DISPINFO_1 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_1))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_1(p->mem_ctx, ctr->sam.info1, max_entries, enum_context, info->disp_info.disp_user_info);
		if (NT_STATUS_IS_ERR(disp_ret))
			return disp_ret;
		break;
	case 0x2:
		if (max_entries) {
			if (!(ctr->sam.info2 = (SAM_DISPINFO_2 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_2))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_2(p->mem_ctx, ctr->sam.info2, max_entries, enum_context, info->disp_info.disp_user_info);
		if (NT_STATUS_IS_ERR(disp_ret))
			return disp_ret;
		break;
	case 0x3:
		if (max_entries) {
			if (!(ctr->sam.info3 = (SAM_DISPINFO_3 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_3))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_3(p->mem_ctx, ctr->sam.info3, max_entries, enum_context, info->disp_info.disp_group_info);
		if (NT_STATUS_IS_ERR(disp_ret))
			return disp_ret;
		break;
	case 0x4:
		if (max_entries) {
			if (!(ctr->sam.info4 = (SAM_DISPINFO_4 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_4))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_4(p->mem_ctx, ctr->sam.info4, max_entries, enum_context, info->disp_info.disp_user_info);
		if (NT_STATUS_IS_ERR(disp_ret))
			return disp_ret;
		break;
	case 0x5:
		if (max_entries) {
			if (!(ctr->sam.info5 = (SAM_DISPINFO_5 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_5))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_5(p->mem_ctx, ctr->sam.info5, max_entries, enum_context, info->disp_info.disp_group_info);
		if (NT_STATUS_IS_ERR(disp_ret))
			return disp_ret;
		break;

	default:
		ctr->sam.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* calculate the total size */
	total_data_size=num_account*struct_size;

	if (enum_context+max_entries < num_account)
		r_u->status = STATUS_MORE_ENTRIES;

	DEBUG(5, ("_samr_query_dispinfo: %d\n", __LINE__));

	init_samr_r_query_dispinfo(r_u, max_entries, total_data_size, temp_size, q_u->switch_level, ctr, r_u->status);

	return r_u->status;

}

/*******************************************************************
 samr_reply_query_aliasinfo
 ********************************************************************/

NTSTATUS _samr_query_aliasinfo(pipes_struct *p, SAMR_Q_QUERY_ALIASINFO *q_u, SAMR_R_QUERY_ALIASINFO *r_u)
{
	fstring alias_desc = "Local Unix group";
	fstring alias="";
	enum SID_NAME_USE type;
	uint32 alias_rid;
	struct samr_info *info = NULL;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_aliasinfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	alias_rid = get_lsa_policy_samr_rid(info);
	if(alias_rid == 0xffffffff)
		return NT_STATUS_NO_SUCH_ALIAS;

	if(!local_lookup_rid(alias_rid, alias, &type))
		return NT_STATUS_NO_SUCH_ALIAS;

	switch (q_u->switch_level) {
	case 3:
		r_u->ptr = 1;
		r_u->ctr.switch_value1 = 3;
		init_samr_alias_info3(&r_u->ctr.alias.info3, alias_desc);
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	DEBUG(5,("_samr_query_aliasinfo: %d\n", __LINE__));

	return r_u->status;
}

#if 0
/*******************************************************************
 samr_reply_lookup_ids
 ********************************************************************/

 uint32 _samr_lookup_ids(pipes_struct *p, SAMR_Q_LOOKUP_IDS *q_u, SAMR_R_LOOKUP_IDS *r_u)
{
    uint32 rid[MAX_SAM_ENTRIES];
    int num_rids = q_u->num_sids1;

    r_u->status = NT_STATUS_OK;

    DEBUG(5,("_samr_lookup_ids: %d\n", __LINE__));

    if (num_rids > MAX_SAM_ENTRIES) {
        num_rids = MAX_SAM_ENTRIES;
        DEBUG(5,("_samr_lookup_ids: truncating entries to %d\n", num_rids));
    }

#if 0
    int i;
    SMB_ASSERT_ARRAY(q_u->uni_user_name, num_rids);

    for (i = 0; i < num_rids && status == 0; i++)
    {
        struct sam_passwd *sam_pass;
        fstring user_name;


        fstrcpy(user_name, unistrn2(q_u->uni_user_name[i].buffer,
                                    q_u->uni_user_name[i].uni_str_len));

        /* find the user account */
        become_root();
        sam_pass = get_smb21pwd_entry(user_name, 0);
        unbecome_root();

        if (sam_pass == NULL)
        {
            status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
            rid[i] = 0;
        }
        else
        {
            rid[i] = sam_pass->user_rid;
        }
    }
#endif

    num_rids = 1;
    rid[0] = BUILTIN_ALIAS_RID_USERS;

    init_samr_r_lookup_ids(&r_u, num_rids, rid, NT_STATUS_OK);

    DEBUG(5,("_samr_lookup_ids: %d\n", __LINE__));

    return r_u->status;
}
#endif

/*******************************************************************
 _samr_lookup_names
 ********************************************************************/

NTSTATUS _samr_lookup_names(pipes_struct *p, SAMR_Q_LOOKUP_NAMES *q_u, SAMR_R_LOOKUP_NAMES *r_u)
{
	uint32 rid[MAX_SAM_ENTRIES];
	uint32 local_rid;
	enum SID_NAME_USE type[MAX_SAM_ENTRIES];
	enum SID_NAME_USE local_type;
	int i;
	int num_rids = q_u->num_names2;
	DOM_SID pol_sid;
	fstring sid_str;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_lookup_names: %d\n", __LINE__));

	ZERO_ARRAY(rid);
	ZERO_ARRAY(type);

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &pol_sid)) {
		init_samr_r_lookup_names(p->mem_ctx, r_u, 0, NULL, NULL, NT_STATUS_OBJECT_TYPE_MISMATCH);
		return r_u->status;
	}

	if (num_rids > MAX_SAM_ENTRIES) {
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("_samr_lookup_names: truncating entries to %d\n", num_rids));
	}

	DEBUG(5,("_samr_lookup_names: looking name on SID %s\n", sid_to_string(sid_str, &pol_sid)));

	for (i = 0; i < num_rids; i++) {
		fstring name;
		DOM_SID sid;

		r_u->status = NT_STATUS_NONE_MAPPED;

		rid [i] = 0xffffffff;
		type[i] = SID_NAME_UNKNOWN;

		fstrcpy(name, dos_unistrn2(q_u->uni_name[i].buffer, q_u->uni_name[i].uni_str_len));

		/*
		 * we are only looking for a name
		 * the SID we get back can be outside
		 * the scope of the pol_sid
		 *
		 * in clear: it prevents to reply to domain\group: yes
		 * when only builtin\group exists.
		 *
		 * a cleaner code is to add the sid of the domain we're looking in
		 * to the local_lookup_name function.
		 */
 
		if(local_lookup_name(global_myname, name, &sid, &local_type)) {
			sid_split_rid(&sid, &local_rid);
 
			if (sid_equal(&sid, &pol_sid)) {
				rid[i]=local_rid;
				type[i]=local_type;
				r_u->status = NT_STATUS_OK;
			}
		}
	}

	init_samr_r_lookup_names(p->mem_ctx, r_u, num_rids, rid, (uint32 *)type, r_u->status);

	DEBUG(5,("_samr_lookup_names: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _samr_chgpasswd_user
 ********************************************************************/

NTSTATUS _samr_chgpasswd_user(pipes_struct *p, SAMR_Q_CHGPASSWD_USER *q_u, SAMR_R_CHGPASSWD_USER *r_u)
{
    fstring user_name;
    fstring wks;

    DEBUG(5,("_samr_chgpasswd_user: %d\n", __LINE__));

    r_u->status = NT_STATUS_OK;

    fstrcpy(user_name, dos_unistrn2(q_u->uni_user_name.buffer, q_u->uni_user_name.uni_str_len));
    fstrcpy(wks      , dos_unistrn2(q_u->uni_dest_host.buffer, q_u->uni_dest_host.uni_str_len));

    DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */
 
	(void)map_username(user_name);
 
	/*
	 * Do any UNIX username case mangling.
	 */
	(void)Get_Pwnam( user_name, True);

    if (!pass_oem_change(user_name, q_u->lm_newpass.pass, q_u->lm_oldhash.hash,
                         q_u->nt_newpass.pass, q_u->nt_oldhash.hash))
        r_u->status = NT_STATUS_WRONG_PASSWORD;

    init_samr_r_chgpasswd_user(r_u, r_u->status);

    DEBUG(5,("_samr_chgpasswd_user: %d\n", __LINE__));

    return r_u->status;
}

/*******************************************************************
makes a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/

static BOOL make_samr_lookup_rids(TALLOC_CTX *ctx, uint32 num_names, fstring names[],
	    UNIHDR **pp_hdr_name, UNISTR2 **pp_uni_name)
{
	uint32 i;
	UNIHDR *hdr_name = NULL;
	UNISTR2 *uni_name = NULL;

	*pp_uni_name = NULL;
	*pp_hdr_name = NULL;

	if (num_names != 0) {
		hdr_name = (UNIHDR *)talloc_zero(ctx, sizeof(UNIHDR)*num_names);
		if (hdr_name == NULL)
			return False;

		uni_name = (UNISTR2 *)talloc_zero(ctx,sizeof(UNISTR2)*num_names);
		if (uni_name == NULL)
			return False;
	}

	for (i = 0; i < num_names; i++) {
		int len = names[i] != NULL ? strlen(names[i]) : 0;
		DEBUG(10, ("names[%d]:%s\n", i, names[i]));
		init_uni_hdr(&hdr_name[i], len);
		init_unistr2(&uni_name[i], names[i], len);
	}

	*pp_uni_name = uni_name;
	*pp_hdr_name = hdr_name;

	return True;
}

/*******************************************************************
 _samr_lookup_rids
 ********************************************************************/

NTSTATUS _samr_lookup_rids(pipes_struct *p, SAMR_Q_LOOKUP_RIDS *q_u, SAMR_R_LOOKUP_RIDS *r_u)
{
	fstring group_names[MAX_SAM_ENTRIES];
	uint32 *group_attrs = NULL;
	UNIHDR *hdr_name = NULL;
	UNISTR2 *uni_name = NULL;
	DOM_SID pol_sid;
	int num_rids = q_u->num_rids1;
	int i;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_lookup_rids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &pol_sid))
		return NT_STATUS_INVALID_HANDLE;

	if (num_rids > MAX_SAM_ENTRIES) {
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("_samr_lookup_rids: truncating entries to %d\n", num_rids));
	}

	if (num_rids) {
		if ((group_attrs = (uint32 *)talloc_zero(p->mem_ctx, num_rids * sizeof(uint32))) == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	r_u->status = NT_STATUS_NONE_MAPPED;

	for (i = 0; i < num_rids; i++) {
		fstring tmpname;
		fstring domname;
		DOM_SID sid;
   		enum SID_NAME_USE type;

		group_attrs[i] = SID_NAME_UNKNOWN;
		*group_names[i] = '\0';

		if (sid_equal(&pol_sid, &global_sam_sid)) {
			sid_copy(&sid, &pol_sid);
			sid_append_rid(&sid, q_u->rid[i]);

			if (lookup_sid(&sid, domname, tmpname, &type)) {
				r_u->status = NT_STATUS_OK;
				group_attrs[i] = (uint32)type;
				fstrcpy(group_names[i],tmpname);
			}
		}
	}

	if(!make_samr_lookup_rids(p->mem_ctx, num_rids, group_names, &hdr_name, &uni_name))
		return NT_STATUS_NO_MEMORY;

	init_samr_r_lookup_rids(r_u, num_rids, hdr_name, uni_name, group_attrs);

	DEBUG(5,("_samr_lookup_rids: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _api_samr_open_user. Safe - gives out no passwd info.
 ********************************************************************/

NTSTATUS _api_samr_open_user(pipes_struct *p, SAMR_Q_OPEN_USER *q_u, SAMR_R_OPEN_USER *r_u)
{
	SAM_ACCOUNT *sampass=NULL;
	DOM_SID sid;
	POLICY_HND domain_pol = q_u->domain_pol;
	uint32 user_rid = q_u->user_rid;
	POLICY_HND *user_pol = &r_u->user_pol;
	struct samr_info *info = NULL;
	BOOL ret;

	r_u->status = NT_STATUS_OK;

	/* find the domain policy handle. */
	if (!find_policy_by_hnd(p, &domain_pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	pdb_init_sam(&sampass);

	become_root();
	ret=pdb_getsampwrid(sampass, user_rid);
	unbecome_root();

	/* check that the RID exists in our domain. */
	if (ret == False) {
		pdb_free_sam(sampass);
        	return NT_STATUS_NO_SUCH_USER;
	}

	samr_clear_sam_passwd(sampass);
	pdb_free_sam(sampass);

	/* Get the domain SID stored in the domain policy */
	if(!get_lsa_policy_samr_sid(p, &domain_pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	/* append the user's RID to it */
	if(!sid_append_rid(&sid, user_rid))
		return NT_STATUS_NO_SUCH_USER;

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/*************************************************************************
 get_user_info_10. Safe. Only gives out acb bits.
 *************************************************************************/

static BOOL get_user_info_10(SAM_USER_INFO_10 *id10, uint32 user_rid)
{
	SAM_ACCOUNT *smbpass=NULL;
	BOOL ret;

	if (!pdb_rid_is_user(user_rid)) {
		DEBUG(4,("RID 0x%x is not a user RID\n", user_rid));
		return False;
	}

	pdb_init_sam(&smbpass);

	become_root();
	ret = pdb_getsampwrid(smbpass, user_rid);
	unbecome_root();

	if (ret==False) {
		DEBUG(4,("User 0x%x not found\n", user_rid));
		pdb_free_sam(smbpass);
		return False;
	}

	DEBUG(3,("User:[%s]\n", pdb_get_username(smbpass) ));

	ZERO_STRUCTP(id10);
	init_sam_user_info10(id10, pdb_get_acct_ctrl(smbpass) );

	samr_clear_sam_passwd(smbpass);
	pdb_free_sam(smbpass);

	return True;
}

/*************************************************************************
 get_user_info_12. OK - this is the killer as it gives out password info.
 Ensure that this is only allowed on an encrypted connection with a root
 user. JRA.
 *************************************************************************/

static NTSTATUS get_user_info_12(pipes_struct *p, SAM_USER_INFO_12 * id12, uint32 user_rid)
{
	SAM_ACCOUNT *smbpass=NULL;
	BOOL ret;

	if (!p->ntlmssp_auth_validated)
		return NT_STATUS_ACCESS_DENIED;

	if (!(p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SIGN) || !(p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SEAL))
		return NT_STATUS_ACCESS_DENIED;

	/*
	 * Do *NOT* do become_root()/unbecome_root() here ! JRA.
	 */
	pdb_init_sam(&smbpass);

	ret = pdb_getsampwrid(smbpass, user_rid);

	if (ret == False) {
		DEBUG(4, ("User 0x%x not found\n", user_rid));
		pdb_free_sam(smbpass);
		return (geteuid() == (uid_t)0) ? NT_STATUS_NO_SUCH_USER : NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(3,("User:[%s] 0x%x\n", pdb_get_username(smbpass), pdb_get_acct_ctrl(smbpass) ));

	if ( pdb_get_acct_ctrl(smbpass) & ACB_DISABLED) {
		pdb_free_sam(smbpass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	ZERO_STRUCTP(id12);
	init_sam_user_info12(id12, pdb_get_lanman_passwd(smbpass), pdb_get_nt_passwd(smbpass));
	
	pdb_free_sam(smbpass);

	return NT_STATUS_OK;
}

#if 1 /* JRA - re-enabled... JERRY - why was this removed ? */
/*************************************************************************
 get_user_info_20
 *************************************************************************/

static BOOL get_user_info_20(SAM_USER_INFO_20 *id20, uint32 user_rid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;

	if (!pdb_rid_is_user(user_rid)) {
		DEBUG(4,("RID 0x%x is not a user RID\n", user_rid));
		return False;
	}

	pdb_init_sam(&sampass);

	become_root();
	ret = pdb_getsampwrid(sampass, user_rid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User 0x%x not found\n", user_rid));
		pdb_free_sam(sampass);
		return False;
	}

	samr_clear_sam_passwd(sampass);

	DEBUG(3,("User:[%s]\n",  pdb_get_username(sampass) ));

	ZERO_STRUCTP(id20);
	init_sam_user_info20A(id20, sampass);
	
	pdb_free_sam(sampass);

	return True;
}
#endif

/*************************************************************************
 get_user_info_21
 *************************************************************************/

static BOOL get_user_info_21(SAM_USER_INFO_21 *id21, uint32 user_rid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;

	if (!pdb_rid_is_user(user_rid)) {
		DEBUG(4,("RID 0x%x is not a user RID\n", user_rid));
		return False;
	}

	pdb_init_sam(&sampass);

	become_root();
	ret = pdb_getsampwrid(sampass, user_rid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User 0x%x not found\n", user_rid));
		pdb_free_sam(sampass);
		return False;
	}

	samr_clear_sam_passwd(sampass);

	DEBUG(3,("User:[%s]\n",  pdb_get_username(sampass) ));

	ZERO_STRUCTP(id21);
	init_sam_user_info21A(id21, sampass);
	
	pdb_free_sam(sampass);

	return True;
}

/*******************************************************************
 _samr_query_userinfo
 ********************************************************************/

NTSTATUS _samr_query_userinfo(pipes_struct *p, SAMR_Q_QUERY_USERINFO *q_u, SAMR_R_QUERY_USERINFO *r_u)
{
	SAM_USERINFO_CTR *ctr;
	uint32 rid = 0;
	struct samr_info *info = NULL;

	r_u->status=NT_STATUS_OK;

	/* search for the handle */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* find the user's rid */
	if ((rid = get_lsa_policy_samr_rid(info)) == 0xffffffff)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	DEBUG(5,("_samr_query_userinfo: rid:0x%x\n", rid));

	ctr = (SAM_USERINFO_CTR *)talloc_zero(p->mem_ctx, sizeof(SAM_USERINFO_CTR));
	if (!ctr)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(ctr);

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	ctr->switch_value = q_u->switch_value;

	switch (q_u->switch_value) {
	case 0x10:
		ctr->info.id10 = (SAM_USER_INFO_10 *)talloc_zero(p->mem_ctx, sizeof(SAM_USER_INFO_10));
		if (ctr->info.id10 == NULL)
			return NT_STATUS_NO_MEMORY;

		if (!get_user_info_10(ctr->info.id10, rid))
			return NT_STATUS_NO_SUCH_USER;
		break;

#if 0
/* whoops - got this wrong.  i think.  or don't understand what's happening. */
        case 0x11:
        {
            NTTIME expire;
            info = (void *)&id11;

            expire.low = 0xffffffff;
            expire.high = 0x7fffffff;

            ctr->info.id = (SAM_USER_INFO_11 *)talloc_zero(p->mem_ctx,
                                    sizeof
                                    (*ctr->
                                     info.
                                     id11));
            init_sam_user_info11(ctr->info.id11, &expire,
                         "BROOKFIELDS$",    /* name */
                         0x03ef,    /* user rid */
                         0x201, /* group rid */
                         0x0080);   /* acb info */

            break;
        }
#endif

	case 0x12:
		ctr->info.id12 = (SAM_USER_INFO_12 *)talloc_zero(p->mem_ctx, sizeof(SAM_USER_INFO_12));
		if (ctr->info.id12 == NULL)
			return NT_STATUS_NO_MEMORY;

		if (NT_STATUS_IS_ERR(r_u->status = get_user_info_12(p, ctr->info.id12, rid)))
			return r_u->status;
		break;

	case 20:
		ctr->info.id20 = (SAM_USER_INFO_20 *)talloc_zero(p->mem_ctx,sizeof(SAM_USER_INFO_20));
		if (ctr->info.id20 == NULL)
			return NT_STATUS_NO_MEMORY;
		if (!get_user_info_20(ctr->info.id20, rid))
			return NT_STATUS_NO_SUCH_USER;
		break;

	case 21:
		ctr->info.id21 = (SAM_USER_INFO_21 *)talloc_zero(p->mem_ctx,sizeof(SAM_USER_INFO_21));
		if (ctr->info.id21 == NULL)
			return NT_STATUS_NO_MEMORY;
		if (!get_user_info_21(ctr->info.id21, rid))
			return NT_STATUS_NO_SUCH_USER;
		break;

	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	init_samr_r_query_userinfo(r_u, ctr, r_u->status);

	DEBUG(5,("_samr_query_userinfo: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_reply_query_usergroups
 ********************************************************************/

NTSTATUS _samr_query_usergroups(pipes_struct *p, SAMR_Q_QUERY_USERGROUPS *q_u, SAMR_R_QUERY_USERGROUPS *r_u)
{
	SAM_ACCOUNT *sam_pass=NULL;
	DOM_GID *gids = NULL;
	int num_groups = 0;
	pstring groups;
	uint32 rid;
	struct samr_info *info = NULL;
	BOOL ret;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* find the user's rid */
	if ((rid = get_lsa_policy_samr_rid(info)) == 0xffffffff)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	pdb_init_sam(&sam_pass);

	become_root();
	ret = pdb_getsampwrid(sam_pass, rid);
	unbecome_root();

	if (ret == False) {
		samr_clear_sam_passwd(sam_pass);
		pdb_free_sam(sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}

	get_domain_user_groups(groups, pdb_get_username(sam_pass));
	gids = NULL;
	num_groups = make_dom_gids(p->mem_ctx, groups, &gids);

	/* construct the response.  lkclXXXX: gids are not copied! */
	init_samr_r_query_usergroups(r_u, num_groups, gids, r_u->status);

	DEBUG(5,("_samr_query_usergroups: %d\n", __LINE__));
	
	samr_clear_sam_passwd(sam_pass);
	pdb_free_sam(sam_pass);

	return r_u->status;
}

/*******************************************************************
 _samr_query_dom_info
 ********************************************************************/

NTSTATUS _samr_query_dom_info(pipes_struct *p, SAMR_Q_QUERY_DOMAIN_INFO *q_u, SAMR_R_QUERY_DOMAIN_INFO *r_u)
{
	struct samr_info *info = NULL;
	SAM_UNK_CTR *ctr;
	uint32 min_pass_len,pass_hist,flag;
	time_t u_expire, u_min_age;
	NTTIME nt_expire, nt_min_age;

	time_t u_lock_duration, u_reset_time;
	NTTIME nt_lock_duration, nt_reset_time;
	uint32 lockout;
	
	time_t u_logout;
	NTTIME nt_logout;

	uint32 num_users=0, num_groups=0, num_aliases=0;

	if ((ctr = (SAM_UNK_CTR *)talloc_zero(p->mem_ctx, sizeof(SAM_UNK_CTR))) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(ctr);

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_dom_info: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->domain_pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	switch (q_u->switch_value) {
		case 0x01:
			/* Use defaults until we merge with HEAD db. JRA */
			min_pass_len = MINPASSWDLENGTH;		/* 5 chars minimum             */
			pass_hist = 0;				/* don't keep any old password */
			flag = 0;				/* don't force user to logon   */
			u_expire = MAX_PASSWORD_AGE;		/* 21 days                     */
			u_min_age = 0;				/* 0 days                      */

			unix_to_nt_time_abs(&nt_expire, u_expire);
			unix_to_nt_time_abs(&nt_min_age, u_min_age);

			init_unk_info1(&ctr->info.inf1, (uint16)min_pass_len, (uint16)pass_hist, 
			               flag, nt_expire, nt_min_age);
			break;
		case 0x02:
			become_root();		
			r_u->status=load_sampwd_entries(info, ACB_NORMAL);
			unbecome_root();
			if (NT_STATUS_IS_ERR(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_sampwd_entries failed\n"));
				return r_u->status;
			}
			num_users=info->disp_info.num_user_account;
			free_samr_db(info);
			
			r_u->status=load_group_domain_entries(info, &global_sam_sid);
			if (NT_STATUS_IS_ERR(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_group_domain_entries failed\n"));
				return r_u->status;
			}
			num_groups=info->disp_info.num_group_account;
			free_samr_db(info);
			
			/* The time call below is to get a sequence number for the sam. FIXME !!! JRA. */
			init_unk_info2(&ctr->info.inf2, global_myworkgroup, global_myname, (uint32) time(NULL), 
				       num_users, num_groups, num_aliases);
			break;
		case 0x03:
			/* Use defaults until we merge with HEAD db. JRA */
			u_logout = -1;				/* don't force logout          */
			unix_to_nt_time_abs(&nt_logout, u_logout);
			init_unk_info3(&ctr->info.inf3, nt_logout);
			break;
		case 0x05:
			init_unk_info5(&ctr->info.inf5, global_myname);
			break;
		case 0x06:
			init_unk_info6(&ctr->info.inf6);
			break;
		case 0x07:
			init_unk_info7(&ctr->info.inf7);
			break;
		case 0x0c:
			/* Use defaults until we merge with HEAD db. JRA */
			u_lock_duration = 0;			/* lockout for 0 minutes       */
			u_reset_time = 0;			/* reset immediatly            */
			lockout = 0;				/* don't lockout               */
	
			unix_to_nt_time_abs(&nt_lock_duration, u_lock_duration);
			unix_to_nt_time_abs(&nt_reset_time, u_reset_time);
	
            		init_unk_info12(&ctr->info.inf12, nt_lock_duration, nt_reset_time, (uint16)lockout);
            		break;
        	default:
            		return NT_STATUS_INVALID_INFO_CLASS;
	}

	init_samr_r_query_dom_info(r_u, q_u->switch_value, ctr, NT_STATUS_OK);

	DEBUG(5,("_samr_query_dom_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _api_samr_create_user
 Create an account, can be either a normal user or a machine.
 This funcion will need to be updated for bdc/domain trusts.
 ********************************************************************/

NTSTATUS _api_samr_create_user(pipes_struct *p, SAMR_Q_CREATE_USER *q_u, SAMR_R_CREATE_USER *r_u)
{
	SAM_ACCOUNT *sam_pass=NULL;
	fstring mach_acct;
	pstring err_str;
	pstring msg_str;
	int local_flags=0;
	DOM_SID sid;
	pstring add_script;
	POLICY_HND dom_pol = q_u->domain_pol;
	UNISTR2 user_account = q_u->uni_name;
	uint16 acb_info = q_u->acb_info;
	POLICY_HND *user_pol = &r_u->user_pol;
	struct samr_info *info = NULL;
	BOOL ret;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &dom_pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	/* find the machine account: tell the caller if it exists.
	  lkclXXXX i have *no* idea if this is a problem or not
 	  or even if you are supposed to construct a different
	  reply if the account already exists...
	 */

	fstrcpy(mach_acct, dos_unistrn2(user_account.buffer, user_account.uni_str_len));
	strlower(mach_acct);

	pdb_init_sam(&sam_pass);

	become_root();
	ret = pdb_getsampwnam(sam_pass, mach_acct);
	unbecome_root();
	if (ret == True) {
		/* machine account exists: say so */
		pdb_free_sam(sam_pass);
		return NT_STATUS_USER_EXISTS;
	}

	local_flags=LOCAL_ADD_USER|LOCAL_DISABLE_USER|LOCAL_SET_NO_PASSWORD;
	local_flags|= (acb_info & ACB_WSTRUST) ? LOCAL_TRUST_ACCOUNT:0;

	/*
	 * NB. VERY IMPORTANT ! This call must be done as the current pipe user,
	 * *NOT* surrounded by a become_root()/unbecome_root() call. This ensures
	 * that only people with write access to the smbpasswd file will be able
	 * to create a user. JRA.
	 */

	/*
	 * add the user in the /etc/passwd file or the unix authority system.
	 * We don't check if the smb_create_user() function succed or not for 2 reasons:
	 * a) local_password_change() checks for us if the /etc/passwd account really exists
	 * b) smb_create_user() would return an error if the account already exists
	 * and as it could return an error also if it can't create the account, it would be tricky.
	 *
	 * So we go the easy way, only check after if the account exists.
	 * JFM (2/3/2001), to clear any possible bad understanding (-:
	 */
 
	pstrcpy(add_script, lp_adduser_script());
 
	if(*add_script)
		smb_create_user(mach_acct, NULL);

	/* add the user in the smbpasswd file or the Samba authority database */
	if (!local_password_change(mach_acct, local_flags, NULL, err_str, sizeof(err_str), msg_str, sizeof(msg_str))) {
		DEBUG(0, ("%s\n", err_str));
		pdb_free_sam(sam_pass);
		return NT_STATUS_ACCESS_DENIED;
	}

	become_root();
	ret = pdb_getsampwnam(sam_pass, mach_acct);
 	unbecome_root();
 	if (ret == False) {
		/* account doesn't exist: say so */
		pdb_free_sam(sam_pass);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Get the domain SID stored in the domain policy */
	if(!get_lsa_policy_samr_sid(p, &dom_pol, &sid)) {
		pdb_free_sam(sam_pass);
		return NT_STATUS_INVALID_HANDLE;
	}

	/* append the user's RID to it */
	if(!sid_append_rid(&sid, pdb_get_user_rid(sam_pass) )) {
		pdb_free_sam(sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}

	/* associate the user's SID with the new handle. */
	
	if ((info = get_samr_info_by_sid(&sid)) == NULL) {
		pdb_free_sam(sam_pass);
		return NT_STATUS_NO_MEMORY;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info)) {
		pdb_free_sam(sam_pass);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	r_u->user_rid=sam_pass->user_rid;
	r_u->unknown_0 = 0x000703ff;

	pdb_free_sam(sam_pass);

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_reply_connect_anon
 ********************************************************************/

NTSTATUS _samr_connect_anon(pipes_struct *p, SAMR_Q_CONNECT_ANON *q_u, SAMR_R_CONNECT_ANON *r_u)
{
	struct samr_info *info = NULL;

	/* set up the SAMR connect_anon response */

	r_u->status = NT_STATUS_OK;

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->status = q_u->unknown_0;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->connect_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/*******************************************************************
 samr_reply_connect
 ********************************************************************/

NTSTATUS _samr_connect(pipes_struct *p, SAMR_Q_CONNECT *q_u, SAMR_R_CONNECT *r_u)
{
	struct samr_info *info = NULL;

	DEBUG(5,("_samr_connect: %d\n", __LINE__));

	r_u->status = NT_STATUS_OK;

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->status = q_u->access_mask;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->connect_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_connect: %d\n", __LINE__));

	return r_u->status;
}

/**********************************************************************
 api_samr_lookup_domain
 **********************************************************************/

NTSTATUS _samr_lookup_domain(pipes_struct *p, SAMR_Q_LOOKUP_DOMAIN *q_u, SAMR_R_LOOKUP_DOMAIN *r_u)
{
	fstring domain_name;
	DOM_SID sid;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->connect_pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	fstrcpy(domain_name, dos_unistrn2( q_u->uni_domain.buffer, q_u->uni_domain.uni_str_len));

	ZERO_STRUCT(sid);

	if (!secrets_fetch_domain_sid(domain_name, &sid)) {
		r_u->status = NT_STATUS_NO_SUCH_DOMAIN;
	}

	DEBUG(2,("Returning domain sid for domain %s -> %s\n", domain_name, sid_string_static(&sid)));

	init_samr_r_lookup_domain(r_u, &sid, r_u->status);

	return r_u->status;
}

/******************************************************************
makes a SAMR_R_ENUM_DOMAINS structure.
********************************************************************/

static BOOL make_enum_domains(TALLOC_CTX *ctx, SAM_ENTRY **pp_sam,
			UNISTR2 **pp_uni_name, uint32 num_sam_entries, fstring doms[])
{
	uint32 i;
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;

	DEBUG(5, ("make_enum_domains\n"));

	*pp_sam = NULL;
	*pp_uni_name = NULL;

	if (num_sam_entries == 0)
		return True;

	sam = (SAM_ENTRY *)talloc_zero(ctx, sizeof(SAM_ENTRY)*num_sam_entries);
	uni_name = (UNISTR2 *)talloc_zero(ctx, sizeof(UNISTR2)*num_sam_entries);

	if (sam == NULL || uni_name == NULL)
		return False;

	for (i = 0; i < num_sam_entries; i++) {
		int len = doms[i] != NULL ? strlen(doms[i]) : 0;

		init_sam_entry(&sam[i], len, 0);
		init_unistr2(&uni_name[i], doms[i], len);
	}

	*pp_sam = sam;
	*pp_uni_name = uni_name;

	return True;
}

/**********************************************************************
 api_samr_enum_domains
 **********************************************************************/

NTSTATUS _samr_enum_domains(pipes_struct *p, SAMR_Q_ENUM_DOMAINS *q_u, SAMR_R_ENUM_DOMAINS *r_u)
{
	uint32 num_entries = 2;
	fstring dom[2];
	char *name;

	r_u->status = NT_STATUS_OK;

	switch (lp_server_role()) {
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			name = global_myworkgroup;
			break;
		default:
			name = global_myname;
	}

	fstrcpy(dom[0],name);
	strupper(dom[0]);
	fstrcpy(dom[1],"Builtin");

	if (!make_enum_domains(p->mem_ctx, &r_u->sam, &r_u->uni_dom_name, num_entries, dom))
		return NT_STATUS_NO_MEMORY;

	init_samr_r_enum_domains(r_u, q_u->start_idx + num_entries, num_entries);

	return r_u->status;
}

/*******************************************************************
 api_samr_open_alias
 ********************************************************************/

NTSTATUS _api_samr_open_alias(pipes_struct *p, SAMR_Q_OPEN_ALIAS *q_u, SAMR_R_OPEN_ALIAS *r_u)
{
	DOM_SID sid;
	POLICY_HND domain_pol = q_u->dom_pol;
	uint32 alias_rid = q_u->rid_alias;
	POLICY_HND *alias_pol = &r_u->pol;
	struct samr_info *info = NULL;

	r_u->status = NT_STATUS_OK;

	/* get the domain policy. */
	if (!find_policy_by_hnd(p, &domain_pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	/* Get the domain SID stored in the domain policy */
	if(!get_lsa_policy_samr_sid(p, &domain_pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	/* append the alias' RID to it */
	if(!sid_append_rid(&sid, alias_rid))
		return NT_STATUS_NO_SUCH_USER;

	/*
	 * we should check if the rid really exist !!!
	 * JFM.
	 */

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, alias_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/*******************************************************************
 set_user_info_10
 ********************************************************************/

static BOOL set_user_info_10(const SAM_USER_INFO_10 *id10, uint32 rid)
{
	SAM_ACCOUNT *pwd =NULL;
	BOOL ret;
	
	pdb_init_sam(&pwd);
	
	ret = pdb_getsampwrid(pwd, rid);
	
	if(ret==False) {
		pdb_free_sam(pwd);
		return False;
	}

	if (id10 == NULL) {
		DEBUG(5, ("set_user_info_10: NULL id10\n"));
		pdb_free_sam(pwd);
		return False;
	}

	if (!pdb_set_acct_ctrl(pwd, id10->acb_info)) {
		pdb_free_sam(pwd);
		return False;
	}

	if(!pdb_update_sam_account(pwd, True)) {
		pdb_free_sam(pwd);
		return False;
	}

	pdb_free_sam(pwd);

	return True;
}

/*******************************************************************
 set_user_info_12
 ********************************************************************/

static BOOL set_user_info_12(SAM_USER_INFO_12 *id12, uint32 rid)
{
	SAM_ACCOUNT *pwd = NULL;

	pdb_init_sam(&pwd);

	if(!pdb_getsampwrid(pwd, rid)) {
		pdb_free_sam(pwd);
		return False;
	}

	if (id12 == NULL) {
		DEBUG(2, ("set_user_info_12: id12 is NULL\n"));
		pdb_free_sam(pwd);
		return False;
	}
 
	if (!pdb_set_lanman_passwd (pwd, id12->lm_pwd)) {
		pdb_free_sam(pwd);
		return False;
	}
	if (!pdb_set_nt_passwd(pwd, id12->nt_pwd)) {
		pdb_free_sam(pwd);
		return False;
	}
 
	if(!pdb_update_sam_account(pwd, True)) {
		pdb_free_sam(pwd);
		return False;
 	}

	pdb_free_sam(pwd);
	return True;
}

/*******************************************************************
 set_user_info_21
 ********************************************************************/

static BOOL set_user_info_21(SAM_USER_INFO_21 *id21, uint32 rid)
{
	SAM_ACCOUNT *pwd = NULL;
	BOOL result = True;
 
	if (id21 == NULL) {
		DEBUG(5, ("set_user_info_21: NULL id21\n"));
		return False;
	}
 
	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwrid(pwd, rid)) {
		result = False;
		goto done;
	}
 
	/* we make a copy so that we can modify stuff */
	copy_id21_to_sam_passwd(pwd, id21);
 
	/*
	 * The funny part about the previous two calls is
	 * that pwd still has the password hashes from the
	 * passdb entry.  These have not been updated from
	 * id21.  I don't know if they need to be set.    --jerry
	 */
 
	/* write the change out */
	if(!pdb_update_sam_account(pwd, True)) {
		result = False;
		goto done;
 	}

done:
	pdb_free_sam(pwd);
	return result;
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/

static BOOL set_user_info_23(SAM_USER_INFO_23 *id23, uint32 rid)
{
	SAM_ACCOUNT *pwd = NULL;
	uint8 nt_hash[16];
	uint8 lm_hash[16];
	pstring buf;
	uint32 len;
	uint16 acct_ctrl;
	BOOL result = True;
 
	if (id23 == NULL) {
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return False;
	}
 
 	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwrid(pwd, rid)) {
		result = False;
		goto done;
 	}

	acct_ctrl = pdb_get_acct_ctrl(pwd);
	
	copy_id23_to_sam_passwd(pwd, id23);
 
	if (!decode_pw_buffer((char*)id23->pass, buf, 256, &len, nt_hash, lm_hash)) {
		result = False;
		goto done;
 	}
  
	if (!pdb_set_lanman_passwd (pwd, lm_hash)) {
		result = False;
		goto done;
	}
	if (!pdb_set_nt_passwd(pwd, nt_hash)) {
		result = False;
		goto done;
	}
 
	/* if it's a trust account, don't update /etc/passwd */
	if ( ( (acct_ctrl &  ACB_DOMTRUST) == ACB_DOMTRUST ) ||
	     ( (acct_ctrl &  ACB_WSTRUST) ==  ACB_WSTRUST) ||
	     ( (acct_ctrl &  ACB_SVRTRUST) ==  ACB_SVRTRUST) ) {
	     DEBUG(5, ("Changing trust account password, not updating /etc/passwd\n"));
	} else  {
		/* update the UNIX password */
		if (lp_unix_password_sync() )
			if(!chgpasswd(pdb_get_username(pwd), "", buf, True)) {
				result = False;
				goto done;
			}
	}
 
	memset(buf, 0, sizeof(buf));
 
	if(!pdb_update_sam_account(pwd, True)) {
		result = False;
		goto done;
	}
 
done:
	pdb_free_sam(pwd);
	return result;
}

/*******************************************************************
 set_user_info_pw
 ********************************************************************/

static BOOL set_user_info_pw(char *pass, uint32 rid)
{
	SAM_ACCOUNT *pwd = NULL;
	uchar nt_hash[16];
	uchar lm_hash[16];
	uint32 len;
	pstring buf;
	uint16 acct_ctrl;
 
 	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwrid(pwd, rid)) {
		pdb_free_sam(pwd);
		return False;
 	}
	
	acct_ctrl = pdb_get_acct_ctrl(pwd);

	memset(buf, 0, sizeof(buf));
 
	if (!decode_pw_buffer(pass, buf, 256, &len, nt_hash, lm_hash)) {
		pdb_free_sam(pwd);
		return False;
 	}

	if (!pdb_set_lanman_passwd (pwd, lm_hash)) {
		pdb_free_sam(pwd);
		return False;
	}
	if (!pdb_set_nt_passwd(pwd, nt_hash)) {
		pdb_free_sam(pwd);
		return False;
	}
 
	/* if it's a trust account, don't update /etc/passwd */
	if ( ( (acct_ctrl &  ACB_DOMTRUST) == ACB_DOMTRUST ) ||
	     ( (acct_ctrl &  ACB_WSTRUST) ==  ACB_WSTRUST) ||
	     ( (acct_ctrl &  ACB_SVRTRUST) ==  ACB_SVRTRUST) ) {
	     DEBUG(5, ("Changing trust account password, not updating /etc/passwd\n"));
	} else {
		/* update the UNIX password */
		if (lp_unix_password_sync())
			if(!chgpasswd(pdb_get_username(pwd), "", buf, True)) {
				pdb_free_sam(pwd);
				return False;
			}
	}
 
	memset(buf, 0, sizeof(buf));
 
	DEBUG(5,("set_user_info_pw: pdb_update_sam_account()\n"));
 
	/* update the SAMBA password */
	if(!pdb_update_sam_account(pwd, True)) {
		pdb_free_sam(pwd);
		return False;
 	}

	pdb_free_sam(pwd);

	return True;
}

/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/

NTSTATUS _samr_set_userinfo(pipes_struct *p, SAMR_Q_SET_USERINFO *q_u, SAMR_R_SET_USERINFO *r_u)
{
	uint32 rid = 0x0;
	DOM_SID sid;
	struct current_user user;
	SAM_ACCOUNT *sam_pass=NULL;
	unsigned char sess_key[16];
	POLICY_HND *pol = &q_u->pol;
	uint16 switch_value = q_u->switch_value;
	SAM_USERINFO_CTR *ctr = q_u->ctr;
	BOOL ret;

	DEBUG(5, ("_samr_set_userinfo: %d\n", __LINE__));

	r_u->status = NT_STATUS_OK;

	if (p->ntlmssp_auth_validated) 	{
		memcpy(&user, &p->pipe_user, sizeof(user));
	} else 	{
		extern struct current_user current_user;
		memcpy(&user, &current_user, sizeof(user));
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	sid_split_rid(&sid, &rid);

	DEBUG(5, ("_samr_set_userinfo: rid:0x%x, level:%d\n", rid, switch_value));

	if (ctr == NULL) {
		DEBUG(5, ("_samr_set_userinfo: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}


	pdb_init_sam(&sam_pass);

	/* 
	 * We need the NT hash of the user who is changing the user's password.
	 * This NT hash is used to generate a "user session key"
	 * This "user session key" is in turn used to encrypt/decrypt the user's password.
	 */

	become_root();
	ret = pdb_getsampwuid(sam_pass, user.uid);
	unbecome_root();
	if(ret == False) {
		DEBUG(0,("_samr_set_userinfo: Unable to get smbpasswd entry for uid %u\n", (unsigned int)user.uid ));
		pdb_free_sam(sam_pass);
		return NT_STATUS_ACCESS_DENIED;
	}
		
	memset(sess_key, '\0', 16);
	mdfour(sess_key, pdb_get_nt_passwd(sam_pass), 16);

	pdb_free_sam(sam_pass);
	sam_pass = NULL;

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value) {
		case 0x12:
			if (!set_user_info_12(ctr->info.id12, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;

		case 24:
			SamOEMhash(ctr->info.id24->pass, sess_key, 516);

			dump_data(100, (char *)ctr->info.id24->pass, 516);

			if (!set_user_info_pw((char *)ctr->info.id24->pass, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;

		case 25:
#if 0
			/*
			 * Currently we don't really know how to unmarshall
			 * the level 25 struct, and the password encryption
			 * is different. This is a placeholder for when we
			 * do understand it. In the meantime just return INVALID
			 * info level and W2K SP2 drops down to level 23... JRA.
			 */

			SamOEMhash(ctr->info.id25->pass, sess_key, 532);

			dump_data(100, (char *)ctr->info.id25->pass, 532);

			if (!set_user_info_pw(ctr->info.id25->pass, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;
#endif
			return NT_STATUS_INVALID_INFO_CLASS;

		case 23:
			SamOEMhash(ctr->info.id23->pass, sess_key, 516);

			dump_data(100, (char *)ctr->info.id23->pass, 516);

			if (!set_user_info_23(ctr->info.id23, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;

		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	return r_u->status;
}

/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/

NTSTATUS _samr_set_userinfo2(pipes_struct *p, SAMR_Q_SET_USERINFO2 *q_u, SAMR_R_SET_USERINFO2 *r_u)
{
	DOM_SID sid;
	uint32 rid = 0x0;
	SAM_USERINFO_CTR *ctr = q_u->ctr;
	POLICY_HND *pol = &q_u->pol;
	uint16 switch_value = q_u->switch_value;

	DEBUG(5, ("samr_reply_set_userinfo2: %d\n", __LINE__));

	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	sid_split_rid(&sid, &rid);

	DEBUG(5, ("samr_reply_set_userinfo2: rid:0x%x\n", rid));

	if (ctr == NULL) {
		DEBUG(5, ("samr_reply_set_userinfo2: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	switch_value=ctr->switch_value;

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value) {
		case 21:
			if (!set_user_info_21(ctr->info.id21, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		case 16:
			if (!set_user_info_10(ctr->info.id10, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		case 18:
			/* Used by AS/U JRA. */
			if (!set_user_info_12(ctr->info.id12, rid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	return r_u->status;
}

/*********************************************************************
 _samr_query_aliasmem
*********************************************************************/

NTSTATUS _samr_query_useraliases(pipes_struct *p, SAMR_Q_QUERY_USERALIASES *q_u, SAMR_R_QUERY_USERALIASES *r_u)
{
	uint32 *rid=NULL;
	int num_rids;

	num_rids = 1;
	rid=(uint32 *)talloc_zero(p->mem_ctx, num_rids*sizeof(uint32));
	if (rid == NULL)
		return NT_STATUS_NO_MEMORY;

	/* until i see a real useraliases query, we fack one up */
 
	rid[0] = BUILTIN_ALIAS_RID_USERS;
 
	init_samr_r_query_useraliases(r_u, num_rids, rid, NT_STATUS_OK);
 
	return NT_STATUS_OK;

}

/*********************************************************************
 _samr_query_aliasmem
*********************************************************************/

NTSTATUS _samr_query_aliasmem(pipes_struct *p, SAMR_Q_QUERY_ALIASMEM *q_u, SAMR_R_QUERY_ALIASMEM *r_u)
{
	DEBUG(0,("_samr_query_aliasmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_query_groupmem
*********************************************************************/

NTSTATUS _samr_query_groupmem(pipes_struct *p, SAMR_Q_QUERY_GROUPMEM *q_u, SAMR_R_QUERY_GROUPMEM *r_u)
{
	DEBUG(0,("_samr_query_groupmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_add_aliasmem
*********************************************************************/

NTSTATUS _samr_add_aliasmem(pipes_struct *p, SAMR_Q_ADD_ALIASMEM *q_u, SAMR_R_ADD_ALIASMEM *r_u)
{
	DEBUG(0,("_samr_add_aliasmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_del_aliasmem
*********************************************************************/

NTSTATUS _samr_del_aliasmem(pipes_struct *p, SAMR_Q_DEL_ALIASMEM *q_u, SAMR_R_DEL_ALIASMEM *r_u)
{
	DEBUG(0,("_samr_del_aliasmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_add_groupmem
*********************************************************************/

NTSTATUS _samr_add_groupmem(pipes_struct *p, SAMR_Q_ADD_GROUPMEM *q_u, SAMR_R_ADD_GROUPMEM *r_u)
{
	DEBUG(0,("_samr_add_groupmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_del_groupmem
*********************************************************************/

NTSTATUS _samr_del_groupmem(pipes_struct *p, SAMR_Q_DEL_GROUPMEM *q_u, SAMR_R_DEL_GROUPMEM *r_u)
{
	DEBUG(0,("_samr_del_groupmem: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_delete_dom_user
*********************************************************************/

NTSTATUS _samr_delete_dom_user(pipes_struct *p, SAMR_Q_DELETE_DOM_USER *q_u, SAMR_R_DELETE_DOM_USER *r_u )
{
	DEBUG(0,("_samr_delete_dom_user: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_delete_dom_group
*********************************************************************/

NTSTATUS _samr_delete_dom_group(pipes_struct *p, SAMR_Q_DELETE_DOM_GROUP *q_u, SAMR_R_DELETE_DOM_GROUP *r_u)
{
	DEBUG(0,("_samr_delete_dom_group: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_delete_dom_alias
*********************************************************************/

NTSTATUS _samr_delete_dom_alias(pipes_struct *p, SAMR_Q_DELETE_DOM_ALIAS *q_u, SAMR_R_DELETE_DOM_ALIAS *r_u)
{
	DEBUG(0,("_samr_delete_dom_alias: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_create_dom_group
*********************************************************************/

NTSTATUS _samr_create_dom_group(pipes_struct *p, SAMR_Q_CREATE_DOM_GROUP *q_u, SAMR_R_CREATE_DOM_GROUP *r_u)
{
	DEBUG(0,("_samr_create_dom_group: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_create_dom_alias
*********************************************************************/

NTSTATUS _samr_create_dom_alias(pipes_struct *p, SAMR_Q_CREATE_DOM_ALIAS *q_u, SAMR_R_CREATE_DOM_ALIAS *r_u)
{
	DEBUG(0,("_samr_create_dom_alias: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_query_groupinfo
*********************************************************************/

NTSTATUS _samr_query_groupinfo(pipes_struct *p, SAMR_Q_QUERY_GROUPINFO *q_u, SAMR_R_QUERY_GROUPINFO *r_u)
{
	DEBUG(0,("_samr_query_groupinfo: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_set_groupinfo
*********************************************************************/

NTSTATUS _samr_set_groupinfo(pipes_struct *p, SAMR_Q_SET_GROUPINFO *q_u, SAMR_R_SET_GROUPINFO *r_u)
{
	DEBUG(0,("_samr_set_groupinfo: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_get_dom_pwinfo
*********************************************************************/

NTSTATUS _samr_get_dom_pwinfo(pipes_struct *p, SAMR_Q_GET_DOM_PWINFO *q_u, SAMR_R_GET_DOM_PWINFO *r_u)
{
	/* Actually, returning zeros here works quite well :-). */
	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_open_group
*********************************************************************/

NTSTATUS _samr_open_group(pipes_struct *p, SAMR_Q_OPEN_GROUP *q_u, SAMR_R_OPEN_GROUP *r_u)
{
	DEBUG(0,("_samr_open_group: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 _samr_unknown_2d
*********************************************************************/

NTSTATUS _samr_unknown_2d(pipes_struct *p, SAMR_Q_UNKNOWN_2D *q_u, SAMR_R_UNKNOWN_2D *r_u)
{
	DEBUG(0,("_samr_unknown_2d: Not yet implemented.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}
