/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Marc Jacobsen			    1999,
 *  Copyright (C) Jeremy Allison               2001-2002,
 *  Copyright (C) Jean François Micouleau      1998-2001,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002,
 *  Copyright (C) Gerald (Jerry) Carter             2003,
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

extern DOM_SID global_sid_Builtin;

extern rid_name domain_group_rids[];
extern rid_name domain_alias_rids[];
extern rid_name builtin_alias_rids[];


typedef struct _disp_info {
	BOOL user_dbloaded;
	uint32 num_user_account;
	SAM_ACCOUNT *disp_user_info;
	BOOL group_dbloaded;
	uint32 num_group_account;
	DOMAIN_GRP *disp_group_info;
} DISP_INFO;

struct samr_info {
	/* for use by the \PIPE\samr policy */
	DOM_SID sid;
	uint32 status; /* some sort of flag.  best to record it.  comes from opnum 0x39 */
	uint32 acc_granted;
	uint16 acb_mask;
	BOOL all_machines;
	DISP_INFO disp_info;

	TALLOC_CTX *mem_ctx;
};

struct generic_mapping sam_generic_mapping = {GENERIC_RIGHTS_SAM_READ, GENERIC_RIGHTS_SAM_WRITE, GENERIC_RIGHTS_SAM_EXECUTE, GENERIC_RIGHTS_SAM_ALL_ACCESS};
struct generic_mapping dom_generic_mapping = {GENERIC_RIGHTS_DOMAIN_READ, GENERIC_RIGHTS_DOMAIN_WRITE, GENERIC_RIGHTS_DOMAIN_EXECUTE, GENERIC_RIGHTS_DOMAIN_ALL_ACCESS};
struct generic_mapping usr_generic_mapping = {GENERIC_RIGHTS_USER_READ, GENERIC_RIGHTS_USER_WRITE, GENERIC_RIGHTS_USER_EXECUTE, GENERIC_RIGHTS_USER_ALL_ACCESS};
struct generic_mapping grp_generic_mapping = {GENERIC_RIGHTS_GROUP_READ, GENERIC_RIGHTS_GROUP_WRITE, GENERIC_RIGHTS_GROUP_EXECUTE, GENERIC_RIGHTS_GROUP_ALL_ACCESS};
struct generic_mapping ali_generic_mapping = {GENERIC_RIGHTS_ALIAS_READ, GENERIC_RIGHTS_ALIAS_WRITE, GENERIC_RIGHTS_ALIAS_EXECUTE, GENERIC_RIGHTS_ALIAS_ALL_ACCESS};

static NTSTATUS samr_make_dom_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size);

/*******************************************************************
 Checks if access to an object should be granted, and returns that
 level of access for further checks.
********************************************************************/

NTSTATUS access_check_samr_object(SEC_DESC *psd, NT_USER_TOKEN *nt_user_token, uint32 des_access, 
				  uint32 *acc_granted, const char *debug) 
{
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;

	if (!se_access_check(psd, nt_user_token, des_access, acc_granted, &status)) {
		*acc_granted = des_access;
		if (geteuid() == sec_initial_uid()) {
			DEBUG(4,("%s: ACCESS should be DENIED  (requested: %#010x)\n",
				debug, des_access));
			DEBUGADD(4,("but overritten by euid == sec_initial_uid()\n"));
			status = NT_STATUS_OK;
		}
		else {
			DEBUG(2,("%s: ACCESS DENIED  (requested: %#010x)\n",
				debug, des_access));
		}
	}
	return status;
}

/*******************************************************************
 Checks if access to a function can be granted
********************************************************************/

NTSTATUS access_check_samr_function(uint32 acc_granted, uint32 acc_required, const char *debug)
{
	DEBUG(5,("%s: access check ((granted: %#010x;  required: %#010x)\n",
			debug, acc_granted, acc_required));
	if ((acc_granted & acc_required) != acc_required) {
		if (geteuid() == sec_initial_uid()) {
			DEBUG(4,("%s: ACCESS should be DENIED (granted: %#010x;  required: %#010x)\n",
				debug, acc_granted, acc_required));
			DEBUGADD(4,("but overwritten by euid == 0\n"));
			return NT_STATUS_OK;
		}
		DEBUG(2,("%s: ACCESS DENIED (granted: %#010x;  required: %#010x)\n",
			debug, acc_granted, acc_required));
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}


/*******************************************************************
 Create a samr_info struct.
********************************************************************/

static struct samr_info *get_samr_info_by_sid(DOM_SID *psid)
{
	struct samr_info *info;
	fstring sid_str;
	TALLOC_CTX *mem_ctx;
	
	if (psid) {
		sid_to_string(sid_str, psid);
	} else {
		fstrcpy(sid_str,"(NULL)");
	}

	mem_ctx = talloc_init("samr_info for domain sid %s", sid_str);

	if ((info = (struct samr_info *)talloc(mem_ctx, sizeof(struct samr_info))) == NULL)
		return NULL;

	ZERO_STRUCTP(info);
	DEBUG(10,("get_samr_info_by_sid: created new info for sid %s\n", sid_str));
	if (psid) {
		sid_copy( &info->sid, psid);
	} else {
		DEBUG(10,("get_samr_info_by_sid: created new info for NULL sid.\n"));
	}
	info->mem_ctx = mem_ctx;
	return info;
}

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_samr_users(struct samr_info *info) 
{
	int i;

	if (info->disp_info.user_dbloaded){
		for (i=0; i<info->disp_info.num_user_account; i++) {
			SAM_ACCOUNT *sam = &info->disp_info.disp_user_info[i];
			/* Not really a free, actually a 'clear' */
			pdb_free_sam(&sam);
		}
	}
	info->disp_info.user_dbloaded=False;
	info->disp_info.num_user_account=0;
}

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_samr_db(struct samr_info *info)
{
	/* Groups are talloced */

	free_samr_users(info);

	info->disp_info.group_dbloaded=False;
	info->disp_info.num_group_account=0;
}

static void free_samr_info(void *ptr)
{
	struct samr_info *info=(struct samr_info *) ptr;

	free_samr_db(info);
	talloc_destroy(info->mem_ctx);
}

/*******************************************************************
 Ensure password info is never given out. Paranioa... JRA.
 ********************************************************************/

static void samr_clear_sam_passwd(SAM_ACCOUNT *sam_pass)
{
	
	if (!sam_pass)
		return;

	/* These now zero out the old password */

	pdb_set_lanman_passwd(sam_pass, NULL, PDB_DEFAULT);
	pdb_set_nt_passwd(sam_pass, NULL, PDB_DEFAULT);
}


static NTSTATUS load_sampwd_entries(struct samr_info *info, uint16 acb_mask, BOOL all_machines)
{
	SAM_ACCOUNT *pwd = NULL;
	SAM_ACCOUNT *pwd_array = NULL;
	NTSTATUS nt_status = NT_STATUS_OK;
	TALLOC_CTX *mem_ctx = info->mem_ctx;

	DEBUG(10,("load_sampwd_entries\n"));

	/* if the snapshoot is already loaded, return */
	if ((info->disp_info.user_dbloaded==True) 
	    && (info->acb_mask == acb_mask) 
	    && (info->all_machines == all_machines)) {
		DEBUG(10,("load_sampwd_entries: already in memory\n"));
		return NT_STATUS_OK;
	}

	free_samr_users(info);

	if (!pdb_setsampwent(False)) {
		DEBUG(0, ("load_sampwd_entries: Unable to open passdb.\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	for (; (NT_STATUS_IS_OK(nt_status = pdb_init_sam_talloc(mem_ctx, &pwd))) 
		     && pdb_getsampwent(pwd) == True; pwd=NULL) {
		
		if (all_machines) {
			if (!((pdb_get_acct_ctrl(pwd) & ACB_WSTRUST) 
			      || (pdb_get_acct_ctrl(pwd) & ACB_SVRTRUST))) {
				DEBUG(5,("load_sampwd_entries: '%s' is not a machine account - ACB: %x - skipping\n", pdb_get_username(pwd), acb_mask));
				pdb_free_sam(&pwd);
				continue;
			}
		} else {
			if (acb_mask != 0 && !(pdb_get_acct_ctrl(pwd) & acb_mask)) {
				pdb_free_sam(&pwd);
				DEBUG(5,(" acb_mask %x reject\n", acb_mask));
				continue;
			}
		}

		/* Realloc some memory for the array of ptr to the SAM_ACCOUNT structs */
		if (info->disp_info.num_user_account % MAX_SAM_ENTRIES == 0) {
		
			DEBUG(10,("load_sampwd_entries: allocating more memory\n"));
			pwd_array=(SAM_ACCOUNT *)talloc_realloc(mem_ctx, info->disp_info.disp_user_info, 
			                  (info->disp_info.num_user_account+MAX_SAM_ENTRIES)*sizeof(SAM_ACCOUNT));

			if (pwd_array==NULL)
				return NT_STATUS_NO_MEMORY;

			info->disp_info.disp_user_info=pwd_array;
		}
	
		/* Copy the SAM_ACCOUNT into the array */
		info->disp_info.disp_user_info[info->disp_info.num_user_account]=*pwd;

		DEBUG(10,("load_sampwd_entries: entry: %d\n", info->disp_info.num_user_account));

		info->disp_info.num_user_account++;	
	}

	pdb_endsampwent();

	/* the snapshoot is in memory, we're ready to enumerate fast */

	info->acb_mask = acb_mask;
	info->all_machines = all_machines;
	info->disp_info.user_dbloaded=True;

	DEBUG(10,("load_sampwd_entries: done\n"));

	return nt_status;
}

static NTSTATUS load_group_domain_entries(struct samr_info *info, DOM_SID *sid)
{
	GROUP_MAP *map=NULL;
	DOMAIN_GRP *grp_array = NULL;
	uint32 group_entries = 0;
	uint32 i;
	TALLOC_CTX *mem_ctx = info->mem_ctx;
	BOOL ret;

	DEBUG(10,("load_group_domain_entries\n"));

	/* if the snapshoot is already loaded, return */
	if (info->disp_info.group_dbloaded==True) {
		DEBUG(10,("load_group_domain_entries: already in memory\n"));
		return NT_STATUS_OK;
	}
	
	if (sid_equal(sid, &global_sid_Builtin)) {
		/* No domain groups for now in the BUILTIN domain */
		info->disp_info.num_group_account=0;
		info->disp_info.disp_group_info=NULL;
		info->disp_info.group_dbloaded=True;
		return NT_STATUS_OK;
	}

	become_root();
	ret = pdb_enum_group_mapping(SID_NAME_DOM_GRP, &map, (int *)&group_entries, ENUM_ONLY_MAPPED); 
	unbecome_root();
	
	if ( !ret ) {
		DEBUG(1, ("load_group_domain_entries: pdb_enum_group_mapping() failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	

	info->disp_info.num_group_account=group_entries;

	grp_array=(DOMAIN_GRP *)talloc(mem_ctx, info->disp_info.num_group_account*sizeof(DOMAIN_GRP));
	if (group_entries!=0 && grp_array==NULL) {
		DEBUG(1, ("load_group_domain_entries: talloc() failed for grp_array!\n"));
		SAFE_FREE(map);
		return NT_STATUS_NO_MEMORY;
	}

	info->disp_info.disp_group_info=grp_array;

	for (i=0; i<group_entries; i++) {
		fstrcpy(grp_array[i].name, map[i].nt_name);
		fstrcpy(grp_array[i].comment, map[i].comment);
		sid_split_rid(&map[i].sid, &grp_array[i].rid);
		grp_array[i].attr=SID_NAME_DOM_GRP;
	}

	SAFE_FREE(map);

	/* the snapshoot is in memory, we're ready to enumerate fast */

	info->disp_info.group_dbloaded=True;

	DEBUG(10,("load_group_domain_entries: done\n"));

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
	struct    samr_info *info;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = q_u->flags;
	size_t    sd_size;
	NTSTATUS  status;

	r_u->status = NT_STATUS_OK;

	/* find the connection policy handle. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void**)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!NT_STATUS_IS_OK(status = access_check_samr_function(info->acc_granted, SA_RIGHT_SAM_OPEN_DOMAIN,"_samr_open_domain"))) {
		return status;
	}

	/*check if access can be granted as requested by client. */
	samr_make_dom_obj_sd(p->mem_ctx, &psd, &sd_size);
	se_map_generic(&des_access,&dom_generic_mapping);

	if (!NT_STATUS_IS_OK(status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_open_domain"))) {
		return status;
	}

	/* associate the domain SID with the (unique) handle. */
	if ((info = get_samr_info_by_sid(&q_u->dom_sid.sid))==NULL)
		return NT_STATUS_NO_MEMORY;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->domain_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("samr_open_domain: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _samr_get_usrdom_pwinfo
 ********************************************************************/

NTSTATUS _samr_get_usrdom_pwinfo(pipes_struct *p, SAMR_Q_GET_USRDOM_PWINFO *q_u, SAMR_R_GET_USRDOM_PWINFO *r_u)
{
	struct samr_info *info = NULL;

	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->user_pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!sid_check_is_in_our_domain(&info->sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	init_samr_r_get_usrdom_pwinfo(r_u, NT_STATUS_OK);

	DEBUG(5,("_samr_get_usrdom_pwinfo: %d\n", __LINE__));

	/* 
	 * NT sometimes return NT_STATUS_ACCESS_DENIED
	 * I don't know yet why.
	 */

	return r_u->status;
}

/*******************************************************************
 samr_make_dom_obj_sd
 ********************************************************************/

static NTSTATUS samr_make_dom_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size)
{
	extern DOM_SID global_sid_World;
	DOM_SID adm_sid;
	DOM_SID act_sid;

	SEC_ACE ace[3];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;

	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, &global_sid_Builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	/*basic access for every one*/
	init_sec_access(&mask, GENERIC_RIGHTS_DOMAIN_EXECUTE | GENERIC_RIGHTS_DOMAIN_READ);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/*full access for builtin aliases Administrators and Account Operators*/
	init_sec_access(&mask, GENERIC_RIGHTS_DOMAIN_ALL_ACCESS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[2], &act_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 3, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if ((*psd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_make_usr_obj_sd
 ********************************************************************/

static NTSTATUS samr_make_usr_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size, DOM_SID *usr_sid)
{
	extern DOM_SID global_sid_World;
	DOM_SID adm_sid;
	DOM_SID act_sid;

	SEC_ACE ace[4];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;

	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, &global_sid_Builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	/*basic access for every one*/
	init_sec_access(&mask, GENERIC_RIGHTS_USER_EXECUTE | GENERIC_RIGHTS_USER_READ);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/*full access for builtin aliases Administrators and Account Operators*/
	init_sec_access(&mask, GENERIC_RIGHTS_USER_ALL_ACCESS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[2], &act_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/*extended access for the user*/
	init_sec_access(&mask,READ_CONTROL_ACCESS | SA_RIGHT_USER_CHANGE_PASSWORD | SA_RIGHT_USER_SET_LOC_COM);
	init_sec_ace(&ace[3], usr_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 4, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if ((*psd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_make_grp_obj_sd
 ********************************************************************/

static NTSTATUS samr_make_grp_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size)
{
	extern DOM_SID global_sid_World;
	DOM_SID adm_sid;
	DOM_SID act_sid;

	SEC_ACE ace[3];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;

	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, &global_sid_Builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	/*basic access for every one*/
	init_sec_access(&mask, GENERIC_RIGHTS_GROUP_EXECUTE | GENERIC_RIGHTS_GROUP_READ);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/*full access for builtin aliases Administrators and Account Operators*/
	init_sec_access(&mask, GENERIC_RIGHTS_GROUP_ALL_ACCESS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[2], &act_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 3, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if ((*psd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_make_ali_obj_sd
 ********************************************************************/

static NTSTATUS samr_make_ali_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size)
{
	extern DOM_SID global_sid_World;
	DOM_SID adm_sid;
	DOM_SID act_sid;

	SEC_ACE ace[3];
	SEC_ACCESS mask;

	SEC_ACL *psa = NULL;

	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, &global_sid_Builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	/*basic access for every one*/
	init_sec_access(&mask, GENERIC_RIGHTS_ALIAS_EXECUTE | GENERIC_RIGHTS_ALIAS_READ);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/*full access for builtin aliases Administrators and Account Operators*/
	init_sec_access(&mask, GENERIC_RIGHTS_ALIAS_ALL_ACCESS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[2], &act_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 3, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if ((*psd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

static BOOL get_lsa_policy_samr_sid(pipes_struct *p, POLICY_HND *pol, DOM_SID *sid, uint32 *acc_granted)
{
	struct samr_info *info = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, pol, (void **)&info))
		return False;

	if (!info)
		return False;

	*sid = info->sid;
	*acc_granted = info->acc_granted;
	return True;
}

/*******************************************************************
 _samr_set_sec_obj
 ********************************************************************/

NTSTATUS _samr_set_sec_obj(pipes_struct *p, SAMR_Q_SET_SEC_OBJ *q_u, SAMR_R_SET_SEC_OBJ *r_u)
{
	DEBUG(0,("_samr_set_sec_obj: Not yet implemented!\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*******************************************************************
 _samr_query_sec_obj
 ********************************************************************/

NTSTATUS _samr_query_sec_obj(pipes_struct *p, SAMR_Q_QUERY_SEC_OBJ *q_u, SAMR_R_QUERY_SEC_OBJ *r_u)
{
	DOM_SID pol_sid;
	fstring str_sid;
	SEC_DESC * psd = NULL;
	size_t sd_size;
	uint32 acc_granted;

	r_u->status = NT_STATUS_OK;

	/* Get the SID. */
	if (!get_lsa_policy_samr_sid(p, &q_u->user_pol, &pol_sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;



	DEBUG(10,("_samr_query_sec_obj: querying security on SID: %s\n", sid_to_string(str_sid, &pol_sid)));

	/* Check what typ of SID is beeing queried (e.g Domain SID, User SID, Group SID) */

	/* To query the security of the SAM it self an invalid SID with S-0-0 is passed to this function */
	if (pol_sid.sid_rev_num == 0)
	{
		DEBUG(5,("_samr_query_sec_obj: querying security on SAM\n"));
		r_u->status = samr_make_sam_obj_sd(p->mem_ctx, &psd, &sd_size);
	}
	else if (sid_equal(&pol_sid,get_global_sam_sid()))  /* check if it is our domain SID */

	{
		DEBUG(5,("_samr_query_sec_obj: querying security on Domain with SID: %s\n", sid_to_string(str_sid, &pol_sid)));
		r_u->status = samr_make_dom_obj_sd(p->mem_ctx, &psd, &sd_size);
	}
	else if (sid_equal(&pol_sid,&global_sid_Builtin)) /* check if it is the Builtin  Domain */
	{
		/* TODO: Builtin probably needs a different SD with restricted write access*/
		DEBUG(5,("_samr_query_sec_obj: querying security on Builtin Domain with SID: %s\n", sid_to_string(str_sid, &pol_sid)));
		r_u->status = samr_make_dom_obj_sd(p->mem_ctx, &psd, &sd_size);
	}
	else if (sid_check_is_in_our_domain(&pol_sid) ||
	    	 sid_check_is_in_builtin(&pol_sid))
	{
		/* TODO: different SDs have to be generated for aliases groups and users.
		         Currently all three get a default user SD  */
		DEBUG(10,("_samr_query_sec_obj: querying security on Object with SID: %s\n", sid_to_string(str_sid, &pol_sid)));
		r_u->status = samr_make_usr_obj_sd(p->mem_ctx, &psd,&sd_size, &pol_sid);
	}
	else return NT_STATUS_OBJECT_TYPE_MISMATCH;

	if ((r_u->buf = make_sec_desc_buf(p->mem_ctx, sd_size, psd)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if (NT_STATUS_IS_OK(r_u->status))
		r_u->ptr = 1;

	return r_u->status;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure from a user list.
********************************************************************/

static NTSTATUS make_user_sam_entry_list(TALLOC_CTX *ctx, SAM_ENTRY **sam_pp, UNISTR2 **uni_name_pp,
					 uint32 num_entries, uint32 start_idx, SAM_ACCOUNT *disp_user_info,
					 DOM_SID *domain_sid)
{
	uint32 i;
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;
	SAM_ACCOUNT *pwd = NULL;
	UNISTR2 uni_temp_name;
	const char *temp_name;
	const DOM_SID *user_sid;
	uint32 user_rid;
	fstring user_sid_string;
	fstring domain_sid_string;
	
	*sam_pp = NULL;
	*uni_name_pp = NULL;

	if (num_entries == 0)
		return NT_STATUS_OK;

	sam = (SAM_ENTRY *)talloc_zero(ctx, sizeof(SAM_ENTRY)*num_entries);

	uni_name = (UNISTR2 *)talloc_zero(ctx, sizeof(UNISTR2)*num_entries);

	if (sam == NULL || uni_name == NULL) {
		DEBUG(0, ("make_user_sam_entry_list: talloc_zero failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries; i++) {
		pwd = &disp_user_info[i+start_idx];
		temp_name = pdb_get_username(pwd);
		init_unistr2(&uni_temp_name, temp_name, UNI_STR_TERMINATE);
		user_sid = pdb_get_user_sid(pwd);

		if (!sid_peek_check_rid(domain_sid, user_sid, &user_rid)) {
			DEBUG(0, ("make_user_sam_entry_list: User %s has SID %s, which conflicts with "
				  "the domain sid %s.  Failing operation.\n", 
				  temp_name, 
				  sid_to_string(user_sid_string, user_sid),
				  sid_to_string(domain_sid_string, domain_sid)));
			return NT_STATUS_UNSUCCESSFUL;
		}

		init_sam_entry(&sam[i], &uni_temp_name, user_rid);
		copy_unistr2(&uni_name[i], &uni_temp_name);
	}

	*sam_pp = sam;
	*uni_name_pp = uni_name;
	return NT_STATUS_OK;
}

/*******************************************************************
 samr_reply_enum_dom_users
 ********************************************************************/

NTSTATUS _samr_enum_dom_users(pipes_struct *p, SAMR_Q_ENUM_DOM_USERS *q_u, 
			      SAMR_R_ENUM_DOM_USERS *r_u)
{
	struct samr_info *info = NULL;
	uint32 struct_size=0x20; /* W2K always reply that, client doesn't care */
	int num_account;
	uint32 enum_context=q_u->start_idx;
	uint32 max_size=q_u->max_size;
	uint32 temp_size;
	enum remote_arch_types ra_type = get_remote_arch();
	int max_sam_entries = (ra_type == RA_WIN95) ? MAX_SAM_ENTRIES_W95 : MAX_SAM_ENTRIES_W2K;
	uint32 max_entries = max_sam_entries;
	DOM_SID domain_sid;
	
	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	domain_sid = info->sid;

 	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(info->acc_granted, 
					SA_RIGHT_DOMAIN_ENUM_ACCOUNTS, 
					"_samr_enum_dom_users"))) {
 		return r_u->status;
	}
 	
	DEBUG(5,("_samr_enum_dom_users: %d\n", __LINE__));

	become_root();
	r_u->status=load_sampwd_entries(info, q_u->acb_mask, False);
	unbecome_root();
	
	if (!NT_STATUS_IS_OK(r_u->status))
		return r_u->status;

	num_account = info->disp_info.num_user_account;

	if (enum_context > num_account) {
		DEBUG(5, ("_samr_enum_dom_users: enumeration handle over total entries\n"));
		return NT_STATUS_OK;
	}

	/* verify we won't overflow */
	if (max_entries > num_account-enum_context) {
		max_entries = num_account-enum_context;
		DEBUG(5, ("_samr_enum_dom_users: only %d entries to return\n", max_entries));
	}

	/* calculate the size and limit on the number of entries we will return */
	temp_size=max_entries*struct_size;
	
	if (temp_size>max_size) {
		max_entries=MIN((max_size/struct_size),max_entries);;
		DEBUG(5, ("_samr_enum_dom_users: buffer size limits to only %d entries\n", max_entries));
	}

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

	r_u->status = make_user_sam_entry_list(p->mem_ctx, &r_u->sam, &r_u->uni_acct_name, 
					       max_entries, enum_context, 
					       info->disp_info.disp_user_info,
					       &domain_sid);

	if (!NT_STATUS_IS_OK(r_u->status))
		return r_u->status;

	if (enum_context+max_entries < num_account)
		r_u->status = STATUS_MORE_ENTRIES;

	DEBUG(5, ("_samr_enum_dom_users: %d\n", __LINE__));

	init_samr_r_enum_dom_users(r_u, q_u->start_idx + max_entries, max_entries);

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
		init_unistr2(&uni_name[i], grp[i].name, UNI_STR_TERMINATE);
		init_sam_entry(&sam[i], &uni_name[i], grp[i].rid);
	}

	*sam_pp = sam;
	*uni_name_pp = uni_name;
}

/*******************************************************************
 Get the group entries - similar to get_sampwd_entries().
 ******************************************************************/

static NTSTATUS get_group_domain_entries( TALLOC_CTX *ctx, 
                                   DOMAIN_GRP **d_grp, DOM_SID *sid, uint32 start_idx,
                                   uint32 *p_num_entries, uint32 max_entries )
{
	GROUP_MAP *map=NULL;
	int i;
	uint32 group_entries = 0;
	uint32 num_entries = 0;

	*p_num_entries = 0;

	/* access checks for the users were performed higher up.  become/unbecome_root()
	   needed for some passdb backends to enumerate groups */
	   
	become_root();
	pdb_enum_group_mapping(SID_NAME_DOM_GRP, &map, (int *)&group_entries,
			       ENUM_ONLY_MAPPED);
	unbecome_root();
	
	num_entries=group_entries-start_idx;

	/* limit the number of entries */
	if (num_entries>max_entries) {
		DEBUG(5,("Limiting to %d entries\n", max_entries));
		num_entries=max_entries;
	}

	*d_grp=(DOMAIN_GRP *)talloc_zero(ctx, num_entries*sizeof(DOMAIN_GRP));
	if (num_entries!=0 && *d_grp==NULL){
		SAFE_FREE(map);
		return NT_STATUS_NO_MEMORY;
	}
	
	for (i=0; i<num_entries; i++) {
		fstrcpy((*d_grp)[i].name, map[i+start_idx].nt_name);
		fstrcpy((*d_grp)[i].comment, map[i+start_idx].comment);
		sid_split_rid(&map[i+start_idx].sid, &(*d_grp)[i].rid);
		(*d_grp)[i].attr=SID_NAME_DOM_GRP;
	}

	SAFE_FREE(map);

	*p_num_entries = num_entries;

	DEBUG(10,("get_group_domain_entries: returning %d entries\n",
		  *p_num_entries));

	return NT_STATUS_OK;
}

/*******************************************************************
 Wrapper for enumerating local groups
 ******************************************************************/

static NTSTATUS get_alias_entries( TALLOC_CTX *ctx, DOMAIN_GRP **d_grp,
				   const DOM_SID *sid, uint32 start_idx,
                                   uint32 *p_num_entries, uint32 max_entries )
{
	struct acct_info *info;
	int i;
	BOOL res;

	become_root();
	res = pdb_enum_aliases(sid, start_idx, max_entries,
			       p_num_entries, &info);
	unbecome_root();

	if (!res)
		return NT_STATUS_ACCESS_DENIED;

	if (*p_num_entries == 0)
		return NT_STATUS_OK;

	*d_grp = talloc(ctx, sizeof(DOMAIN_GRP) * (*p_num_entries));

	if (*d_grp == NULL) {
		SAFE_FREE(info);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<*p_num_entries; i++) {
		fstrcpy((*d_grp)[i].name, info[i].acct_name);
		fstrcpy((*d_grp)[i].comment, info[i].acct_desc);
		(*d_grp)[i].rid = info[i].rid;
		(*d_grp)[i].attr = SID_NAME_ALIAS;
	}

	SAFE_FREE(info);
	return NT_STATUS_OK;
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/

NTSTATUS _samr_enum_dom_groups(pipes_struct *p, SAMR_Q_ENUM_DOM_GROUPS *q_u, SAMR_R_ENUM_DOM_GROUPS *r_u)
{
	DOMAIN_GRP *grp=NULL;
	uint32 num_entries;
	DOM_SID sid;
	uint32 acc_granted;

	r_u->status = NT_STATUS_OK;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_ENUM_ACCOUNTS, "_samr_enum_dom_groups"))) {
		return r_u->status;
	}

	DEBUG(5,("samr_reply_enum_dom_groups: %d\n", __LINE__));

	/* the domain group array is being allocated in the function below */
	if (!NT_STATUS_IS_OK(r_u->status = get_group_domain_entries(p->mem_ctx, &grp, &sid, q_u->start_idx, &num_entries, MAX_SAM_ENTRIES))) {
		return r_u->status;
	}

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
	DOMAIN_GRP *grp=NULL;
	uint32 num_entries = 0;
	fstring sid_str;
	DOM_SID sid;
	NTSTATUS status;
	uint32  acc_granted;
	
	r_u->status = NT_STATUS_OK;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;

	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_ENUM_ACCOUNTS, "_samr_enum_dom_aliases"))) {
		return r_u->status;
	}
	
	sid_to_string(sid_str, &sid);
	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	status = get_alias_entries(p->mem_ctx, &grp, &sid, q_u->start_idx, 
				   &num_entries, MAX_SAM_ENTRIES);
	if (!NT_STATUS_IS_OK(status)) return status;

	make_group_sam_entry_list(p->mem_ctx, &r_u->sam, &r_u->uni_grp_name, num_entries, grp);

	/*safe_free(grp);*/

	init_samr_r_enum_dom_aliases(r_u, q_u->start_idx + num_entries, num_entries);

	DEBUG(5,("samr_enum_dom_aliases: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/

NTSTATUS _samr_query_dispinfo(pipes_struct *p, SAMR_Q_QUERY_DISPINFO *q_u, 
			      SAMR_R_QUERY_DISPINFO *r_u)
{
	struct samr_info *info = NULL;
	uint32 struct_size=0x20; /* W2K always reply that, client doesn't care */
	
	uint32 max_entries=q_u->max_entries;
	uint32 enum_context=q_u->start_idx;
	uint32 max_size=q_u->max_size;

	SAM_DISPINFO_CTR *ctr;
	uint32 temp_size=0, total_data_size=0;
	NTSTATUS disp_ret;
	uint32 num_account = 0;
	enum remote_arch_types ra_type = get_remote_arch();
	int max_sam_entries = (ra_type == RA_WIN95) ? MAX_SAM_ENTRIES_W95 : MAX_SAM_ENTRIES_W2K;
	DOM_SID domain_sid;

	DEBUG(5, ("samr_reply_query_dispinfo: %d\n", __LINE__));
	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->domain_pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	domain_sid = info->sid;

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
	switch (q_u->switch_level) {
		case 0x1:
			/* When playing with usrmgr, this is necessary
                           if you want immediate refresh after editing
                           a user. I would like to do this after the
                           setuserinfo2, but we do not have access to
                           the domain handle in that call, only to the
                           user handle. Where else does this hurt?
			   -- Volker
			*/
#if 0
			/* We cannot do this here - it kills performace. JRA. */
			free_samr_users(info);
#endif
		case 0x2:
		case 0x4:
			become_root();		
			/* Level 2 is for all machines, otherwise only 'normal' users */
			r_u->status=load_sampwd_entries(info, ACB_NORMAL, q_u->switch_level==2);
			unbecome_root();
			if (!NT_STATUS_IS_OK(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_sampwd_entries failed\n"));
				return r_u->status;
			}
			num_account = info->disp_info.num_user_account;
			break;
		case 0x3:
		case 0x5:
			r_u->status = load_group_domain_entries(info, &info->sid);
			if (!NT_STATUS_IS_OK(r_u->status))
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
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	/* verify we won't overflow */
	if (max_entries > num_account-enum_context) {
		max_entries = num_account-enum_context;
		DEBUG(5, ("samr_reply_query_dispinfo: only %d entries to return\n", max_entries));
	}

	/* calculate the size and limit on the number of entries we will return */
	temp_size=max_entries*struct_size;
	
	if (temp_size>max_size) {
		max_entries=MIN((max_size/struct_size),max_entries);;
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
		disp_ret = init_sam_dispinfo_1(p->mem_ctx, ctr->sam.info1, max_entries, enum_context, 
					       info->disp_info.disp_user_info, &domain_sid);
		if (!NT_STATUS_IS_OK(disp_ret))
			return disp_ret;
		break;
	case 0x2:
		if (max_entries) {
			if (!(ctr->sam.info2 = (SAM_DISPINFO_2 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_2))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_2(p->mem_ctx, ctr->sam.info2, max_entries, enum_context, 
					       info->disp_info.disp_user_info, &domain_sid);
		if (!NT_STATUS_IS_OK(disp_ret))
			return disp_ret;
		break;
	case 0x3:
		if (max_entries) {
			if (!(ctr->sam.info3 = (SAM_DISPINFO_3 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_3))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_3(p->mem_ctx, ctr->sam.info3, max_entries, enum_context, info->disp_info.disp_group_info);
		if (!NT_STATUS_IS_OK(disp_ret))
			return disp_ret;
		break;
	case 0x4:
		if (max_entries) {
			if (!(ctr->sam.info4 = (SAM_DISPINFO_4 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_4))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_4(p->mem_ctx, ctr->sam.info4, max_entries, enum_context, info->disp_info.disp_user_info);
		if (!NT_STATUS_IS_OK(disp_ret))
			return disp_ret;
		break;
	case 0x5:
		if (max_entries) {
			if (!(ctr->sam.info5 = (SAM_DISPINFO_5 *)talloc_zero(p->mem_ctx,max_entries*sizeof(SAM_DISPINFO_5))))
				return NT_STATUS_NO_MEMORY;
		}
		disp_ret = init_sam_dispinfo_5(p->mem_ctx, ctr->sam.info5, max_entries, enum_context, info->disp_info.disp_group_info);
		if (!NT_STATUS_IS_OK(disp_ret))
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
	DOM_SID   sid;
	struct acct_info info;
	uint32    acc_granted;
	BOOL ret;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_aliasinfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_ALIAS_LOOKUP_INFO, "_samr_query_aliasinfo"))) {
		return r_u->status;
	}

	become_root();
	ret = pdb_get_aliasinfo(&sid, &info);
	unbecome_root();
	
	if ( !ret )
		return NT_STATUS_NO_SUCH_ALIAS;

	switch (q_u->switch_level) {
	case 1:
		r_u->ptr = 1;
		r_u->ctr.switch_value1 = 1;
		init_samr_alias_info1(&r_u->ctr.alias.info1,
				      info.acct_name, 1, info.acct_desc);
		break;
	case 3:
		r_u->ptr = 1;
		r_u->ctr.switch_value1 = 3;
		init_samr_alias_info3(&r_u->ctr.alias.info3, info.acct_desc);
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
	uint32  acc_granted;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_lookup_names: %d\n", __LINE__));

	ZERO_ARRAY(rid);
	ZERO_ARRAY(type);

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &pol_sid, &acc_granted)) {
		init_samr_r_lookup_names(p->mem_ctx, r_u, 0, NULL, NULL, NT_STATUS_OBJECT_TYPE_MISMATCH);
		return r_u->status;
	}
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, 0, "_samr_lookup_names"))) { /* Don't know the acc_bits yet */
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
            	int ret;

	        r_u->status = NT_STATUS_NONE_MAPPED;

	        rid [i] = 0xffffffff;
	        type[i] = SID_NAME_UNKNOWN;

		ret = rpcstr_pull(name, q_u->uni_name[i].buffer, sizeof(name), q_u->uni_name[i].uni_str_len*2, 0);

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
		 
            	if ((ret > 0) && local_lookup_name(name, &sid, &local_type)) {
                	sid_split_rid(&sid, &local_rid);
				
			if (sid_equal(&sid, &pol_sid)) {
				rid[i]=local_rid;

				/* Windows does not return WKN_GRP here, even
				 * on lookups in builtin */
				type[i] = (local_type == SID_NAME_WKN_GRP) ?
					SID_NAME_ALIAS : local_type;

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

	rpcstr_pull(user_name, q_u->uni_user_name.buffer, sizeof(user_name), q_u->uni_user_name.uni_str_len*2, 0);
	rpcstr_pull(wks, q_u->uni_dest_host.buffer, sizeof(wks), q_u->uni_dest_host.uni_str_len*2,0);

	DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */
 
	(void)map_username(user_name);
 
	/*
	 * UNIX username case mangling not required, pass_oem_change 
	 * is case insensitive.
	 */

	r_u->status = pass_oem_change(user_name, q_u->lm_newpass.pass, q_u->lm_oldhash.hash,
				q_u->nt_newpass.pass, q_u->nt_oldhash.hash);

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
	UNIHDR *hdr_name=NULL;
	UNISTR2 *uni_name=NULL;

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
		DEBUG(10, ("names[%d]:%s\n", i, names[i] ? names[i] : ""));
		init_unistr2(&uni_name[i], names[i], UNI_FLAGS_NONE);
		init_uni_hdr(&hdr_name[i], &uni_name[i]);
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
	uint32 acc_granted;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_lookup_rids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &pol_sid, &acc_granted))
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

	become_root();  /* lookup_sid can require root privs */

	for (i = 0; i < num_rids; i++) {
		fstring tmpname;
		fstring domname;
		DOM_SID sid;
   		enum SID_NAME_USE type;

		group_attrs[i] = SID_NAME_UNKNOWN;
		*group_names[i] = '\0';

		if (sid_equal(&pol_sid, get_global_sam_sid())) {
			sid_copy(&sid, &pol_sid);
			sid_append_rid(&sid, q_u->rid[i]);

			if (lookup_sid(&sid, domname, tmpname, &type)) {
				r_u->status = NT_STATUS_OK;
				group_attrs[i] = (uint32)type;
				fstrcpy(group_names[i],tmpname);
				DEBUG(5,("_samr_lookup_rids: %s:%d\n", group_names[i], group_attrs[i]));
			}
		}
	}

	unbecome_root();

	if(!make_samr_lookup_rids(p->mem_ctx, num_rids, group_names, &hdr_name, &uni_name))
		return NT_STATUS_NO_MEMORY;

	init_samr_r_lookup_rids(r_u, num_rids, hdr_name, uni_name, group_attrs);

	DEBUG(5,("_samr_lookup_rids: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _samr_open_user. Safe - gives out no passwd info.
 ********************************************************************/

NTSTATUS _samr_open_user(pipes_struct *p, SAMR_Q_OPEN_USER *q_u, SAMR_R_OPEN_USER *r_u)
{
	SAM_ACCOUNT *sampass=NULL;
	DOM_SID sid;
	POLICY_HND domain_pol = q_u->domain_pol;
	POLICY_HND *user_pol = &r_u->user_pol;
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = q_u->access_mask;
	size_t    sd_size;
	BOOL ret;
	NTSTATUS nt_status;

	r_u->status = NT_STATUS_OK;

	/* find the domain policy handle and get domain SID / access bits in the domain policy. */
	if (!get_lsa_policy_samr_sid(p, &domain_pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(nt_status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_OPEN_ACCOUNT, "_samr_open_user"))) {
		return nt_status;
	}

	nt_status = pdb_init_sam_talloc(p->mem_ctx, &sampass);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/* append the user's RID to it */
	if (!sid_append_rid(&sid, q_u->user_rid))
		return NT_STATUS_NO_SUCH_USER;
	
	/* check if access can be granted as requested by client. */
	samr_make_usr_obj_sd(p->mem_ctx, &psd, &sd_size, &sid);
	se_map_generic(&des_access, &usr_generic_mapping);
	if (!NT_STATUS_IS_OK(nt_status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_open_user"))) {
		return nt_status;
	}

	become_root();
	ret=pdb_getsampwsid(sampass, &sid);
	unbecome_root();

	/* check that the SID exists in our domain. */
	if (ret == False) {
        	return NT_STATUS_NO_SUCH_USER;
	}

	pdb_free_sam(&sampass);

	/* associate the user's SID and access bits with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/*************************************************************************
 get_user_info_10. Safe. Only gives out acb bits.
 *************************************************************************/

static NTSTATUS get_user_info_10(TALLOC_CTX *mem_ctx, SAM_USER_INFO_10 *id10, DOM_SID *user_sid)
{
	SAM_ACCOUNT *smbpass=NULL;
	BOOL ret;
	NTSTATUS nt_status;

	nt_status = pdb_init_sam_talloc(mem_ctx, &smbpass);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	become_root();
	ret = pdb_getsampwsid(smbpass, user_sid);
	unbecome_root();

	if (ret==False) {
		DEBUG(4,("User %s not found\n", sid_string_static(user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(3,("User:[%s]\n", pdb_get_username(smbpass) ));

	ZERO_STRUCTP(id10);
	init_sam_user_info10(id10, pdb_get_acct_ctrl(smbpass) );

	pdb_free_sam(&smbpass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_12. OK - this is the killer as it gives out password info.
 Ensure that this is only allowed on an encrypted connection with a root
 user. JRA. 
 *************************************************************************/

static NTSTATUS get_user_info_12(pipes_struct *p, TALLOC_CTX *mem_ctx, SAM_USER_INFO_12 * id12, DOM_SID *user_sid)
{
	SAM_ACCOUNT *smbpass=NULL;
	BOOL ret;
	NTSTATUS nt_status;

	if (!p->ntlmssp_auth_validated)
		return NT_STATUS_ACCESS_DENIED;

	if (!(p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SIGN) || !(p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SEAL))
		return NT_STATUS_ACCESS_DENIED;

	/*
	 * Do *NOT* do become_root()/unbecome_root() here ! JRA.
	 */

	nt_status = pdb_init_sam_talloc(mem_ctx, &smbpass);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	ret = pdb_getsampwsid(smbpass, user_sid);

	if (ret == False) {
		DEBUG(4, ("User %s not found\n", sid_string_static(user_sid)));
		pdb_free_sam(&smbpass);
		return (geteuid() == (uid_t)0) ? NT_STATUS_NO_SUCH_USER : NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(3,("User:[%s] 0x%x\n", pdb_get_username(smbpass), pdb_get_acct_ctrl(smbpass) ));

	if ( pdb_get_acct_ctrl(smbpass) & ACB_DISABLED) {
		pdb_free_sam(&smbpass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	ZERO_STRUCTP(id12);
	init_sam_user_info12(id12, pdb_get_lanman_passwd(smbpass), pdb_get_nt_passwd(smbpass));
	
	pdb_free_sam(&smbpass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_20
 *************************************************************************/

static NTSTATUS get_user_info_20(TALLOC_CTX *mem_ctx, SAM_USER_INFO_20 *id20, DOM_SID *user_sid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;

	pdb_init_sam_talloc(mem_ctx, &sampass);

	become_root();
	ret = pdb_getsampwsid(sampass, user_sid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User %s not found\n", sid_string_static(user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	samr_clear_sam_passwd(sampass);

	DEBUG(3,("User:[%s]\n",  pdb_get_username(sampass) ));

	ZERO_STRUCTP(id20);
	init_sam_user_info20A(id20, sampass);
	
	pdb_free_sam(&sampass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_21
 *************************************************************************/

static NTSTATUS get_user_info_21(TALLOC_CTX *mem_ctx, SAM_USER_INFO_21 *id21, 
				 DOM_SID *user_sid, DOM_SID *domain_sid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;
	NTSTATUS nt_status;

	nt_status = pdb_init_sam_talloc(mem_ctx, &sampass);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	become_root();
	ret = pdb_getsampwsid(sampass, user_sid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User %s not found\n", sid_string_static(user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	samr_clear_sam_passwd(sampass);

	DEBUG(3,("User:[%s]\n",  pdb_get_username(sampass) ));

	ZERO_STRUCTP(id21);
	nt_status = init_sam_user_info21A(id21, sampass, domain_sid);
	
	pdb_free_sam(&sampass);

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_query_userinfo
 ********************************************************************/

NTSTATUS _samr_query_userinfo(pipes_struct *p, SAMR_Q_QUERY_USERINFO *q_u, SAMR_R_QUERY_USERINFO *r_u)
{
	SAM_USERINFO_CTR *ctr;
	struct samr_info *info = NULL;
	DOM_SID domain_sid;
	uint32 rid;
	
	r_u->status=NT_STATUS_OK;

	/* search for the handle */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	domain_sid = info->sid;

	sid_split_rid(&domain_sid, &rid);

	if (!sid_check_is_in_our_domain(&info->sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	DEBUG(5,("_samr_query_userinfo: sid:%s\n", sid_string_static(&info->sid)));

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

		if (!NT_STATUS_IS_OK(r_u->status = get_user_info_10(p->mem_ctx, ctr->info.id10, &info->sid)))
			return r_u->status;
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
	    ZERO_STRUCTP(ctr->info.id11);
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

		if (!NT_STATUS_IS_OK(r_u->status = get_user_info_12(p, p->mem_ctx, ctr->info.id12, &info->sid)))
			return r_u->status;
		break;
		
	case 20:
		ctr->info.id20 = (SAM_USER_INFO_20 *)talloc_zero(p->mem_ctx,sizeof(SAM_USER_INFO_20));
		if (ctr->info.id20 == NULL)
			return NT_STATUS_NO_MEMORY;
		if (!NT_STATUS_IS_OK(r_u->status = get_user_info_20(p->mem_ctx, ctr->info.id20, &info->sid)))
			return r_u->status;
		break;

	case 21:
		ctr->info.id21 = (SAM_USER_INFO_21 *)talloc_zero(p->mem_ctx,sizeof(SAM_USER_INFO_21));
		if (ctr->info.id21 == NULL)
			return NT_STATUS_NO_MEMORY;
		if (!NT_STATUS_IS_OK(r_u->status = get_user_info_21(p->mem_ctx, ctr->info.id21, 
								    &info->sid, &domain_sid)))
			return r_u->status;
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
	DOM_SID  sid;
	DOM_GID *gids = NULL;
	int num_groups = 0;
	uint32 acc_granted;
	BOOL ret;

	/*
	 * from the SID in the request:
	 * we should send back the list of DOMAIN GROUPS
	 * the user is a member of
	 *
	 * and only the DOMAIN GROUPS
	 * no ALIASES !!! neither aliases of the domain
	 * nor aliases of the builtin SID
	 *
	 * JFM, 12/2/2001
	 */

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_USER_GET_GROUPS, "_samr_query_usergroups"))) {
		return r_u->status;
	}

	if (!sid_check_is_in_our_domain(&sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	pdb_init_sam(&sam_pass);
	
	become_root();
	ret = pdb_getsampwsid(sam_pass, &sid);
	unbecome_root();

	if (ret == False) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}
	
	if(!get_domain_user_groups(p->mem_ctx, &num_groups, &gids, sam_pass)) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_NO_SUCH_GROUP;
	}
	
	/* construct the response.  lkclXXXX: gids are not copied! */
	init_samr_r_query_usergroups(r_u, num_groups, gids, r_u->status);
	
	DEBUG(5,("_samr_query_usergroups: %d\n", __LINE__));
	
	pdb_free_sam(&sam_pass);
	
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

	uint32 account_policy_temp;

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
			
			account_policy_get(AP_MIN_PASSWORD_LEN, &account_policy_temp);
			min_pass_len = account_policy_temp;

			account_policy_get(AP_PASSWORD_HISTORY, &account_policy_temp);
			pass_hist = account_policy_temp;

			account_policy_get(AP_USER_MUST_LOGON_TO_CHG_PASS, &account_policy_temp);
			flag = account_policy_temp;

			account_policy_get(AP_MAX_PASSWORD_AGE, &account_policy_temp);
			u_expire = account_policy_temp;

			account_policy_get(AP_MIN_PASSWORD_AGE, &account_policy_temp);
			u_min_age = account_policy_temp;
			
			unix_to_nt_time_abs(&nt_expire, u_expire);
			unix_to_nt_time_abs(&nt_min_age, u_min_age);

			init_unk_info1(&ctr->info.inf1, (uint16)min_pass_len, (uint16)pass_hist, 
			               flag, nt_expire, nt_min_age);
			break;
		case 0x02:
			become_root();		
			r_u->status=load_sampwd_entries(info, ACB_NORMAL, False);
			unbecome_root();
			if (!NT_STATUS_IS_OK(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_sampwd_entries failed\n"));
				return r_u->status;
			}
			num_users=info->disp_info.num_user_account;
			free_samr_db(info);
			
			r_u->status=load_group_domain_entries(info, get_global_sam_sid());
			if (!NT_STATUS_IS_OK(r_u->status)) {
				DEBUG(5, ("_samr_query_dispinfo: load_group_domain_entries failed\n"));
				return r_u->status;
			}
			num_groups=info->disp_info.num_group_account;
			free_samr_db(info);
			
			/* The time call below is to get a sequence number for the sam. FIXME !!! JRA. */
			init_unk_info2(&ctr->info.inf2, lp_workgroup(), global_myname(), (uint32) time(NULL), 
				       num_users, num_groups, num_aliases);
			break;
		case 0x03:
			account_policy_get(AP_TIME_TO_LOGOUT, (unsigned int *)&u_logout);
			unix_to_nt_time_abs(&nt_logout, u_logout);
			
			init_unk_info3(&ctr->info.inf3, nt_logout);
			break;
		case 0x05:
			init_unk_info5(&ctr->info.inf5, global_myname());
			break;
		case 0x06:
			init_unk_info6(&ctr->info.inf6);
			break;
		case 0x07:
			init_unk_info7(&ctr->info.inf7);
			break;
		case 0x0c:
			account_policy_get(AP_LOCK_ACCOUNT_DURATION, &account_policy_temp);
			u_lock_duration = account_policy_temp * 60;

			account_policy_get(AP_RESET_COUNT_TIME, &account_policy_temp);
			u_reset_time = account_policy_temp * 60;

			account_policy_get(AP_BAD_ATTEMPT_LOCKOUT, &account_policy_temp);
			lockout = account_policy_temp;

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
 _samr_create_user
 Create an account, can be either a normal user or a machine.
 This funcion will need to be updated for bdc/domain trusts.
 ********************************************************************/

NTSTATUS _samr_create_user(pipes_struct *p, SAMR_Q_CREATE_USER *q_u, SAMR_R_CREATE_USER *r_u)
{
	SAM_ACCOUNT *sam_pass=NULL;
	fstring account;
	DOM_SID sid;
	pstring add_script;
	POLICY_HND dom_pol = q_u->domain_pol;
	UNISTR2 user_account = q_u->uni_name;
	uint16 acb_info = q_u->acb_info;
	POLICY_HND *user_pol = &r_u->user_pol;
	struct samr_info *info = NULL;
	BOOL ret;
	NTSTATUS nt_status;
	struct passwd *pw;
	uint32 acc_granted;
	SEC_DESC *psd;
	size_t    sd_size;
	uint32 new_rid = 0;
	/* check this, when giving away 'add computer to domain' privs */
	uint32    des_access = GENERIC_RIGHTS_USER_ALL_ACCESS;

	/* Get the domain SID stored in the domain policy */
	if (!get_lsa_policy_samr_sid(p, &dom_pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;

	if (!NT_STATUS_IS_OK(nt_status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_CREATE_USER, "_samr_create_user"))) {
		return nt_status;
	}

	if (!(acb_info == ACB_NORMAL || acb_info == ACB_DOMTRUST || acb_info == ACB_WSTRUST || acb_info == ACB_SVRTRUST)) { 
		/* Match Win2k, and return NT_STATUS_INVALID_PARAMETER if 
		   this parameter is not an account type */
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* find the account: tell the caller if it exists.
	  lkclXXXX i have *no* idea if this is a problem or not
 	  or even if you are supposed to construct a different
	  reply if the account already exists...
	 */

	rpcstr_pull(account, user_account.buffer, sizeof(account), user_account.uni_str_len*2, 0);
	strlower_m(account);

	pdb_init_sam(&sam_pass);

	become_root();
	ret = pdb_getsampwnam(sam_pass, account);
	unbecome_root();
	if (ret == True) {
		/* this account exists: say so */
		pdb_free_sam(&sam_pass);
		return NT_STATUS_USER_EXISTS;
	}

	pdb_free_sam(&sam_pass);

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
	 *
	 * We now have seperate script paramaters for adding users/machines so we
	 * now have some sainity-checking to match. 
	 */

	DEBUG(10,("checking account %s at pos %lu for $ termination\n",account, (unsigned long)strlen(account)-1));
	
	/* 
	 * we used to have code here that made sure the acb_info flags 
	 * matched with the users named (e.g. an account flags as a machine 
	 * trust account ended in '$').  It has been ifdef'd out for a long 
	 * time, so I replaced it with this comment.     --jerry
	 */

	/* the passdb lookup has failed; check to see if we need to run the
	   add user/machine script */
	   
	pw = Get_Pwnam(account);
	
	/*********************************************************************
	 * HEADS UP!  If we have to create a new user account, we have to get 
	 * a new RID from somewhere.  This used to be done by the passdb 
	 * backend. It has been moved into idmap now.  Since idmap is now 
	 * wrapped up behind winbind, this means you have to run winbindd if you
	 * want new accounts to get a new RID when "enable rid algorithm = no".
	 * Tough.  We now have a uniform way of allocating RIDs regardless
	 * of what ever passdb backend people may use.
	 *                                             --jerry (2003-07-10)
	 *********************************************************************/
	
	if ( !pw ) {
		/* 
		 * we can't check both the ending $ and the acb_info.
		 * 
		 * UserManager creates trust accounts (ending in $,
		 * normal that hidden accounts) with the acb_info equals to ACB_NORMAL.
		 * JFM, 11/29/2001
		 */
		if (account[strlen(account)-1] == '$')
			pstrcpy(add_script, lp_addmachine_script());		
		else 
			pstrcpy(add_script, lp_adduser_script());

		if (*add_script) {
  			int add_ret;
  			all_string_sub(add_script, "%u", account, sizeof(account));
  			add_ret = smbrun(add_script,NULL);
 			DEBUG(3,("_samr_create_user: Running the command `%s' gave %d\n", add_script, add_ret));
  		}
		else	/* no add user script -- ask winbindd to do it */
		{
			if ( !winbind_create_user( account, &new_rid ) ) {
				DEBUG(3,("_samr_create_user: winbind_create_user(%s) failed\n", 
					account));
			}
		}
		
	}
	
	/* implicit call to getpwnam() next.  we have a valid SID coming out of this call */

	if ( !NT_STATUS_IS_OK(nt_status = pdb_init_sam_new(&sam_pass, account, new_rid)) )
		return nt_status;
		
 	pdb_set_acct_ctrl(sam_pass, acb_info, PDB_CHANGED);
	
 	if (!pdb_add_sam_account(sam_pass)) {
 		pdb_free_sam(&sam_pass);
 		DEBUG(0, ("could not add user/computer %s to passdb.  Check permissions?\n", 
 			  account));
 		return NT_STATUS_ACCESS_DENIED;		
 	}
 	
	/* Get the user's SID */
	sid_copy(&sid, pdb_get_user_sid(sam_pass));
	
	samr_make_usr_obj_sd(p->mem_ctx, &psd, &sd_size, &sid);
	se_map_generic(&des_access, &usr_generic_mapping);
	if (!NT_STATUS_IS_OK(nt_status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_create_user"))) {
		return nt_status;
	}

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(info);
	info->sid = sid;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info)) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	r_u->user_rid=pdb_get_user_rid(sam_pass);

	r_u->access_granted = acc_granted;

	pdb_free_sam(&sam_pass);

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_reply_connect_anon
 ********************************************************************/

NTSTATUS _samr_connect_anon(pipes_struct *p, SAMR_Q_CONNECT_ANON *q_u, SAMR_R_CONNECT_ANON *r_u)
{
	struct samr_info *info = NULL;
	uint32    des_access = q_u->access_mask;

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_connect_anon\n"));
		r_u->status = NT_STATUS_ACCESS_DENIED;
		return r_u->status;
	}

	/* set up the SAMR connect_anon response */

	r_u->status = NT_STATUS_OK;

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* don't give away the farm but this is probably ok.  The SA_RIGHT_SAM_ENUM_DOMAINS
	   was observed from a win98 client trying to enumerate users (when configured  
	   user level access control on shares)   --jerry */
	   
	se_map_generic( &des_access, &sam_generic_mapping );
	info->acc_granted = des_access & (SA_RIGHT_SAM_ENUM_DOMAINS|SA_RIGHT_SAM_OPEN_DOMAIN);
	
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
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = q_u->access_mask;
	size_t    sd_size;
	NTSTATUS  nt_status;


	DEBUG(5,("_samr_connect: %d\n", __LINE__));

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_connect\n"));
		r_u->status = NT_STATUS_ACCESS_DENIED;
		return r_u->status;
	}

	samr_make_sam_obj_sd(p->mem_ctx, &psd, &sd_size);
	se_map_generic(&des_access, &sam_generic_mapping);
	if (!NT_STATUS_IS_OK(nt_status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_connect"))) {
		return nt_status;
	}

	r_u->status = NT_STATUS_OK;

	/* associate the user's SID and access granted with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;
	info->status = q_u->access_mask;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->connect_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_connect: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 samr_connect4
 ********************************************************************/

NTSTATUS _samr_connect4(pipes_struct *p, SAMR_Q_CONNECT4 *q_u, SAMR_R_CONNECT4 *r_u)
{
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = q_u->access_mask;
	size_t    sd_size;
	NTSTATUS  nt_status;


	DEBUG(5,("_samr_connect4: %d\n", __LINE__));

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_connect4\n"));
		r_u->status = NT_STATUS_ACCESS_DENIED;
		return r_u->status;
	}

	samr_make_sam_obj_sd(p->mem_ctx, &psd, &sd_size);
	se_map_generic(&des_access, &sam_generic_mapping);
	if (!NT_STATUS_IS_OK(nt_status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_connect"))) {
		return nt_status;
	}

	r_u->status = NT_STATUS_OK;

	/* associate the user's SID and access granted with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;
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
	struct samr_info *info;
	fstring domain_name;
	DOM_SID sid;

	r_u->status = NT_STATUS_OK;

	if (!find_policy_by_hnd(p, &q_u->connect_pol, (void**)&info))
		return NT_STATUS_INVALID_HANDLE;

	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(info->acc_granted, 
		SA_RIGHT_SAM_ENUM_DOMAINS, "_samr_lookup_domain"))) 
	{
		return r_u->status;
	}

	rpcstr_pull(domain_name, q_u->uni_domain.buffer, sizeof(domain_name), q_u->uni_domain.uni_str_len*2, 0);

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
		init_unistr2(&uni_name[i], doms[i], UNI_FLAGS_NONE);
		init_sam_entry(&sam[i], &uni_name[i], 0);
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
	struct samr_info *info;
	uint32 num_entries = 2;
	fstring dom[2];
	const char *name;

	r_u->status = NT_STATUS_OK;
	
	if (!find_policy_by_hnd(p, &q_u->pol, (void**)&info))
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(info->acc_granted, SA_RIGHT_SAM_ENUM_DOMAINS, "_samr_enum_domains"))) {
		return r_u->status;
	}

	name = get_global_sam_name();

	fstrcpy(dom[0],name);
	strupper_m(dom[0]);
	fstrcpy(dom[1],"Builtin");

	if (!make_enum_domains(p->mem_ctx, &r_u->sam, &r_u->uni_dom_name, num_entries, dom))
		return NT_STATUS_NO_MEMORY;

	init_samr_r_enum_domains(r_u, q_u->start_idx + num_entries, num_entries);

	return r_u->status;
}

/*******************************************************************
 api_samr_open_alias
 ********************************************************************/

NTSTATUS _samr_open_alias(pipes_struct *p, SAMR_Q_OPEN_ALIAS *q_u, SAMR_R_OPEN_ALIAS *r_u)
{
	DOM_SID sid;
	POLICY_HND domain_pol = q_u->dom_pol;
	uint32 alias_rid = q_u->rid_alias;
	POLICY_HND *alias_pol = &r_u->pol;
	struct    samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = q_u->access_mask;
	size_t    sd_size;
	NTSTATUS  status;

	r_u->status = NT_STATUS_OK;

	/* find the domain policy and get the SID / access bits stored in the domain policy */
	if (!get_lsa_policy_samr_sid(p, &domain_pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_OPEN_ACCOUNT, "_samr_open_alias"))) {
		return status;
	}

	/* append the alias' RID to it */
	if (!sid_append_rid(&sid, alias_rid))
		return NT_STATUS_NO_SUCH_USER;
		
	/*check if access can be granted as requested by client. */
	samr_make_ali_obj_sd(p->mem_ctx, &psd, &sd_size);
	se_map_generic(&des_access,&ali_generic_mapping);
	if (!NT_STATUS_IS_OK(status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_open_alias"))) {
		return status;
	}

	/*
	 * we should check if the rid really exist !!!
	 * JFM.
	 */

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;
		
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, alias_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return r_u->status;
}

/*******************************************************************
 set_user_info_10
 ********************************************************************/

static BOOL set_user_info_10(const SAM_USER_INFO_10 *id10, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd =NULL;
	BOOL ret;
	
	pdb_init_sam(&pwd);
	
	ret = pdb_getsampwsid(pwd, sid);
	
	if(ret==False) {
		pdb_free_sam(&pwd);
		return False;
	}

	if (id10 == NULL) {
		DEBUG(5, ("set_user_info_10: NULL id10\n"));
		pdb_free_sam(&pwd);
		return False;
	}
	
	/* FIX ME: check if the value is really changed --metze */
	if (!pdb_set_acct_ctrl(pwd, id10->acb_info, PDB_CHANGED)) {
		pdb_free_sam(&pwd);
		return False;
	}

	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
	}

	pdb_free_sam(&pwd);

	return True;
}

/*******************************************************************
 set_user_info_12
 ********************************************************************/

static BOOL set_user_info_12(SAM_USER_INFO_12 *id12, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd = NULL;

	pdb_init_sam(&pwd);

	if(!pdb_getsampwsid(pwd, sid)) {
		pdb_free_sam(&pwd);
		return False;
	}

	if (id12 == NULL) {
		DEBUG(2, ("set_user_info_12: id12 is NULL\n"));
		pdb_free_sam(&pwd);
		return False;
	}
 
	if (!pdb_set_lanman_passwd (pwd, id12->lm_pwd, PDB_CHANGED)) {
		pdb_free_sam(&pwd);
		return False;
	}
	if (!pdb_set_nt_passwd     (pwd, id12->nt_pwd, PDB_CHANGED)) {
		pdb_free_sam(&pwd);
		return False;
	}
 	if (!pdb_set_pass_changed_now (pwd)) {
		pdb_free_sam(&pwd);
		return False; 
	}
 
	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	pdb_free_sam(&pwd);
	return True;
}

/*******************************************************************
 The GROUPSID field in the SAM_ACCOUNT changed. Try to tell unix.
 ********************************************************************/
static BOOL set_unix_primary_group(SAM_ACCOUNT *sampass)
{
	struct group *grp;
	gid_t gid;

	if (!NT_STATUS_IS_OK(sid_to_gid(pdb_get_group_sid(sampass),
					&gid))) {
		DEBUG(2,("Could not get gid for primary group of "
			 "user %s\n", pdb_get_username(sampass)));
		return False;
	}

	grp = getgrgid(gid);

	if (grp == NULL) {
		DEBUG(2,("Could not find primary group %lu for "
			 "user %s\n", (unsigned long)gid, 
			 pdb_get_username(sampass)));
		return False;
	}

	if (smb_set_primary_group(grp->gr_name,
				  pdb_get_username(sampass)) != 0) {
		DEBUG(2,("Could not set primary group for user %s to "
			 "%s\n",
			 pdb_get_username(sampass), grp->gr_name));
		return False;
	}

	return True;
}
	

/*******************************************************************
 set_user_info_20
 ********************************************************************/

static BOOL set_user_info_20(SAM_USER_INFO_20 *id20, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd = NULL;
 
	if (id20 == NULL) {
		DEBUG(5, ("set_user_info_20: NULL id20\n"));
		return False;
	}
 
	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwsid(pwd, sid)) {
		pdb_free_sam(&pwd);
		return False;
	}
 
	copy_id20_to_sam_passwd(pwd, id20);

	/* write the change out */
	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	pdb_free_sam(&pwd);

	return True;
}
/*******************************************************************
 set_user_info_21
 ********************************************************************/

static BOOL set_user_info_21(SAM_USER_INFO_21 *id21, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd = NULL;
 
	if (id21 == NULL) {
		DEBUG(5, ("set_user_info_21: NULL id21\n"));
		return False;
	}
 
	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwsid(pwd, sid)) {
		pdb_free_sam(&pwd);
		return False;
	}
 
	copy_id21_to_sam_passwd(pwd, id21);
 
	/*
	 * The funny part about the previous two calls is
	 * that pwd still has the password hashes from the
	 * passdb entry.  These have not been updated from
	 * id21.  I don't know if they need to be set.    --jerry
	 */
 
	if (IS_SAM_CHANGED(pwd, PDB_GROUPSID))
		set_unix_primary_group(pwd);

	/* write the change out */
	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	pdb_free_sam(&pwd);

	return True;
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/

static BOOL set_user_info_23(SAM_USER_INFO_23 *id23, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd = NULL;
	pstring plaintext_buf;
	uint32 len;
	uint16 acct_ctrl;
 
	if (id23 == NULL) {
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return False;
	}
 
 	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwsid(pwd, sid)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	DEBUG(5, ("Attempting administrator password change (level 23) for user %s\n",
		  pdb_get_username(pwd)));

	acct_ctrl = pdb_get_acct_ctrl(pwd);

	if (!decode_pw_buffer((char*)id23->pass, plaintext_buf, 256, &len, STR_UNICODE)) {
		pdb_free_sam(&pwd);
		return False;
 	}
  
	if (!pdb_set_plaintext_passwd (pwd, plaintext_buf)) {
		pdb_free_sam(&pwd);
		return False;
	}
 
	copy_id23_to_sam_passwd(pwd, id23);
 
	/* if it's a trust account, don't update /etc/passwd */
	if (    ( (acct_ctrl &  ACB_DOMTRUST) == ACB_DOMTRUST ) ||
		( (acct_ctrl &  ACB_WSTRUST) ==  ACB_WSTRUST) ||
		( (acct_ctrl &  ACB_SVRTRUST) ==  ACB_SVRTRUST) ) {
		DEBUG(5, ("Changing trust account or non-unix-user password, not updating /etc/passwd\n"));
	} else  {
		/* update the UNIX password */
		if (lp_unix_password_sync() ) {
			struct passwd *passwd = Get_Pwnam(pdb_get_username(pwd));
			if (!passwd) {
				DEBUG(1, ("chgpasswd: Username does not exist in system !?!\n"));
			}
			
			if(!chgpasswd(pdb_get_username(pwd), passwd, "", plaintext_buf, True)) {
				pdb_free_sam(&pwd);
				return False;
			}
		}
	}
 
	ZERO_STRUCT(plaintext_buf);
 
	if (IS_SAM_CHANGED(pwd, PDB_GROUPSID))
		set_unix_primary_group(pwd);

	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
	}
 
	pdb_free_sam(&pwd);

	return True;
}

/*******************************************************************
 set_user_info_pw
 ********************************************************************/

static BOOL set_user_info_pw(char *pass, DOM_SID *sid)
{
	SAM_ACCOUNT *pwd = NULL;
	uint32 len;
	pstring plaintext_buf;
	uint16 acct_ctrl;
 
 	pdb_init_sam(&pwd);
 
	if (!pdb_getsampwsid(pwd, sid)) {
		pdb_free_sam(&pwd);
		return False;
 	}
	
	DEBUG(5, ("Attempting administrator password change for user %s\n",
		  pdb_get_username(pwd)));

	acct_ctrl = pdb_get_acct_ctrl(pwd);

	ZERO_STRUCT(plaintext_buf);
 
	if (!decode_pw_buffer(pass, plaintext_buf, 256, &len, STR_UNICODE)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	if (!pdb_set_plaintext_passwd (pwd, plaintext_buf)) {
		pdb_free_sam(&pwd);
		return False;
	}
 
	/* if it's a trust account, don't update /etc/passwd */
	if ( ( (acct_ctrl &  ACB_DOMTRUST) == ACB_DOMTRUST ) ||
		( (acct_ctrl &  ACB_WSTRUST) ==  ACB_WSTRUST) ||
		( (acct_ctrl &  ACB_SVRTRUST) ==  ACB_SVRTRUST) ) {
		DEBUG(5, ("Changing trust account or non-unix-user password, not updating /etc/passwd\n"));
	} else {
		/* update the UNIX password */
		if (lp_unix_password_sync()) {
			struct passwd *passwd = Get_Pwnam(pdb_get_username(pwd));
			if (!passwd) {
				DEBUG(1, ("chgpasswd: Username does not exist in system !?!\n"));
			}
			
			if(!chgpasswd(pdb_get_username(pwd), passwd, "", plaintext_buf, True)) {
				pdb_free_sam(&pwd);
				return False;
			}
		}
	}
 
	ZERO_STRUCT(plaintext_buf);
 
	DEBUG(5,("set_user_info_pw: pdb_update_pwd()\n"));
 
	/* update the SAMBA password */
	if(!pdb_update_sam_account(pwd)) {
		pdb_free_sam(&pwd);
		return False;
 	}

	pdb_free_sam(&pwd);

	return True;
}

/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/

NTSTATUS _samr_set_userinfo(pipes_struct *p, SAMR_Q_SET_USERINFO *q_u, SAMR_R_SET_USERINFO *r_u)
{
	DOM_SID sid;
	POLICY_HND *pol = &q_u->pol;
	uint16 switch_value = q_u->switch_value;
	SAM_USERINFO_CTR *ctr = q_u->ctr;
	uint32 acc_granted;
	uint32 acc_required;

	DEBUG(5, ("_samr_set_userinfo: %d\n", __LINE__));

	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	acc_required = SA_RIGHT_USER_SET_LOC_COM | SA_RIGHT_USER_SET_ATTRIBUTES; /* This is probably wrong */	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, acc_required, "_samr_set_userinfo"))) {
		return r_u->status;
	}
		
	DEBUG(5, ("_samr_set_userinfo: sid:%s, level:%d\n", sid_string_static(&sid), switch_value));

	if (ctr == NULL) {
		DEBUG(5, ("_samr_set_userinfo: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value) {
		case 0x12:
			if (!set_user_info_12(ctr->info.id12, &sid))
				return NT_STATUS_ACCESS_DENIED;
			break;

		case 24:
			if (!p->session_key.length) {
				return NT_STATUS_NO_USER_SESSION_KEY;
			}
			SamOEMhashBlob(ctr->info.id24->pass, 516, &p->session_key);

			dump_data(100, (char *)ctr->info.id24->pass, 516);

			if (!set_user_info_pw((char *)ctr->info.id24->pass, &sid))
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

			if (!p->session_key.length) {
				return NT_STATUS_NO_USER_SESSION_KEY;
			}
			SamOEMhashBlob(ctr->info.id25->pass, 532, &p->session_key);

			dump_data(100, (char *)ctr->info.id25->pass, 532);

			if (!set_user_info_pw(ctr->info.id25->pass, &sid))
				return NT_STATUS_ACCESS_DENIED;
			break;
#endif
			return NT_STATUS_INVALID_INFO_CLASS;

		case 23:
			if (!p->session_key.length) {
				return NT_STATUS_NO_USER_SESSION_KEY;
			}
			SamOEMhashBlob(ctr->info.id23->pass, 516, &p->session_key);

			dump_data(100, (char *)ctr->info.id23->pass, 516);

			if (!set_user_info_23(ctr->info.id23, &sid))
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
	SAM_USERINFO_CTR *ctr = q_u->ctr;
	POLICY_HND *pol = &q_u->pol;
	uint16 switch_value = q_u->switch_value;
	uint32 acc_granted;
	uint32 acc_required;

	DEBUG(5, ("samr_reply_set_userinfo2: %d\n", __LINE__));

	r_u->status = NT_STATUS_OK;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, pol, &sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	acc_required = SA_RIGHT_USER_SET_LOC_COM | SA_RIGHT_USER_SET_ATTRIBUTES; /* This is probably wrong */	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, acc_required, "_samr_set_userinfo2"))) {
		return r_u->status;
	}

	DEBUG(5, ("samr_reply_set_userinfo2: sid:%s\n", sid_string_static(&sid)));

	if (ctr == NULL) {
		DEBUG(5, ("samr_reply_set_userinfo2: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	switch_value=ctr->switch_value;

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value) {
		case 21:
			if (!set_user_info_21(ctr->info.id21, &sid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		case 20:
			if (!set_user_info_20(ctr->info.id20, &sid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		case 16:
			if (!set_user_info_10(ctr->info.id10, &sid))
				return NT_STATUS_ACCESS_DENIED;
			break;
		case 18:
			/* Used by AS/U JRA. */
			if (!set_user_info_12(ctr->info.id12, &sid))
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
	int num_groups = 0, tmp_num_groups=0;
	uint32 *rids=NULL, *new_rids=NULL, *tmp_rids=NULL;
	struct samr_info *info = NULL;
	int i,j;
		
	NTSTATUS ntstatus1;
	NTSTATUS ntstatus2;

	/* until i see a real useraliases query, we fack one up */

	/* I have seen one, JFM 2/12/2001 */
	/*
	 * Explanation of what this call does:
	 * for all the SID given in the request:
	 * return a list of alias (local groups)
	 * that have those SID as members.
	 *
	 * and that's the alias in the domain specified
	 * in the policy_handle
	 *
	 * if the policy handle is on an incorrect sid
	 * for example a user's sid
	 * we should reply NT_STATUS_OBJECT_TYPE_MISMATCH
	 */
	
	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_query_useraliases: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;
		
	ntstatus1 = access_check_samr_function(info->acc_granted, SA_RIGHT_DOMAIN_LOOKUP_ALIAS_BY_MEM, "_samr_query_useraliases");
	ntstatus2 = access_check_samr_function(info->acc_granted, SA_RIGHT_DOMAIN_OPEN_ACCOUNT, "_samr_query_useraliases");
	
	if (!NT_STATUS_IS_OK(ntstatus1) || !NT_STATUS_IS_OK(ntstatus2)) {
		if (!(NT_STATUS_EQUAL(ntstatus1,NT_STATUS_ACCESS_DENIED) && NT_STATUS_IS_OK(ntstatus2)) &&
		    !(NT_STATUS_EQUAL(ntstatus1,NT_STATUS_ACCESS_DENIED) && NT_STATUS_IS_OK(ntstatus1))) {
			return (NT_STATUS_IS_OK(ntstatus1)) ? ntstatus2 : ntstatus1;
		}
	}		

	if (!sid_check_is_domain(&info->sid) &&
	    !sid_check_is_builtin(&info->sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;


	for (i=0; i<q_u->num_sids1; i++) {

		r_u->status=get_alias_user_groups(p->mem_ctx, &info->sid, &tmp_num_groups, &tmp_rids, &(q_u->sid[i].sid));

		/*
		 * if there is an error, we just continue as
		 * it can be an unfound user or group
		 */
		if (!NT_STATUS_IS_OK(r_u->status)) {
			DEBUG(10,("_samr_query_useraliases: an error occured while getting groups\n"));
			continue;
		}

		if (tmp_num_groups==0) {
			DEBUG(10,("_samr_query_useraliases: no groups found\n"));
			continue;
		}

		new_rids=(uint32 *)talloc_realloc(p->mem_ctx, rids, (num_groups+tmp_num_groups)*sizeof(uint32));
		if (new_rids==NULL) {
			DEBUG(0,("_samr_query_useraliases: could not realloc memory\n"));
			return NT_STATUS_NO_MEMORY;
		}
		rids=new_rids;

		for (j=0; j<tmp_num_groups; j++)
			rids[j+num_groups]=tmp_rids[j];
		
		safe_free(tmp_rids);
		
		num_groups+=tmp_num_groups;
	}
	
	init_samr_r_query_useraliases(r_u, num_groups, rids, NT_STATUS_OK);
	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_query_aliasmem
*********************************************************************/

NTSTATUS _samr_query_aliasmem(pipes_struct *p, SAMR_Q_QUERY_ALIASMEM *q_u, SAMR_R_QUERY_ALIASMEM *r_u)
{
	int i;

	int num_sids = 0;
	DOM_SID2 *sid;
	DOM_SID *sids=NULL;

	DOM_SID alias_sid;

	uint32 acc_granted;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->alias_pol, &alias_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = 
		access_check_samr_function(acc_granted, SA_RIGHT_ALIAS_GET_MEMBERS, "_samr_query_aliasmem"))) {
		return r_u->status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_static(&alias_sid)));

	if (!pdb_enum_aliasmem(&alias_sid, &sids, &num_sids))
		return NT_STATUS_NO_SUCH_ALIAS;

	sid = (DOM_SID2 *)talloc_zero(p->mem_ctx, sizeof(DOM_SID2) * num_sids);	
	if (num_sids!=0 && sid == NULL) {
		SAFE_FREE(sids);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_sids; i++) {
		init_dom_sid2(&sid[i], &sids[i]);
	}

	init_samr_r_query_aliasmem(r_u, num_sids, sid, NT_STATUS_OK);

	SAFE_FREE(sids);

	return NT_STATUS_OK;
}

static void add_uid_to_array_unique(uid_t uid, uid_t **uids, int *num)
{
	int i;

	if ((*num) >= groups_max())
		return;

	for (i=0; i<*num; i++) {
		if ((*uids)[i] == uid)
			return;
	}
	
	*uids = Realloc(*uids, (*num+1) * sizeof(uid_t));

	if (*uids == NULL)
		return;

	(*uids)[*num] = uid;
	*num += 1;
}


static BOOL get_memberuids(gid_t gid, uid_t **uids, int *num)
{
	struct group *grp;
	char **gr;
	struct sys_pwent *userlist, *user;
 
	*uids = NULL;
	*num = 0;

	/* We only look at our own sam, so don't care about imported stuff */

	winbind_off();

	if ((grp = getgrgid(gid)) == NULL) {
		winbind_on();
		return False;
	}

	/* Primary group members */

	userlist = getpwent_list();

	for (user = userlist; user != NULL; user = user->next) {
		if (user->pw_gid != gid)
			continue;
		add_uid_to_array_unique(user->pw_uid, uids, num);
	}

	pwent_free(userlist);

	/* Secondary group members */

	gr = grp->gr_mem;
	while ((*gr != NULL) && ((*gr)[0] != '\0')) {
		struct passwd *pw = getpwnam(*gr);

		if (pw == NULL)
			continue;

		add_uid_to_array_unique(pw->pw_uid, uids, num);

		gr += 1;
	}

	winbind_on();

	return True;
}	

/*********************************************************************
 _samr_query_groupmem
*********************************************************************/

NTSTATUS _samr_query_groupmem(pipes_struct *p, SAMR_Q_QUERY_GROUPMEM *q_u, SAMR_R_QUERY_GROUPMEM *r_u)
{
	int final_num_rids, i;
	DOM_SID group_sid;
	fstring group_sid_str;
	uid_t *uids;
	int num;
	gid_t gid;

	uint32 *rid=NULL;
	uint32 *attr=NULL;

	uint32 acc_granted;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->group_pol, &group_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_GROUP_GET_MEMBERS, "_samr_query_groupmem"))) {
		return r_u->status;
	}
		
	sid_to_string(group_sid_str, &group_sid);
	DEBUG(10, ("sid is %s\n", group_sid_str));

	if (!sid_check_is_in_our_domain(&group_sid)) {
		DEBUG(3, ("sid %s is not in our domain\n", group_sid_str));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	DEBUG(10, ("lookup on Domain SID\n"));

	if (!NT_STATUS_IS_OK(sid_to_gid(&group_sid, &gid)))
		return NT_STATUS_NO_SUCH_GROUP;

	if(!get_memberuids(gid, &uids, &num))
		return NT_STATUS_NO_SUCH_GROUP;

	rid=talloc_zero(p->mem_ctx, sizeof(uint32)*num);
	attr=talloc_zero(p->mem_ctx, sizeof(uint32)*num);
	
	if (num!=0 && (rid==NULL || attr==NULL))
		return NT_STATUS_NO_MEMORY;
	
	final_num_rids = 0;
		
	for (i=0; i<num; i++) {
		DOM_SID sid;

		if (!NT_STATUS_IS_OK(uid_to_sid(&sid, uids[i]))) {
			DEBUG(1, ("Could not map member uid to SID\n"));
			continue;
		}

		if (!sid_check_is_in_our_domain(&sid)) {
			DEBUG(1, ("Inconsistent SAM -- group member uid not "
				  "in our domain\n"));
			continue;
		}

		sid_peek_rid(&sid, &rid[final_num_rids]);

		/* Hmm. In a trace I got the constant 7 here from NT. */
		attr[final_num_rids] = SID_NAME_USER;

		final_num_rids += 1;
	}

	SAFE_FREE(uids);

	init_samr_r_query_groupmem(r_u, final_num_rids, rid, attr,
				   NT_STATUS_OK);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_add_aliasmem
*********************************************************************/

NTSTATUS _samr_add_aliasmem(pipes_struct *p, SAMR_Q_ADD_ALIASMEM *q_u, SAMR_R_ADD_ALIASMEM *r_u)
{
	DOM_SID alias_sid;
	uint32 acc_granted;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->alias_pol, &alias_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_ALIAS_ADD_MEMBER, "_samr_add_aliasmem"))) {
		return r_u->status;
	}
		
	DEBUG(10, ("sid is %s\n", sid_string_static(&alias_sid)));

	if (!pdb_add_aliasmem(&alias_sid, &q_u->sid.sid))
		return NT_STATUS_ACCESS_DENIED;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_del_aliasmem
*********************************************************************/

NTSTATUS _samr_del_aliasmem(pipes_struct *p, SAMR_Q_DEL_ALIASMEM *q_u, SAMR_R_DEL_ALIASMEM *r_u)
{
	DOM_SID alias_sid;
	uint32 acc_granted;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->alias_pol, &alias_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_ALIAS_REMOVE_MEMBER, "_samr_del_aliasmem"))) {
		return r_u->status;
	}
	
	DEBUG(10, ("_samr_del_aliasmem:sid is %s\n",
		   sid_string_static(&alias_sid)));

	if (!pdb_del_aliasmem(&alias_sid, &q_u->sid.sid))
		return NT_STATUS_ACCESS_DENIED;
	
	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_add_groupmem
*********************************************************************/

NTSTATUS _samr_add_groupmem(pipes_struct *p, SAMR_Q_ADD_GROUPMEM *q_u, SAMR_R_ADD_GROUPMEM *r_u)
{
	DOM_SID group_sid;
	DOM_SID user_sid;
	fstring group_sid_str;
	uid_t uid;
	struct passwd *pwd;
	struct group *grp;
	fstring grp_name;
	GROUP_MAP map;
	NTSTATUS ret;
	SAM_ACCOUNT *sam_user=NULL;
	BOOL check;
	uint32 acc_granted;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &group_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_GROUP_ADD_MEMBER, "_samr_add_groupmem"))) {
		return r_u->status;
	}

	sid_to_string(group_sid_str, &group_sid);
	DEBUG(10, ("sid is %s\n", group_sid_str));

	if (sid_compare(&group_sid, get_global_sam_sid())<=0)
		return NT_STATUS_NO_SUCH_GROUP;

	DEBUG(10, ("lookup on Domain SID\n"));

	if(!get_domain_group_from_sid(group_sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	sid_copy(&user_sid, get_global_sam_sid());
	sid_append_rid(&user_sid, q_u->rid);

	ret = pdb_init_sam(&sam_user);
	if (!NT_STATUS_IS_OK(ret))
		return ret;
	
	check = pdb_getsampwsid(sam_user, &user_sid);
	
	if (check != True) {
		pdb_free_sam(&sam_user);
		return NT_STATUS_NO_SUCH_USER;
	}

	/* check a real user exist before we run the script to add a user to a group */
	if (!NT_STATUS_IS_OK(sid_to_uid(pdb_get_user_sid(sam_user), &uid))) {
		pdb_free_sam(&sam_user);
		return NT_STATUS_NO_SUCH_USER;
	}

	pdb_free_sam(&sam_user);

	if ((pwd=getpwuid_alloc(uid)) == NULL) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if ((grp=getgrgid(map.gid)) == NULL) {
		passwd_free(&pwd);
		return NT_STATUS_NO_SUCH_GROUP;
	}

	/* we need to copy the name otherwise it's overloaded in user_in_unix_group_list */
	fstrcpy(grp_name, grp->gr_name);

	/* if the user is already in the group */
	if(user_in_unix_group_list(pwd->pw_name, grp_name)) {
		passwd_free(&pwd);
		return NT_STATUS_MEMBER_IN_GROUP;
	}

	/* 
	 * ok, the group exist, the user exist, the user is not in the group,
	 *
	 * we can (finally) add it to the group !
	 */

	smb_add_user_group(grp_name, pwd->pw_name);

	/* check if the user has been added then ... */
	if(!user_in_unix_group_list(pwd->pw_name, grp_name)) {
		passwd_free(&pwd);
		return NT_STATUS_MEMBER_NOT_IN_GROUP;		/* don't know what to reply else */
	}

	passwd_free(&pwd);
	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_del_groupmem
*********************************************************************/

NTSTATUS _samr_del_groupmem(pipes_struct *p, SAMR_Q_DEL_GROUPMEM *q_u, SAMR_R_DEL_GROUPMEM *r_u)
{
	DOM_SID group_sid;
	DOM_SID user_sid;
	SAM_ACCOUNT *sam_pass=NULL;
	GROUP_MAP map;
	fstring grp_name;
	struct group *grp;
	uint32 acc_granted;

	/*
	 * delete the group member named q_u->rid
	 * who is a member of the sid associated with the handle
	 * the rid is a user's rid as the group is a domain group.
	 */

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &group_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_GROUP_REMOVE_MEMBER, "_samr_del_groupmem"))) {
		return r_u->status;
	}
		
	if (!sid_check_is_in_our_domain(&group_sid))
		return NT_STATUS_NO_SUCH_GROUP;

	sid_copy(&user_sid, get_global_sam_sid());
	sid_append_rid(&user_sid, q_u->rid);

	if (!get_domain_group_from_sid(group_sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	if ((grp=getgrgid(map.gid)) == NULL)
		return NT_STATUS_NO_SUCH_GROUP;

	/* we need to copy the name otherwise it's overloaded in user_in_group_list */
	fstrcpy(grp_name, grp->gr_name);

	/* check if the user exists before trying to remove it from the group */
	pdb_init_sam(&sam_pass);
	if (!pdb_getsampwsid(sam_pass, &user_sid)) {
		DEBUG(5,("User %s doesn't exist.\n", pdb_get_username(sam_pass)));
		pdb_free_sam(&sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}

	/* if the user is not in the group */
	if (!user_in_unix_group_list(pdb_get_username(sam_pass), grp_name)) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_MEMBER_NOT_IN_GROUP;
	}

	smb_delete_user_group(grp_name, pdb_get_username(sam_pass));

	/* check if the user has been removed then ... */
	if (user_in_unix_group_list(pdb_get_username(sam_pass), grp_name)) {
		pdb_free_sam(&sam_pass);
		return NT_STATUS_ACCESS_DENIED;		/* don't know what to reply else */
	}
	
	pdb_free_sam(&sam_pass);
	return NT_STATUS_OK;

}

/****************************************************************************
 Delete a UNIX user on demand.
****************************************************************************/

static int smb_delete_user(const char *unix_user)
{
	pstring del_script;
	int ret;

	/* try winbindd first since it is impossible to determine where 
	   a user came from via NSS.  Try the delete user script if this fails
	   meaning the user did not exist in winbindd's list of accounts */

	if ( winbind_delete_user( unix_user ) ) {
		DEBUG(3,("winbind_delete_user: removed user (%s)\n", unix_user));
		return 0;
	}


	/* fall back to 'delete user script' */

	pstrcpy(del_script, lp_deluser_script());
	if (! *del_script)
		return -1;
	all_string_sub(del_script, "%u", unix_user, sizeof(pstring));
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_user: Running the command `%s' gave %d\n",del_script,ret));

	return ret;
}

/*********************************************************************
 _samr_delete_dom_user
*********************************************************************/

NTSTATUS _samr_delete_dom_user(pipes_struct *p, SAMR_Q_DELETE_DOM_USER *q_u, SAMR_R_DELETE_DOM_USER *r_u )
{
	DOM_SID user_sid;
	SAM_ACCOUNT *sam_pass=NULL;
	uint32 acc_granted;

	DEBUG(5, ("_samr_delete_dom_user: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->user_pol, &user_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, STD_RIGHT_DELETE_ACCESS, "_samr_delete_dom_user"))) {
		return r_u->status;
	}
		
	if (!sid_check_is_in_our_domain(&user_sid))
		return NT_STATUS_CANNOT_DELETE;

	/* check if the user exists before trying to delete */
	pdb_init_sam(&sam_pass);
	if(!pdb_getsampwsid(sam_pass, &user_sid)) {
		DEBUG(5,("_samr_delete_dom_user:User %s doesn't exist.\n", 
			sid_string_static(&user_sid)));
		pdb_free_sam(&sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}

	/* delete the unix side */
	/*
	 * note: we don't check if the delete really happened
	 * as the script is not necessary present
	 * and maybe the sysadmin doesn't want to delete the unix side
	 */
	smb_delete_user(pdb_get_username(sam_pass));

	/* and delete the samba side */
	if (!pdb_delete_sam_account(sam_pass)) {
		DEBUG(5,("_samr_delete_dom_user:Failed to delete entry for user %s.\n", pdb_get_username(sam_pass)));
		pdb_free_sam(&sam_pass);
		return NT_STATUS_CANNOT_DELETE;
	}
	
	pdb_free_sam(&sam_pass);

	if (!close_policy_hnd(p, &q_u->user_pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_delete_dom_group
*********************************************************************/

NTSTATUS _samr_delete_dom_group(pipes_struct *p, SAMR_Q_DELETE_DOM_GROUP *q_u, SAMR_R_DELETE_DOM_GROUP *r_u)
{
	DOM_SID group_sid;
	DOM_SID dom_sid;
	uint32 group_rid;
	fstring group_sid_str;
	gid_t gid;
	struct group *grp;
	GROUP_MAP map;
	uint32 acc_granted;

	DEBUG(5, ("samr_delete_dom_group: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->group_pol, &group_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, STD_RIGHT_DELETE_ACCESS, "_samr_delete_dom_group"))) {
		return r_u->status;
	}
		
	sid_copy(&dom_sid, &group_sid);
	sid_to_string(group_sid_str, &dom_sid);
	sid_split_rid(&dom_sid, &group_rid);

	DEBUG(10, ("sid is %s\n", group_sid_str));

	/* we check if it's our SID before deleting */
	if (!sid_equal(&dom_sid, get_global_sam_sid()))
		return NT_STATUS_NO_SUCH_GROUP;

	DEBUG(10, ("lookup on Domain SID\n"));

	if(!get_domain_group_from_sid(group_sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;

	gid=map.gid;

	/* check if group really exists */
	if ( (grp=getgrgid(gid)) == NULL)
		return NT_STATUS_NO_SUCH_GROUP;

	/* delete mapping first */
	if(!pdb_delete_group_mapping_entry(group_sid))
		return NT_STATUS_ACCESS_DENIED;
		
	/* we can delete the UNIX group */
	smb_delete_group(grp->gr_name);

	/* check if the group has been successfully deleted */
	if ( (grp=getgrgid(gid)) != NULL)
		return NT_STATUS_ACCESS_DENIED;


	if (!close_policy_hnd(p, &q_u->group_pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_delete_dom_alias
*********************************************************************/

NTSTATUS _samr_delete_dom_alias(pipes_struct *p, SAMR_Q_DELETE_DOM_ALIAS *q_u, SAMR_R_DELETE_DOM_ALIAS *r_u)
{
	DOM_SID alias_sid;
	uint32 acc_granted;

	DEBUG(5, ("_samr_delete_dom_alias: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->alias_pol, &alias_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, STD_RIGHT_DELETE_ACCESS, "_samr_delete_dom_alias"))) {
		return r_u->status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_static(&alias_sid)));

	if (!sid_check_is_in_our_domain(&alias_sid))
		return NT_STATUS_NO_SUCH_ALIAS;
		
	DEBUG(10, ("lookup on Local SID\n"));

	/* Have passdb delete the alias */
	if (!pdb_delete_alias(&alias_sid))
		return NT_STATUS_ACCESS_DENIED;

	if (!close_policy_hnd(p, &q_u->alias_pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_create_dom_group
*********************************************************************/

NTSTATUS _samr_create_dom_group(pipes_struct *p, SAMR_Q_CREATE_DOM_GROUP *q_u, SAMR_R_CREATE_DOM_GROUP *r_u)
{
	DOM_SID dom_sid;
	DOM_SID info_sid;
	fstring name;
	fstring sid_string;
	struct group *grp;
	struct samr_info *info;
	uint32 acc_granted;
	gid_t gid;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &dom_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_CREATE_GROUP, "_samr_create_dom_group"))) {
		return r_u->status;
	}
		
	if (!sid_equal(&dom_sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	/* TODO: check if allowed to create group and add a become_root/unbecome_root pair.*/

	unistr2_to_ascii(name, &q_u->uni_acct_desc, sizeof(name)-1);

	/* check if group already exist */
	if ((grp=getgrnam(name)) != NULL)
		return NT_STATUS_GROUP_EXISTS;

	/* we can create the UNIX group */
	if (smb_create_group(name, &gid) != 0)
		return NT_STATUS_ACCESS_DENIED;

	/* check if the group has been successfully created */
	if ((grp=getgrgid(gid)) == NULL)
		return NT_STATUS_ACCESS_DENIED;

	r_u->rid=pdb_gid_to_group_rid(grp->gr_gid);

	/* add the group to the mapping table */
	sid_copy(&info_sid, get_global_sam_sid());
	sid_append_rid(&info_sid, r_u->rid);
	sid_to_string(sid_string, &info_sid);

	if(!add_initial_entry(grp->gr_gid, sid_string, SID_NAME_DOM_GRP, name, NULL))
		return NT_STATUS_ACCESS_DENIED;

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_create_dom_alias
*********************************************************************/

NTSTATUS _samr_create_dom_alias(pipes_struct *p, SAMR_Q_CREATE_DOM_ALIAS *q_u, SAMR_R_CREATE_DOM_ALIAS *r_u)
{
	DOM_SID dom_sid;
	DOM_SID info_sid;
	fstring name;
	struct group *grp;
	struct samr_info *info;
	uint32 acc_granted;
	gid_t gid;
	NTSTATUS result;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, &q_u->dom_pol, &dom_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
		
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_CREATE_ALIAS, "_samr_create_alias"))) {
		return r_u->status;
	}
		
	if (!sid_equal(&dom_sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	/* TODO: check if allowed to create group  and add a become_root/unbecome_root pair.*/

	unistr2_to_ascii(name, &q_u->uni_acct_desc, sizeof(name)-1);

	/* Have passdb create the alias */
	result = pdb_create_alias(name, &r_u->rid);

	if (!NT_STATUS_IS_OK(result))
		return result;

	sid_copy(&info_sid, get_global_sam_sid());
	sid_append_rid(&info_sid, r_u->rid);

	if (!NT_STATUS_IS_OK(sid_to_gid(&info_sid, &gid)))
		return NT_STATUS_ACCESS_DENIED;

	/* check if the group has been successfully created */
	if ((grp=getgrgid(gid)) == NULL)
		return NT_STATUS_ACCESS_DENIED;

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->alias_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_query_groupinfo

sends the name/comment pair of a domain group
level 1 send also the number of users of that group
*********************************************************************/

NTSTATUS _samr_query_groupinfo(pipes_struct *p, SAMR_Q_QUERY_GROUPINFO *q_u, SAMR_R_QUERY_GROUPINFO *r_u)
{
	DOM_SID group_sid;
	GROUP_MAP map;
	DOM_SID *sids=NULL;
	uid_t *uids;
	int num=0;
	GROUP_INFO_CTR *ctr;
	uint32 acc_granted;
	BOOL ret;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &group_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_GROUP_LOOKUP_INFO, "_samr_query_groupinfo"))) {
		return r_u->status;
	}
		
	become_root();
	ret = get_domain_group_from_sid(group_sid, &map);
	unbecome_root();
	if (!ret)
		return NT_STATUS_INVALID_HANDLE;

	ctr=(GROUP_INFO_CTR *)talloc_zero(p->mem_ctx, sizeof(GROUP_INFO_CTR));
	if (ctr==NULL)
		return NT_STATUS_NO_MEMORY;

	switch (q_u->switch_level) {
		case 1:
			ctr->switch_value1 = 1;
			if(!get_memberuids(map.gid, &uids, &num))
				return NT_STATUS_NO_SUCH_GROUP;
			SAFE_FREE(uids);
			init_samr_group_info1(&ctr->group.info1, map.nt_name, map.comment, num);
			SAFE_FREE(sids);
			break;
		case 3:
			ctr->switch_value1 = 3;
			init_samr_group_info3(&ctr->group.info3);
			break;
		case 4:
			ctr->switch_value1 = 4;
			init_samr_group_info4(&ctr->group.info4, map.comment);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	init_samr_r_query_groupinfo(r_u, ctr, NT_STATUS_OK);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_set_groupinfo
 
 update a domain group's comment.
*********************************************************************/

NTSTATUS _samr_set_groupinfo(pipes_struct *p, SAMR_Q_SET_GROUPINFO *q_u, SAMR_R_SET_GROUPINFO *r_u)
{
	DOM_SID group_sid;
	GROUP_MAP map;
	GROUP_INFO_CTR *ctr;
	uint32 acc_granted;

	if (!get_lsa_policy_samr_sid(p, &q_u->pol, &group_sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_GROUP_SET_INFO, "_samr_set_groupinfo"))) {
		return r_u->status;
	}
		
	if (!get_domain_group_from_sid(group_sid, &map))
		return NT_STATUS_NO_SUCH_GROUP;
	
	ctr=q_u->ctr;

	switch (ctr->switch_value1) {
		case 1:
			unistr2_to_ascii(map.comment, &(ctr->group.info1.uni_acct_desc), sizeof(map.comment)-1);
			break;
		case 4:
			unistr2_to_ascii(map.comment, &(ctr->group.info4.uni_acct_desc), sizeof(map.comment)-1);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	if(!pdb_update_group_mapping_entry(&map)) {
		return NT_STATUS_NO_SUCH_GROUP;
	}

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_set_aliasinfo
 
 update an alias's comment.
*********************************************************************/

NTSTATUS _samr_set_aliasinfo(pipes_struct *p, SAMR_Q_SET_ALIASINFO *q_u, SAMR_R_SET_ALIASINFO *r_u)
{
	DOM_SID group_sid;
	struct acct_info info;
	ALIAS_INFO_CTR *ctr;
	uint32 acc_granted;

	if (!get_lsa_policy_samr_sid(p, &q_u->alias_pol, &group_sid, &acc_granted))
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(r_u->status = access_check_samr_function(acc_granted, SA_RIGHT_ALIAS_SET_INFO, "_samr_set_aliasinfo"))) {
		return r_u->status;
	}
		
	ctr=&q_u->ctr;

	switch (ctr->switch_value1) {
		case 3:
			unistr2_to_ascii(info.acct_desc,
					 &(ctr->alias.info3.uni_acct_desc),
					 sizeof(info.acct_desc)-1);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	if(!pdb_set_aliasinfo(&group_sid, &info)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_get_dom_pwinfo
*********************************************************************/

NTSTATUS _samr_get_dom_pwinfo(pipes_struct *p, SAMR_Q_GET_DOM_PWINFO *q_u, SAMR_R_GET_DOM_PWINFO *r_u)
{
	/* Perform access check.  Since this rpc does not require a
	   policy handle it will not be caught by the access checks on
	   SAMR_CONNECT or SAMR_CONNECT_ANON. */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_get_dom_pwinfo\n"));
		r_u->status = NT_STATUS_ACCESS_DENIED;
		return r_u->status;
	}

	/* Actually, returning zeros here works quite well :-). */

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_open_group
*********************************************************************/

NTSTATUS _samr_open_group(pipes_struct *p, SAMR_Q_OPEN_GROUP *q_u, SAMR_R_OPEN_GROUP *r_u)
{
	DOM_SID sid;
	DOM_SID info_sid;
	GROUP_MAP map;
	struct samr_info *info;
	SEC_DESC         *psd = NULL;
	uint32            acc_granted;
	uint32            des_access = q_u->access_mask;
	size_t            sd_size;
	NTSTATUS          status;
	fstring sid_string;
	BOOL ret;

	if (!get_lsa_policy_samr_sid(p, &q_u->domain_pol, &sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	if (!NT_STATUS_IS_OK(status = access_check_samr_function(acc_granted, SA_RIGHT_DOMAIN_OPEN_ACCOUNT, "_samr_open_group"))) {
		return status;
	}
		
	/*check if access can be granted as requested by client. */
	samr_make_grp_obj_sd(p->mem_ctx, &psd, &sd_size);
	se_map_generic(&des_access,&grp_generic_mapping);
	if (!NT_STATUS_IS_OK(status = 
			     access_check_samr_object(psd, p->pipe_user.nt_user_token, 
						      des_access, &acc_granted, "_samr_open_group"))) {
		return status;
	}


	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	sid_copy(&info_sid, get_global_sam_sid());
	sid_append_rid(&info_sid, q_u->rid_group);
	sid_to_string(sid_string, &info_sid);

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;
		
	info->acc_granted = acc_granted;

	DEBUG(10, ("_samr_open_group:Opening SID: %s\n", sid_string));

	/* check if that group really exists */
	become_root();
	ret = get_domain_group_from_sid(info->sid, &map);
	unbecome_root();
	if (!ret)
		return NT_STATUS_NO_SUCH_GROUP;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, &r_u->pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_remove_sid_foreign_domain
*********************************************************************/

NTSTATUS _samr_remove_sid_foreign_domain(pipes_struct *p, 
                                          SAMR_Q_REMOVE_SID_FOREIGN_DOMAIN *q_u, 
                                          SAMR_R_REMOVE_SID_FOREIGN_DOMAIN *r_u)
{
	DOM_SID			delete_sid, alias_sid;
	SAM_ACCOUNT 		*sam_pass=NULL;
	uint32 			acc_granted;
	GROUP_MAP 		map;
	BOOL			is_user = False;
	NTSTATUS		result;
	enum SID_NAME_USE	type = SID_NAME_UNKNOWN;
	
	sid_copy( &delete_sid, &q_u->sid.sid );
	
	DEBUG(5,("_samr_remove_sid_foreign_domain: removing SID [%s]\n",
		sid_string_static(&delete_sid)));
		
	/* Find the policy handle. Open a policy on it. */
	
	if (!get_lsa_policy_samr_sid(p, &q_u->dom_pol, &alias_sid, &acc_granted)) 
		return NT_STATUS_INVALID_HANDLE;
	
	result = access_check_samr_function(acc_granted, STD_RIGHT_DELETE_ACCESS, 
		"_samr_remove_sid_foreign_domain");
		
	if (!NT_STATUS_IS_OK(result)) 
		return result;
			
	DEBUG(8, ("_samr_remove_sid_foreign_domain:sid is %s\n", 
		sid_string_static(&alias_sid)));
		
	/* make sure we can handle this */
	
	if ( sid_check_is_domain(&alias_sid) )
		type = SID_NAME_DOM_GRP;
	else if ( sid_check_is_builtin(&alias_sid) )
		type = SID_NAME_ALIAS;
	
	if ( type == SID_NAME_UNKNOWN ) {
		DEBUG(10, ("_samr_remove_sid_foreign_domain: can't operate on what we don't own!\n"));
		return NT_STATUS_OK;
	}

	/* check if the user exists before trying to delete */
	
	pdb_init_sam(&sam_pass);
	
	if ( pdb_getsampwsid(sam_pass, &delete_sid) ) {
		is_user = True;
	} else {
		/* maybe it is a group */
		if( !pdb_getgrsid(&map, delete_sid) ) {
			DEBUG(3,("_samr_remove_sid_foreign_domain: %s is not a user or a group!\n",
				sid_string_static(&delete_sid)));
			result = NT_STATUS_INVALID_SID;
			goto done;
		}
	}
	
	/* we can only delete a user from a group since we don't have 
	   nested groups anyways.  So in the latter case, just say OK */
	   
	if ( is_user ) {
		GROUP_MAP	*mappings = NULL;
		int		num_groups, i;
		struct group	*grp2;
		
		if ( pdb_enum_group_mapping(type, &mappings, &num_groups, False) && num_groups>0 ) {
		
			/* interate over the groups */
			for ( i=0; i<num_groups; i++ ) {

				grp2 = getgrgid(mappings[i].gid);

				if ( !grp2 ) {
					DEBUG(0,("_samr_remove_sid_foreign_domain: group mapping without UNIX group!\n"));
					continue;
				}
			
				if ( !user_in_unix_group_list(pdb_get_username(sam_pass), grp2->gr_name) )
					continue;
				
				smb_delete_user_group(grp2->gr_name, pdb_get_username(sam_pass));
				
				if ( user_in_unix_group_list(pdb_get_username(sam_pass), grp2->gr_name) ) {
					/* should we fail here ? */
					DEBUG(0,("_samr_remove_sid_foreign_domain: Delete user [%s] from group [%s] failed!\n",
						pdb_get_username(sam_pass), grp2->gr_name ));
					continue;
				}
					
				DEBUG(10,("_samr_remove_sid_foreign_domain: Removed user [%s] from group [%s]!\n",
					pdb_get_username(sam_pass), grp2->gr_name ));
			}
			
			SAFE_FREE(mappings);
		}
	}
	
	result = NT_STATUS_OK;
done:

	pdb_free_sam(&sam_pass);

	return result;
}

/*******************************************************************
 _samr_unknown_2e
 ********************************************************************/

NTSTATUS _samr_unknown_2e(pipes_struct *p, SAMR_Q_UNKNOWN_2E *q_u, SAMR_R_UNKNOWN_2E *r_u)
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

	uint32 account_policy_temp;

	if ((ctr = (SAM_UNK_CTR *)talloc_zero(p->mem_ctx, sizeof(SAM_UNK_CTR))) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(ctr);

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_unknown_2e: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->domain_pol, (void **)&info))
		return NT_STATUS_INVALID_HANDLE;

	switch (q_u->switch_value) {
		case 0x01:
			account_policy_get(AP_MIN_PASSWORD_LEN, &account_policy_temp);
			min_pass_len = account_policy_temp;

			account_policy_get(AP_PASSWORD_HISTORY, &account_policy_temp);
			pass_hist = account_policy_temp;

			account_policy_get(AP_USER_MUST_LOGON_TO_CHG_PASS, &account_policy_temp);
			flag = account_policy_temp;

			account_policy_get(AP_MAX_PASSWORD_AGE, &account_policy_temp);
			u_expire = account_policy_temp;

			account_policy_get(AP_MIN_PASSWORD_AGE, &account_policy_temp);
			u_min_age = account_policy_temp;

			unix_to_nt_time_abs(&nt_expire, u_expire);
			unix_to_nt_time_abs(&nt_min_age, u_min_age);

			init_unk_info1(&ctr->info.inf1, (uint16)min_pass_len, (uint16)pass_hist, 
			               flag, nt_expire, nt_min_age);
			break;
		case 0x02:
			become_root();		
			r_u->status=load_sampwd_entries(info, ACB_NORMAL, False);
			unbecome_root();
			if (!NT_STATUS_IS_OK(r_u->status)) {
				DEBUG(5, ("_samr_unknown_2e: load_sampwd_entries failed\n"));
				return r_u->status;
			}
			num_users=info->disp_info.num_user_account;
			free_samr_db(info);
			
			r_u->status=load_group_domain_entries(info, get_global_sam_sid());
			if (NT_STATUS_IS_ERR(r_u->status)) {
				DEBUG(5, ("_samr_unknown_2e: load_group_domain_entries failed\n"));
				return r_u->status;
			}
			num_groups=info->disp_info.num_group_account;
			free_samr_db(info);

			/* The time call below is to get a sequence number for the sam. FIXME !!! JRA. */
			init_unk_info2(&ctr->info.inf2, lp_workgroup(), global_myname(), (uint32) time(NULL), 
				       num_users, num_groups, num_aliases);
			break;
		case 0x03:
			account_policy_get(AP_TIME_TO_LOGOUT, &account_policy_temp);
			u_logout = account_policy_temp;

			unix_to_nt_time_abs(&nt_logout, u_logout);
			
			init_unk_info3(&ctr->info.inf3, nt_logout);
			break;
		case 0x05:
			init_unk_info5(&ctr->info.inf5, global_myname());
			break;
		case 0x06:
			init_unk_info6(&ctr->info.inf6);
			break;
		case 0x07:
			init_unk_info7(&ctr->info.inf7);
			break;
		case 0x0c:
			account_policy_get(AP_LOCK_ACCOUNT_DURATION, &account_policy_temp);
			u_lock_duration = account_policy_temp * 60;

			account_policy_get(AP_RESET_COUNT_TIME, &account_policy_temp);
			u_reset_time = account_policy_temp * 60;

			account_policy_get(AP_BAD_ATTEMPT_LOCKOUT, &account_policy_temp);
			lockout = account_policy_temp;
	
			unix_to_nt_time_abs(&nt_lock_duration, u_lock_duration);
			unix_to_nt_time_abs(&nt_reset_time, u_reset_time);
	
            		init_unk_info12(&ctr->info.inf12, nt_lock_duration, nt_reset_time, (uint16)lockout);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	init_samr_r_samr_unknown_2e(r_u, q_u->switch_value, ctr, NT_STATUS_OK);

	DEBUG(5,("_samr_unknown_2e: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 _samr_
 ********************************************************************/

NTSTATUS _samr_set_dom_info(pipes_struct *p, SAMR_Q_SET_DOMAIN_INFO *q_u, SAMR_R_SET_DOMAIN_INFO *r_u)
{
	time_t u_expire, u_min_age;
	time_t u_logout;
	time_t u_lock_duration, u_reset_time;

	r_u->status = NT_STATUS_OK;

	DEBUG(5,("_samr_set_dom_info: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, &q_u->domain_pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("_samr_set_dom_info: switch_value: %d\n", q_u->switch_value));

	switch (q_u->switch_value) {
        	case 0x01:
			u_expire=nt_time_to_unix_abs(&q_u->ctr->info.inf1.expire);
			u_min_age=nt_time_to_unix_abs(&q_u->ctr->info.inf1.min_passwordage);
			
			account_policy_set(AP_MIN_PASSWORD_LEN, (uint32)q_u->ctr->info.inf1.min_length_password);
			account_policy_set(AP_PASSWORD_HISTORY, (uint32)q_u->ctr->info.inf1.password_history);
			account_policy_set(AP_USER_MUST_LOGON_TO_CHG_PASS, (uint32)q_u->ctr->info.inf1.flag);
			account_policy_set(AP_MAX_PASSWORD_AGE, (int)u_expire);
			account_policy_set(AP_MIN_PASSWORD_AGE, (int)u_min_age);
            		break;
        	case 0x02:
			break;
		case 0x03:
			u_logout=nt_time_to_unix_abs(&q_u->ctr->info.inf3.logout);
			account_policy_set(AP_TIME_TO_LOGOUT, (int)u_logout);
			break;
		case 0x05:
			break;
		case 0x06:
			break;
		case 0x07:
			break;
		case 0x0c:
			u_lock_duration=nt_time_to_unix_abs(&q_u->ctr->info.inf12.duration)/60;
			u_reset_time=nt_time_to_unix_abs(&q_u->ctr->info.inf12.reset_count)/60;
			
			account_policy_set(AP_LOCK_ACCOUNT_DURATION, (int)u_lock_duration);
			account_policy_set(AP_RESET_COUNT_TIME, (int)u_reset_time);
			account_policy_set(AP_BAD_ATTEMPT_LOCKOUT, (uint32)q_u->ctr->info.inf12.bad_attempt_lockout);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	init_samr_r_set_domain_info(r_u, NT_STATUS_OK);

	DEBUG(5,("_samr_set_dom_info: %d\n", __LINE__));

	return r_u->status;
}
