/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell                   1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton      1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Marc Jacobsen			    1999,
 *  Copyright (C) Jeremy Allison                    2001-2008,
 *  Copyright (C) Jean François Micouleau           1998-2001,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2002,
 *  Copyright (C) Gerald (Jerry) Carter             2003-2004,
 *  Copyright (C) Simo Sorce                        2003.
 *  Copyright (C) Volker Lendecke		    2005.
 *  Copyright (C) Guenther Deschner		    2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is the implementation of the SAMR code.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define SAMR_USR_RIGHTS_WRITE_PW \
		( READ_CONTROL_ACCESS		| \
		  SA_RIGHT_USER_CHANGE_PASSWORD	| \
		  SA_RIGHT_USER_SET_LOC_COM )
#define SAMR_USR_RIGHTS_CANT_WRITE_PW \
		( READ_CONTROL_ACCESS | SA_RIGHT_USER_SET_LOC_COM )

#define DISP_INFO_CACHE_TIMEOUT 10

typedef struct disp_info {
	DOM_SID sid; /* identify which domain this is. */
	bool builtin_domain; /* Quick flag to check if this is the builtin domain. */
	struct pdb_search *users; /* querydispinfo 1 and 4 */
	struct pdb_search *machines; /* querydispinfo 2 */
	struct pdb_search *groups; /* querydispinfo 3 and 5, enumgroups */
	struct pdb_search *aliases; /* enumaliases */

	uint16 enum_acb_mask;
	struct pdb_search *enum_users; /* enumusers with a mask */

	struct timed_event *cache_timeout_event; /* cache idle timeout
						  * handler. */
} DISP_INFO;

/* We keep a static list of these by SID as modern clients close down
   all resources between each request in a complete enumeration. */

struct samr_info {
	/* for use by the \PIPE\samr policy */
	DOM_SID sid;
	bool builtin_domain; /* Quick flag to check if this is the builtin domain. */
	uint32 status; /* some sort of flag.  best to record it.  comes from opnum 0x39 */
	uint32 acc_granted;
	DISP_INFO *disp_info;
	TALLOC_CTX *mem_ctx;
};

static const struct generic_mapping sam_generic_mapping = {
	GENERIC_RIGHTS_SAM_READ,
	GENERIC_RIGHTS_SAM_WRITE,
	GENERIC_RIGHTS_SAM_EXECUTE,
	GENERIC_RIGHTS_SAM_ALL_ACCESS};
static const struct generic_mapping dom_generic_mapping = {
	GENERIC_RIGHTS_DOMAIN_READ,
	GENERIC_RIGHTS_DOMAIN_WRITE,
	GENERIC_RIGHTS_DOMAIN_EXECUTE,
	GENERIC_RIGHTS_DOMAIN_ALL_ACCESS};
static const struct generic_mapping usr_generic_mapping = {
	GENERIC_RIGHTS_USER_READ,
	GENERIC_RIGHTS_USER_WRITE,
	GENERIC_RIGHTS_USER_EXECUTE,
	GENERIC_RIGHTS_USER_ALL_ACCESS};
static const struct generic_mapping usr_nopwchange_generic_mapping = {
	GENERIC_RIGHTS_USER_READ,
	GENERIC_RIGHTS_USER_WRITE,
	GENERIC_RIGHTS_USER_EXECUTE & ~SA_RIGHT_USER_CHANGE_PASSWORD,
	GENERIC_RIGHTS_USER_ALL_ACCESS};
static const struct generic_mapping grp_generic_mapping = {
	GENERIC_RIGHTS_GROUP_READ,
	GENERIC_RIGHTS_GROUP_WRITE,
	GENERIC_RIGHTS_GROUP_EXECUTE,
	GENERIC_RIGHTS_GROUP_ALL_ACCESS};
static const struct generic_mapping ali_generic_mapping = {
	GENERIC_RIGHTS_ALIAS_READ,
	GENERIC_RIGHTS_ALIAS_WRITE,
	GENERIC_RIGHTS_ALIAS_EXECUTE,
	GENERIC_RIGHTS_ALIAS_ALL_ACCESS};

/*******************************************************************
*******************************************************************/

static NTSTATUS make_samr_object_sd( TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size,
                                     const struct generic_mapping *map,
				     DOM_SID *sid, uint32 sid_access )
{
	DOM_SID domadmin_sid;
	SEC_ACE ace[5];		/* at most 5 entries */
	SEC_ACCESS mask;
	size_t i = 0;

	SEC_ACL *psa = NULL;

	/* basic access for Everyone */

	init_sec_access(&mask, map->generic_execute | map->generic_read );
	init_sec_ace(&ace[i++], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/* add Full Access 'BUILTIN\Administrators' and 'BUILTIN\Account Operators */

	init_sec_access(&mask, map->generic_all);

	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	init_sec_ace(&ace[i++], &global_sid_Builtin_Account_Operators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/* Add Full Access for Domain Admins if we are a DC */

	if ( IS_DC ) {
		sid_copy( &domadmin_sid, get_global_sam_sid() );
		sid_append_rid( &domadmin_sid, DOMAIN_GROUP_RID_ADMINS );
		init_sec_ace(&ace[i++], &domadmin_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	}

	/* if we have a sid, give it some special access */

	if ( sid ) {
		init_sec_access( &mask, sid_access );
		init_sec_ace(&ace[i++], sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	}

	/* create the security descriptor */

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) == NULL)
		return NT_STATUS_NO_MEMORY;

	if ((*psd = make_sec_desc(ctx, SECURITY_DESCRIPTOR_REVISION_1,
				  SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL,
				  psa, sd_size)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return NT_STATUS_OK;
}

/*******************************************************************
 Checks if access to an object should be granted, and returns that
 level of access for further checks.
********************************************************************/

static NTSTATUS access_check_samr_object( SEC_DESC *psd, NT_USER_TOKEN *token,
                                          SE_PRIV *rights, uint32 rights_mask,
                                          uint32 des_access, uint32 *acc_granted,
					  const char *debug )
{
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;
	uint32 saved_mask = 0;

	/* check privileges; certain SAM access bits should be overridden
	   by privileges (mostly having to do with creating/modifying/deleting
	   users and groups) */

	if ( rights && user_has_any_privilege( token, rights ) ) {

		saved_mask = (des_access & rights_mask);
		des_access &= ~saved_mask;

		DEBUG(4,("access_check_samr_object: user rights access mask [0x%x]\n",
			rights_mask));
	}


	/* check the security descriptor first */

	if ( se_access_check(psd, token, des_access, acc_granted, &status) )
		goto done;

	/* give root a free pass */

	if ( geteuid() == sec_initial_uid() ) {

		DEBUG(4,("%s: ACCESS should be DENIED  (requested: %#010x)\n", debug, des_access));
		DEBUGADD(4,("but overritten by euid == sec_initial_uid()\n"));

		*acc_granted = des_access;

		status = NT_STATUS_OK;
		goto done;
	}


done:
	/* add in any bits saved during the privilege check (only
	   matters is status is ok) */

	*acc_granted |= rights_mask;

	DEBUG(4,("%s: access %s (requested: 0x%08x, granted: 0x%08x)\n",
		debug, NT_STATUS_IS_OK(status) ? "GRANTED" : "DENIED",
		des_access, *acc_granted));

	return status;
}

/*******************************************************************
 Checks if access to a function can be granted
********************************************************************/

static NTSTATUS access_check_samr_function(uint32 acc_granted, uint32 acc_required, const char *debug)
{
	DEBUG(5,("%s: access check ((granted: %#010x;  required: %#010x)\n",
		debug, acc_granted, acc_required));

	/* check the security descriptor first */

	if ( (acc_granted&acc_required) == acc_required )
		return NT_STATUS_OK;

	/* give root a free pass */

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

/*******************************************************************
 Map any MAXIMUM_ALLOWED_ACCESS request to a valid access set.
********************************************************************/

static void map_max_allowed_access(const NT_USER_TOKEN *token,
					uint32_t *pacc_requested)
{
	if (!((*pacc_requested) & MAXIMUM_ALLOWED_ACCESS)) {
		return;
	}
	*pacc_requested &= ~MAXIMUM_ALLOWED_ACCESS;

	/* At least try for generic read. */
	*pacc_requested = GENERIC_READ_ACCESS;

	/* root gets anything. */
	if (geteuid() == sec_initial_uid()) {
		*pacc_requested |= GENERIC_ALL_ACCESS;
		return;
	}

	/* Full Access for 'BUILTIN\Administrators' and 'BUILTIN\Account Operators */

	if (is_sid_in_token(token, &global_sid_Builtin_Administrators) ||
			is_sid_in_token(token, &global_sid_Builtin_Account_Operators)) {
		*pacc_requested |= GENERIC_ALL_ACCESS;
		return;
	}

	/* Full access for DOMAIN\Domain Admins. */
	if ( IS_DC ) {
		DOM_SID domadmin_sid;
		sid_copy( &domadmin_sid, get_global_sam_sid() );
		sid_append_rid( &domadmin_sid, DOMAIN_GROUP_RID_ADMINS );
		if (is_sid_in_token(token, &domadmin_sid)) {
			*pacc_requested |= GENERIC_ALL_ACCESS;
			return;
		}
	}
	/* TODO ! Check privileges. */
}

/*******************************************************************
 Fetch or create a dispinfo struct.
********************************************************************/

static DISP_INFO *get_samr_dispinfo_by_sid(DOM_SID *psid)
{
	/*
	 * We do a static cache for DISP_INFO's here. Explanation can be found
	 * in Jeremy's checkin message to r11793:
	 *
	 * Fix the SAMR cache so it works across completely insane
	 * client behaviour (ie.:
	 * open pipe/open SAMR handle/enumerate 0 - 1024
	 * close SAMR handle, close pipe.
	 * open pipe/open SAMR handle/enumerate 1024 - 2048...
	 * close SAMR handle, close pipe.
	 * And on ad-nausium. Amazing.... probably object-oriented
	 * client side programming in action yet again.
	 * This change should *massively* improve performance when
	 * enumerating users from an LDAP database.
	 * Jeremy.
	 *
	 * "Our" and the builtin domain are the only ones where we ever
	 * enumerate stuff, so just cache 2 entries.
	 */

	static struct disp_info builtin_dispinfo;
	static struct disp_info domain_dispinfo;

	/* There are two cases to consider here:
	   1) The SID is a domain SID and we look for an equality match, or
	   2) This is an account SID and so we return the DISP_INFO* for our
	      domain */

	if (psid == NULL) {
		return NULL;
	}

	if (sid_check_is_builtin(psid) || sid_check_is_in_builtin(psid)) {
		/*
		 * Necessary only once, but it does not really hurt.
		 */
		sid_copy(&builtin_dispinfo.sid, &global_sid_Builtin);

		return &builtin_dispinfo;
	}

	if (sid_check_is_domain(psid) || sid_check_is_in_our_domain(psid)) {
		/*
		 * Necessary only once, but it does not really hurt.
		 */
		sid_copy(&domain_dispinfo.sid, get_global_sam_sid());

		return &domain_dispinfo;
	}

	return NULL;
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
		sid_to_fstring(sid_str, psid);
	} else {
		fstrcpy(sid_str,"(NULL)");
	}

	mem_ctx = talloc_init("samr_info for domain sid %s", sid_str);

	if ((info = TALLOC_ZERO_P(mem_ctx, struct samr_info)) == NULL)
		return NULL;

	DEBUG(10,("get_samr_info_by_sid: created new info for sid %s\n", sid_str));
	if (psid) {
		sid_copy( &info->sid, psid);
		info->builtin_domain = sid_check_is_builtin(psid);
	} else {
		DEBUG(10,("get_samr_info_by_sid: created new info for NULL sid.\n"));
		info->builtin_domain = False;
	}
	info->mem_ctx = mem_ctx;

	info->disp_info = get_samr_dispinfo_by_sid(psid);

	return info;
}

/*******************************************************************
 Function to free the per SID data.
 ********************************************************************/

static void free_samr_cache(DISP_INFO *disp_info)
{
	DEBUG(10, ("free_samr_cache: deleting cache for SID %s\n",
		   sid_string_dbg(&disp_info->sid)));

	/* We need to become root here because the paged search might have to
	 * tell the LDAP server we're not interested in the rest anymore. */

	become_root();

	if (disp_info->users) {
		DEBUG(10,("free_samr_cache: deleting users cache\n"));
		pdb_search_destroy(disp_info->users);
		disp_info->users = NULL;
	}
	if (disp_info->machines) {
		DEBUG(10,("free_samr_cache: deleting machines cache\n"));
		pdb_search_destroy(disp_info->machines);
		disp_info->machines = NULL;
	}
	if (disp_info->groups) {
		DEBUG(10,("free_samr_cache: deleting groups cache\n"));
		pdb_search_destroy(disp_info->groups);
		disp_info->groups = NULL;
	}
	if (disp_info->aliases) {
		DEBUG(10,("free_samr_cache: deleting aliases cache\n"));
		pdb_search_destroy(disp_info->aliases);
		disp_info->aliases = NULL;
	}
	if (disp_info->enum_users) {
		DEBUG(10,("free_samr_cache: deleting enum_users cache\n"));
		pdb_search_destroy(disp_info->enum_users);
		disp_info->enum_users = NULL;
	}
	disp_info->enum_acb_mask = 0;

	unbecome_root();
}

/*******************************************************************
 Function to free the per handle data.
 ********************************************************************/

static void free_samr_info(void *ptr)
{
	struct samr_info *info=(struct samr_info *) ptr;

	/* Only free the dispinfo cache if no one bothered to set up
	   a timeout. */

	if (info->disp_info && info->disp_info->cache_timeout_event == NULL) {
		free_samr_cache(info->disp_info);
	}

	talloc_destroy(info->mem_ctx);
}

/*******************************************************************
 Idle event handler. Throw away the disp info cache.
 ********************************************************************/

static void disp_info_cache_idle_timeout_handler(struct event_context *ev_ctx,
						 struct timed_event *te,
						 const struct timeval *now,
						 void *private_data)
{
	DISP_INFO *disp_info = (DISP_INFO *)private_data;

	TALLOC_FREE(disp_info->cache_timeout_event);

	DEBUG(10, ("disp_info_cache_idle_timeout_handler: caching timed "
		   "out\n"));
	free_samr_cache(disp_info);
}

/*******************************************************************
 Setup cache removal idle event handler.
 ********************************************************************/

static void set_disp_info_cache_timeout(DISP_INFO *disp_info, time_t secs_fromnow)
{
	/* Remove any pending timeout and update. */

	TALLOC_FREE(disp_info->cache_timeout_event);

	DEBUG(10,("set_disp_info_cache_timeout: caching enumeration for "
		  "SID %s for %u seconds\n", sid_string_dbg(&disp_info->sid),
		  (unsigned int)secs_fromnow ));

	disp_info->cache_timeout_event = event_add_timed(
		smbd_event_context(), NULL,
		timeval_current_ofs(secs_fromnow, 0),
		"disp_info_cache_idle_timeout_handler",
		disp_info_cache_idle_timeout_handler, (void *)disp_info);
}

/*******************************************************************
 Force flush any cache. We do this on any samr_set_xxx call.
 We must also remove the timeout handler.
 ********************************************************************/

static void force_flush_samr_cache(DISP_INFO *disp_info)
{
	if ((disp_info == NULL) || (disp_info->cache_timeout_event == NULL)) {
		return;
	}

	DEBUG(10,("force_flush_samr_cache: clearing idle event\n"));
	TALLOC_FREE(disp_info->cache_timeout_event);
	free_samr_cache(disp_info);
}

/*******************************************************************
 Ensure password info is never given out. Paranioa... JRA.
 ********************************************************************/

static void samr_clear_sam_passwd(struct samu *sam_pass)
{

	if (!sam_pass)
		return;

	/* These now zero out the old password */

	pdb_set_lanman_passwd(sam_pass, NULL, PDB_DEFAULT);
	pdb_set_nt_passwd(sam_pass, NULL, PDB_DEFAULT);
}

static uint32 count_sam_users(struct disp_info *info, uint32 acct_flags)
{
	struct samr_displayentry *entry;

	if (info->builtin_domain) {
		/* No users in builtin. */
		return 0;
	}

	if (info->users == NULL) {
		info->users = pdb_search_users(acct_flags);
		if (info->users == NULL) {
			return 0;
		}
	}
	/* Fetch the last possible entry, thus trigger an enumeration */
	pdb_search_entries(info->users, 0xffffffff, 1, &entry);

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info, DISP_INFO_CACHE_TIMEOUT);

	return info->users->num_entries;
}

static uint32 count_sam_groups(struct disp_info *info)
{
	struct samr_displayentry *entry;

	if (info->builtin_domain) {
		/* No groups in builtin. */
		return 0;
	}

	if (info->groups == NULL) {
		info->groups = pdb_search_groups();
		if (info->groups == NULL) {
			return 0;
		}
	}
	/* Fetch the last possible entry, thus trigger an enumeration */
	pdb_search_entries(info->groups, 0xffffffff, 1, &entry);

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info, DISP_INFO_CACHE_TIMEOUT);

	return info->groups->num_entries;
}

static uint32 count_sam_aliases(struct disp_info *info)
{
	struct samr_displayentry *entry;

	if (info->aliases == NULL) {
		info->aliases = pdb_search_aliases(&info->sid);
		if (info->aliases == NULL) {
			return 0;
		}
	}
	/* Fetch the last possible entry, thus trigger an enumeration */
	pdb_search_entries(info->aliases, 0xffffffff, 1, &entry);

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info, DISP_INFO_CACHE_TIMEOUT);

	return info->aliases->num_entries;
}

/*******************************************************************
 _samr_Close
 ********************************************************************/

NTSTATUS _samr_Close(pipes_struct *p, struct samr_Close *r)
{
	if (!close_policy_hnd(p, r->in.handle)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_OpenDomain
 ********************************************************************/

NTSTATUS _samr_OpenDomain(pipes_struct *p,
			  struct samr_OpenDomain *r)
{
	struct    samr_info *info;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	NTSTATUS  status;
	size_t    sd_size;
	SE_PRIV se_rights;

	/* find the connection policy handle. */

	if ( !find_policy_by_hnd(p, r->in.connect_handle, (void**)(void *)&info) )
		return NT_STATUS_INVALID_HANDLE;

	/*check if access can be granted as requested by client. */
	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd( p->mem_ctx, &psd, &sd_size, &dom_generic_mapping, NULL, 0 );
	se_map_generic( &des_access, &dom_generic_mapping );

	se_priv_copy( &se_rights, &se_machine_account );
	se_priv_add( &se_rights, &se_add_users );

	status = access_check_samr_object( psd, p->pipe_user.nt_user_token,
		&se_rights, GENERIC_RIGHTS_DOMAIN_WRITE, des_access,
		&acc_granted, "_samr_OpenDomain" );

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	if (!sid_check_is_domain(r->in.sid) &&
	    !sid_check_is_builtin(r->in.sid)) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	/* associate the domain SID with the (unique) handle. */
	if ((info = get_samr_info_by_sid(r->in.sid))==NULL)
		return NT_STATUS_NO_MEMORY;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.domain_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_OpenDomain: %d\n", __LINE__));

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_GetUserPwInfo
 ********************************************************************/

NTSTATUS _samr_GetUserPwInfo(pipes_struct *p,
			     struct samr_GetUserPwInfo *r)
{
	struct samr_info *info = NULL;
	enum lsa_SidType sid_type;
	uint32_t min_password_length = 0;
	uint32_t password_properties = 0;
	bool ret = false;
	NTSTATUS status;

	DEBUG(5,("_samr_GetUserPwInfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.user_handle, (void **)(void *)&info)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	status = access_check_samr_function(info->acc_granted,
					    SAMR_USER_ACCESS_GET_ATTRIBUTES,
					    "_samr_GetUserPwInfo" );
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!sid_check_is_in_our_domain(&info->sid)) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	become_root();
	ret = lookup_sid(p->mem_ctx, &info->sid, NULL, NULL, &sid_type);
	unbecome_root();
	if (ret == false) {
		return NT_STATUS_NO_SUCH_USER;
	}

	switch (sid_type) {
		case SID_NAME_USER:
			become_root();
			pdb_get_account_policy(AP_MIN_PASSWORD_LEN,
					       &min_password_length);
			pdb_get_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS,
					       &password_properties);
			unbecome_root();

			if (lp_check_password_script() && *lp_check_password_script()) {
				password_properties |= DOMAIN_PASSWORD_COMPLEX;
			}

			break;
		default:
			break;
	}

	r->out.info->min_password_length = min_password_length;
	r->out.info->password_properties = password_properties;

	DEBUG(5,("_samr_GetUserPwInfo: %d\n", __LINE__));

	return NT_STATUS_OK;
}

/*******************************************************************
********************************************************************/

static bool get_lsa_policy_samr_sid( pipes_struct *p, POLICY_HND *pol,
					DOM_SID *sid, uint32 *acc_granted,
					DISP_INFO **ppdisp_info)
{
	struct samr_info *info = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, pol, (void **)(void *)&info))
		return False;

	if (!info)
		return False;

	*sid = info->sid;
	*acc_granted = info->acc_granted;
	if (ppdisp_info) {
		*ppdisp_info = info->disp_info;
	}

	return True;
}

/*******************************************************************
 _samr_SetSecurity
 ********************************************************************/

NTSTATUS _samr_SetSecurity(pipes_struct *p,
			   struct samr_SetSecurity *r)
{
	DOM_SID pol_sid;
	uint32 acc_granted, i;
	SEC_ACL *dacl;
	bool ret;
	struct samu *sampass=NULL;
	NTSTATUS status;

	if (!get_lsa_policy_samr_sid(p, r->in.handle, &pol_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	if (!(sampass = samu_new( p->mem_ctx))) {
		DEBUG(0,("No memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* get the user record */
	become_root();
	ret = pdb_getsampwsid(sampass, &pol_sid);
	unbecome_root();

	if (!ret) {
		DEBUG(4, ("User %s not found\n", sid_string_dbg(&pol_sid)));
		TALLOC_FREE(sampass);
		return NT_STATUS_INVALID_HANDLE;
	}

	dacl = r->in.sdbuf->sd->dacl;
	for (i=0; i < dacl->num_aces; i++) {
		if (sid_equal(&pol_sid, &dacl->aces[i].trustee)) {
			ret = pdb_set_pass_can_change(sampass,
				(dacl->aces[i].access_mask &
				 SA_RIGHT_USER_CHANGE_PASSWORD) ?
						      True: False);
			break;
		}
	}

	if (!ret) {
		TALLOC_FREE(sampass);
		return NT_STATUS_ACCESS_DENIED;
	}

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_USER_SET_ATTRIBUTES,
					    "_samr_SetSecurity");
	if (NT_STATUS_IS_OK(status)) {
		become_root();
		status = pdb_update_sam_account(sampass);
		unbecome_root();
	}

	TALLOC_FREE(sampass);

	return status;
}

/*******************************************************************
  build correct perms based on policies and password times for _samr_query_sec_obj
*******************************************************************/
static bool check_change_pw_access(TALLOC_CTX *mem_ctx, DOM_SID *user_sid)
{
	struct samu *sampass=NULL;
	bool ret;

	if ( !(sampass = samu_new( mem_ctx )) ) {
		DEBUG(0,("No memory!\n"));
		return False;
	}

	become_root();
	ret = pdb_getsampwsid(sampass, user_sid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(sampass);
		return False;
	}

	DEBUG(3,("User:[%s]\n",  pdb_get_username(sampass) ));

	if (pdb_get_pass_can_change(sampass)) {
		TALLOC_FREE(sampass);
		return True;
	}
	TALLOC_FREE(sampass);
	return False;
}


/*******************************************************************
 _samr_QuerySecurity
 ********************************************************************/

NTSTATUS _samr_QuerySecurity(pipes_struct *p,
			     struct samr_QuerySecurity *r)
{
	NTSTATUS status;
	DOM_SID pol_sid;
	SEC_DESC * psd = NULL;
	uint32 acc_granted;
	size_t sd_size;

	/* Get the SID. */
	if (!get_lsa_policy_samr_sid(p, r->in.handle, &pol_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(10,("_samr_QuerySecurity: querying security on SID: %s\n",
		  sid_string_dbg(&pol_sid)));

	status = access_check_samr_function(acc_granted,
					    STD_RIGHT_READ_CONTROL_ACCESS,
					    "_samr_QuerySecurity");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Check what typ of SID is beeing queried (e.g Domain SID, User SID, Group SID) */

	/* To query the security of the SAM it self an invalid SID with S-0-0 is passed to this function */
	if (pol_sid.sid_rev_num == 0) {
		DEBUG(5,("_samr_QuerySecurity: querying security on SAM\n"));
		status = make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &sam_generic_mapping, NULL, 0);
	} else if (sid_equal(&pol_sid,get_global_sam_sid())) {
		/* check if it is our domain SID */
		DEBUG(5,("_samr_QuerySecurity: querying security on Domain "
			 "with SID: %s\n", sid_string_dbg(&pol_sid)));
		status = make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &dom_generic_mapping, NULL, 0);
	} else if (sid_equal(&pol_sid,&global_sid_Builtin)) {
		/* check if it is the Builtin  Domain */
		/* TODO: Builtin probably needs a different SD with restricted write access*/
		DEBUG(5,("_samr_QuerySecurity: querying security on Builtin "
			 "Domain with SID: %s\n", sid_string_dbg(&pol_sid)));
		status = make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &dom_generic_mapping, NULL, 0);
	} else if (sid_check_is_in_our_domain(&pol_sid) ||
	    	 sid_check_is_in_builtin(&pol_sid)) {
		/* TODO: different SDs have to be generated for aliases groups and users.
		         Currently all three get a default user SD  */
		DEBUG(10,("_samr_QuerySecurity: querying security on Object "
			  "with SID: %s\n", sid_string_dbg(&pol_sid)));
		if (check_change_pw_access(p->mem_ctx, &pol_sid)) {
			status = make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &usr_generic_mapping,
							  &pol_sid, SAMR_USR_RIGHTS_WRITE_PW);
		} else {
			status = make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &usr_nopwchange_generic_mapping,
							  &pol_sid, SAMR_USR_RIGHTS_CANT_WRITE_PW);
		}
	} else {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if ((*r->out.sdbuf = make_sec_desc_buf(p->mem_ctx, sd_size, psd)) == NULL)
		return NT_STATUS_NO_MEMORY;

	return status;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure from a user list.
********************************************************************/

static NTSTATUS make_user_sam_entry_list(TALLOC_CTX *ctx,
					 struct samr_SamEntry **sam_pp,
					 uint32_t num_entries,
					 uint32_t start_idx,
					 struct samr_displayentry *entries)
{
	uint32_t i;
	struct samr_SamEntry *sam;

	*sam_pp = NULL;

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	sam = TALLOC_ZERO_ARRAY(ctx, struct samr_SamEntry, num_entries);
	if (sam == NULL) {
		DEBUG(0, ("make_user_sam_entry_list: TALLOC_ZERO failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries; i++) {
#if 0
		/*
		 * usrmgr expects a non-NULL terminated string with
		 * trust relationships
		 */
		if (entries[i].acct_flags & ACB_DOMTRUST) {
			init_unistr2(&uni_temp_name, entries[i].account_name,
				     UNI_FLAGS_NONE);
		} else {
			init_unistr2(&uni_temp_name, entries[i].account_name,
				     UNI_STR_TERMINATE);
		}
#endif
		init_lsa_String(&sam[i].name, entries[i].account_name);
		sam[i].idx = entries[i].rid;
	}

	*sam_pp = sam;

	return NT_STATUS_OK;
}

#define MAX_SAM_ENTRIES MAX_SAM_ENTRIES_W2K

/*******************************************************************
 _samr_EnumDomainUsers
 ********************************************************************/

NTSTATUS _samr_EnumDomainUsers(pipes_struct *p,
			       struct samr_EnumDomainUsers *r)
{
	NTSTATUS status;
	struct samr_info *info = NULL;
	int num_account;
	uint32 enum_context = *r->in.resume_handle;
	enum remote_arch_types ra_type = get_remote_arch();
	int max_sam_entries = (ra_type == RA_WIN95) ? MAX_SAM_ENTRIES_W95 : MAX_SAM_ENTRIES_W2K;
	uint32 max_entries = max_sam_entries;
	struct samr_displayentry *entries = NULL;
	struct samr_SamArray *samr_array = NULL;
	struct samr_SamEntry *samr_entries = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
					    "_samr_EnumDomainUsers");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(5,("_samr_EnumDomainUsers: %d\n", __LINE__));

	if (info->builtin_domain) {
		/* No users in builtin. */
		*r->out.resume_handle = *r->in.resume_handle;
		DEBUG(5,("_samr_EnumDomainUsers: No users in BUILTIN\n"));
		return status;
	}

	samr_array = TALLOC_ZERO_P(p->mem_ctx, struct samr_SamArray);
	if (!samr_array) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();

	/* AS ROOT !!!! */

	if ((info->disp_info->enum_users != NULL) &&
	    (info->disp_info->enum_acb_mask != r->in.acct_flags)) {
		pdb_search_destroy(info->disp_info->enum_users);
		info->disp_info->enum_users = NULL;
	}

	if (info->disp_info->enum_users == NULL) {
		info->disp_info->enum_users = pdb_search_users(r->in.acct_flags);
		info->disp_info->enum_acb_mask = r->in.acct_flags;
	}

	if (info->disp_info->enum_users == NULL) {
		/* END AS ROOT !!!! */
		unbecome_root();
		return NT_STATUS_ACCESS_DENIED;
	}

	num_account = pdb_search_entries(info->disp_info->enum_users,
					 enum_context, max_entries,
					 &entries);

	/* END AS ROOT !!!! */

	unbecome_root();

	if (num_account == 0) {
		DEBUG(5, ("_samr_EnumDomainUsers: enumeration handle over "
			  "total entries\n"));
		*r->out.resume_handle = *r->in.resume_handle;
		return NT_STATUS_OK;
	}

	status = make_user_sam_entry_list(p->mem_ctx, &samr_entries,
					  num_account, enum_context,
					  entries);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (max_entries <= num_account) {
		status = STATUS_MORE_ENTRIES;
	} else {
		status = NT_STATUS_OK;
	}

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info->disp_info, DISP_INFO_CACHE_TIMEOUT);

	DEBUG(5, ("_samr_EnumDomainUsers: %d\n", __LINE__));

	samr_array->count = num_account;
	samr_array->entries = samr_entries;

	*r->out.resume_handle = *r->in.resume_handle + num_account;
	*r->out.sam = samr_array;
	*r->out.num_entries = num_account;

	DEBUG(5,("_samr_EnumDomainUsers: %d\n", __LINE__));

	return status;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure from a group list.
********************************************************************/

static void make_group_sam_entry_list(TALLOC_CTX *ctx,
				      struct samr_SamEntry **sam_pp,
				      uint32_t num_sam_entries,
				      struct samr_displayentry *entries)
{
	struct samr_SamEntry *sam;
	uint32_t i;

	*sam_pp = NULL;

	if (num_sam_entries == 0) {
		return;
	}

	sam = TALLOC_ZERO_ARRAY(ctx, struct samr_SamEntry, num_sam_entries);
	if (sam == NULL) {
		return;
	}

	for (i = 0; i < num_sam_entries; i++) {
		/*
		 * JRA. I think this should include the null. TNG does not.
		 */
		init_lsa_String(&sam[i].name, entries[i].account_name);
		sam[i].idx = entries[i].rid;
	}

	*sam_pp = sam;
}

/*******************************************************************
 _samr_EnumDomainGroups
 ********************************************************************/

NTSTATUS _samr_EnumDomainGroups(pipes_struct *p,
				struct samr_EnumDomainGroups *r)
{
	NTSTATUS status;
	struct samr_info *info = NULL;
	struct samr_displayentry *groups;
	uint32 num_groups;
	struct samr_SamArray *samr_array = NULL;
	struct samr_SamEntry *samr_entries = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
					    "_samr_EnumDomainGroups");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(5,("_samr_EnumDomainGroups: %d\n", __LINE__));

	if (info->builtin_domain) {
		/* No groups in builtin. */
		*r->out.resume_handle = *r->in.resume_handle;
		DEBUG(5,("_samr_EnumDomainGroups: No groups in BUILTIN\n"));
		return status;
	}

	samr_array = TALLOC_ZERO_P(p->mem_ctx, struct samr_SamArray);
	if (!samr_array) {
		return NT_STATUS_NO_MEMORY;
	}

	/* the domain group array is being allocated in the function below */

	become_root();

	if (info->disp_info->groups == NULL) {
		info->disp_info->groups = pdb_search_groups();

		if (info->disp_info->groups == NULL) {
			unbecome_root();
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	num_groups = pdb_search_entries(info->disp_info->groups,
					*r->in.resume_handle,
					MAX_SAM_ENTRIES, &groups);
	unbecome_root();

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info->disp_info, DISP_INFO_CACHE_TIMEOUT);

	make_group_sam_entry_list(p->mem_ctx, &samr_entries,
				  num_groups, groups);

	samr_array->count = num_groups;
	samr_array->entries = samr_entries;

	*r->out.sam = samr_array;
	*r->out.num_entries = num_groups;
	*r->out.resume_handle = num_groups + *r->in.resume_handle;

	DEBUG(5,("_samr_EnumDomainGroups: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 _samr_EnumDomainAliases
 ********************************************************************/

NTSTATUS _samr_EnumDomainAliases(pipes_struct *p,
				 struct samr_EnumDomainAliases *r)
{
	NTSTATUS status;
	struct samr_info *info;
	struct samr_displayentry *aliases;
	uint32 num_aliases = 0;
	struct samr_SamArray *samr_array = NULL;
	struct samr_SamEntry *samr_entries = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("_samr_EnumDomainAliases: sid %s\n",
		 sid_string_dbg(&info->sid)));

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
					    "_samr_EnumDomainAliases");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	samr_array = TALLOC_ZERO_P(p->mem_ctx, struct samr_SamArray);
	if (!samr_array) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();

	if (info->disp_info->aliases == NULL) {
		info->disp_info->aliases = pdb_search_aliases(&info->sid);
		if (info->disp_info->aliases == NULL) {
			unbecome_root();
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	num_aliases = pdb_search_entries(info->disp_info->aliases,
					 *r->in.resume_handle,
					 MAX_SAM_ENTRIES, &aliases);
	unbecome_root();

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info->disp_info, DISP_INFO_CACHE_TIMEOUT);

	make_group_sam_entry_list(p->mem_ctx, &samr_entries,
				  num_aliases, aliases);

	DEBUG(5,("_samr_EnumDomainAliases: %d\n", __LINE__));

	samr_array->count = num_aliases;
	samr_array->entries = samr_entries;

	*r->out.sam = samr_array;
	*r->out.num_entries = num_aliases;
	*r->out.resume_handle = num_aliases + *r->in.resume_handle;

	return status;
}

/*******************************************************************
 inits a samr_DispInfoGeneral structure.
********************************************************************/

static NTSTATUS init_samr_dispinfo_1(TALLOC_CTX *ctx,
				     struct samr_DispInfoGeneral *r,
				     uint32_t num_entries,
				     uint32_t start_idx,
				     struct samr_displayentry *entries)
{
	uint32 i;

	DEBUG(10, ("init_samr_dispinfo_1: num_entries: %d\n", num_entries));

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	r->count = num_entries;

	r->entries = TALLOC_ZERO_ARRAY(ctx, struct samr_DispEntryGeneral, num_entries);
	if (!r->entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries ; i++) {

		init_lsa_String(&r->entries[i].account_name,
				entries[i].account_name);

		init_lsa_String(&r->entries[i].description,
				entries[i].description);

		init_lsa_String(&r->entries[i].full_name,
				entries[i].fullname);

		r->entries[i].rid = entries[i].rid;
		r->entries[i].acct_flags = entries[i].acct_flags;
		r->entries[i].idx = start_idx+i+1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 inits a samr_DispInfoFull structure.
********************************************************************/

static NTSTATUS init_samr_dispinfo_2(TALLOC_CTX *ctx,
				     struct samr_DispInfoFull *r,
				     uint32_t num_entries,
				     uint32_t start_idx,
				     struct samr_displayentry *entries)
{
	uint32_t i;

	DEBUG(10, ("init_samr_dispinfo_2: num_entries: %d\n", num_entries));

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	r->count = num_entries;

	r->entries = TALLOC_ZERO_ARRAY(ctx, struct samr_DispEntryFull, num_entries);
	if (!r->entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries ; i++) {

		init_lsa_String(&r->entries[i].account_name,
				entries[i].account_name);

		init_lsa_String(&r->entries[i].description,
				entries[i].description);

		r->entries[i].rid = entries[i].rid;
		r->entries[i].acct_flags = entries[i].acct_flags;
		r->entries[i].idx = start_idx+i+1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 inits a samr_DispInfoFullGroups structure.
********************************************************************/

static NTSTATUS init_samr_dispinfo_3(TALLOC_CTX *ctx,
				     struct samr_DispInfoFullGroups *r,
				     uint32_t num_entries,
				     uint32_t start_idx,
				     struct samr_displayentry *entries)
{
	uint32_t i;

	DEBUG(5, ("init_samr_dispinfo_3: num_entries: %d\n", num_entries));

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	r->count = num_entries;

	r->entries = TALLOC_ZERO_ARRAY(ctx, struct samr_DispEntryFullGroup, num_entries);
	if (!r->entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries ; i++) {

		init_lsa_String(&r->entries[i].account_name,
				entries[i].account_name);

		init_lsa_String(&r->entries[i].description,
				entries[i].description);

		r->entries[i].rid = entries[i].rid;
		r->entries[i].acct_flags = entries[i].acct_flags;
		r->entries[i].idx = start_idx+i+1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 inits a samr_DispInfoAscii structure.
********************************************************************/

static NTSTATUS init_samr_dispinfo_4(TALLOC_CTX *ctx,
				     struct samr_DispInfoAscii *r,
				     uint32_t num_entries,
				     uint32_t start_idx,
				     struct samr_displayentry *entries)
{
	uint32_t i;

	DEBUG(5, ("init_samr_dispinfo_4: num_entries: %d\n", num_entries));

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	r->count = num_entries;

	r->entries = TALLOC_ZERO_ARRAY(ctx, struct samr_DispEntryAscii, num_entries);
	if (!r->entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries ; i++) {

		init_lsa_AsciiStringLarge(&r->entries[i].account_name,
					  entries[i].account_name);

		r->entries[i].idx = start_idx+i+1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 inits a samr_DispInfoAscii structure.
********************************************************************/

static NTSTATUS init_samr_dispinfo_5(TALLOC_CTX *ctx,
				     struct samr_DispInfoAscii *r,
				     uint32_t num_entries,
				     uint32_t start_idx,
				     struct samr_displayentry *entries)
{
	uint32_t i;

	DEBUG(5, ("init_samr_dispinfo_5: num_entries: %d\n", num_entries));

	if (num_entries == 0) {
		return NT_STATUS_OK;
	}

	r->count = num_entries;

	r->entries = TALLOC_ZERO_ARRAY(ctx, struct samr_DispEntryAscii, num_entries);
	if (!r->entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_entries ; i++) {

		init_lsa_AsciiStringLarge(&r->entries[i].account_name,
					  entries[i].account_name);

		r->entries[i].idx = start_idx+i+1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_QueryDisplayInfo
 ********************************************************************/

NTSTATUS _samr_QueryDisplayInfo(pipes_struct *p,
				struct samr_QueryDisplayInfo *r)
{
	NTSTATUS status;
	struct samr_info *info = NULL;
	uint32 struct_size=0x20; /* W2K always reply that, client doesn't care */

	uint32 max_entries = r->in.max_entries;
	uint32 enum_context = r->in.start_idx;
	uint32 max_size = r->in.buf_size;

	union samr_DispInfo *disp_info = r->out.info;

	uint32 temp_size=0, total_data_size=0;
	NTSTATUS disp_ret = NT_STATUS_UNSUCCESSFUL;
	uint32 num_account = 0;
	enum remote_arch_types ra_type = get_remote_arch();
	int max_sam_entries = (ra_type == RA_WIN95) ? MAX_SAM_ENTRIES_W95 : MAX_SAM_ENTRIES_W2K;
	struct samr_displayentry *entries = NULL;

	DEBUG(5,("_samr_QueryDisplayInfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
					    "_samr_QueryDisplayInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

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

	if ((r->in.level < 1) || (r->in.level > 5)) {
		DEBUG(0,("_samr_QueryDisplayInfo: Unknown info level (%u)\n",
			 (unsigned int)r->in.level ));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* first limit the number of entries we will return */
	if(max_entries > max_sam_entries) {
		DEBUG(5, ("_samr_QueryDisplayInfo: client requested %d "
			  "entries, limiting to %d\n", max_entries,
			  max_sam_entries));
		max_entries = max_sam_entries;
	}

	/* calculate the size and limit on the number of entries we will
	 * return */

	temp_size=max_entries*struct_size;

	if (temp_size>max_size) {
		max_entries=MIN((max_size/struct_size),max_entries);;
		DEBUG(5, ("_samr_QueryDisplayInfo: buffer size limits to "
			  "only %d entries\n", max_entries));
	}

	become_root();

	/* THe following done as ROOT. Don't return without unbecome_root(). */

	switch (r->in.level) {
	case 0x1:
	case 0x4:
		if (info->disp_info->users == NULL) {
			info->disp_info->users = pdb_search_users(ACB_NORMAL);
			if (info->disp_info->users == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_QueryDisplayInfo: starting user enumeration at index %u\n",
				(unsigned  int)enum_context ));
		} else {
			DEBUG(10,("_samr_QueryDisplayInfo: using cached user enumeration at index %u\n",
				(unsigned  int)enum_context ));
		}

		num_account = pdb_search_entries(info->disp_info->users,
						 enum_context, max_entries,
						 &entries);
		break;
	case 0x2:
		if (info->disp_info->machines == NULL) {
			info->disp_info->machines =
				pdb_search_users(ACB_WSTRUST|ACB_SVRTRUST);
			if (info->disp_info->machines == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_QueryDisplayInfo: starting machine enumeration at index %u\n",
				(unsigned  int)enum_context ));
		} else {
			DEBUG(10,("_samr_QueryDisplayInfo: using cached machine enumeration at index %u\n",
				(unsigned  int)enum_context ));
		}

		num_account = pdb_search_entries(info->disp_info->machines,
						 enum_context, max_entries,
						 &entries);
		break;
	case 0x3:
	case 0x5:
		if (info->disp_info->groups == NULL) {
			info->disp_info->groups = pdb_search_groups();
			if (info->disp_info->groups == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_QueryDisplayInfo: starting group enumeration at index %u\n",
				(unsigned  int)enum_context ));
		} else {
			DEBUG(10,("_samr_QueryDisplayInfo: using cached group enumeration at index %u\n",
				(unsigned  int)enum_context ));
		}

		num_account = pdb_search_entries(info->disp_info->groups,
						 enum_context, max_entries,
						 &entries);
		break;
	default:
		unbecome_root();
		smb_panic("info class changed");
		break;
	}
	unbecome_root();


	/* Now create reply structure */
	switch (r->in.level) {
	case 0x1:
		disp_ret = init_samr_dispinfo_1(p->mem_ctx, &disp_info->info1,
						num_account, enum_context,
						entries);
		break;
	case 0x2:
		disp_ret = init_samr_dispinfo_2(p->mem_ctx, &disp_info->info2,
						num_account, enum_context,
						entries);
		break;
	case 0x3:
		disp_ret = init_samr_dispinfo_3(p->mem_ctx, &disp_info->info3,
						num_account, enum_context,
						entries);
		break;
	case 0x4:
		disp_ret = init_samr_dispinfo_4(p->mem_ctx, &disp_info->info4,
						num_account, enum_context,
						entries);
		break;
	case 0x5:
		disp_ret = init_samr_dispinfo_5(p->mem_ctx, &disp_info->info5,
						num_account, enum_context,
						entries);
		break;
	default:
		smb_panic("info class changed");
		break;
	}

	if (!NT_STATUS_IS_OK(disp_ret))
		return disp_ret;

	/* calculate the total size */
	total_data_size=num_account*struct_size;

	if (max_entries <= num_account) {
		status = STATUS_MORE_ENTRIES;
	} else {
		status = NT_STATUS_OK;
	}

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info->disp_info, DISP_INFO_CACHE_TIMEOUT);

	DEBUG(5, ("_samr_QueryDisplayInfo: %d\n", __LINE__));

	*r->out.total_size = total_data_size;
	*r->out.returned_size = temp_size;

	return status;
}

/****************************************************************
 _samr_QueryDisplayInfo2
****************************************************************/

NTSTATUS _samr_QueryDisplayInfo2(pipes_struct *p,
				 struct samr_QueryDisplayInfo2 *r)
{
	struct samr_QueryDisplayInfo q;

	q.in.domain_handle	= r->in.domain_handle;
	q.in.level		= r->in.level;
	q.in.start_idx		= r->in.start_idx;
	q.in.max_entries	= r->in.max_entries;
	q.in.buf_size		= r->in.buf_size;

	q.out.total_size	= r->out.total_size;
	q.out.returned_size	= r->out.returned_size;
	q.out.info		= r->out.info;

	return _samr_QueryDisplayInfo(p, &q);
}

/****************************************************************
 _samr_QueryDisplayInfo3
****************************************************************/

NTSTATUS _samr_QueryDisplayInfo3(pipes_struct *p,
				 struct samr_QueryDisplayInfo3 *r)
{
	struct samr_QueryDisplayInfo q;

	q.in.domain_handle	= r->in.domain_handle;
	q.in.level		= r->in.level;
	q.in.start_idx		= r->in.start_idx;
	q.in.max_entries	= r->in.max_entries;
	q.in.buf_size		= r->in.buf_size;

	q.out.total_size	= r->out.total_size;
	q.out.returned_size	= r->out.returned_size;
	q.out.info		= r->out.info;

	return _samr_QueryDisplayInfo(p, &q);
}

/*******************************************************************
 _samr_QueryAliasInfo
 ********************************************************************/

NTSTATUS _samr_QueryAliasInfo(pipes_struct *p,
			      struct samr_QueryAliasInfo *r)
{
	DOM_SID   sid;
	struct acct_info info;
	uint32    acc_granted;
	NTSTATUS status;
	union samr_AliasInfo *alias_info = NULL;
	const char *alias_name = NULL;
	const char *alias_description = NULL;

	DEBUG(5,("_samr_QueryAliasInfo: %d\n", __LINE__));

	alias_info = TALLOC_ZERO_P(p->mem_ctx, union samr_AliasInfo);
	if (!alias_info) {
		return NT_STATUS_NO_MEMORY;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_ALIAS_LOOKUP_INFO,
					    "_samr_QueryAliasInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	become_root();
	status = pdb_get_aliasinfo(&sid, &info);
	unbecome_root();

	if ( !NT_STATUS_IS_OK(status))
		return status;

	/* FIXME: info contains fstrings */
	alias_name = talloc_strdup(r, info.acct_name);
	alias_description = talloc_strdup(r, info.acct_desc);

	switch (r->in.level) {
	case ALIASINFOALL:
		init_samr_alias_info1(&alias_info->all,
				      alias_name,
				      1,
				      alias_description);
		break;
	case ALIASINFODESCRIPTION:
		init_samr_alias_info3(&alias_info->description,
				      alias_description);
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = alias_info;

	DEBUG(5,("_samr_QueryAliasInfo: %d\n", __LINE__));

	return NT_STATUS_OK;
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
 _samr_LookupNames
 ********************************************************************/

NTSTATUS _samr_LookupNames(pipes_struct *p,
			   struct samr_LookupNames *r)
{
	NTSTATUS status;
	uint32 *rid;
	enum lsa_SidType *type;
	int i;
	int num_rids = r->in.num_names;
	DOM_SID pol_sid;
	uint32  acc_granted;
	struct samr_Ids rids, types;
	uint32_t num_mapped = 0;

	DEBUG(5,("_samr_LookupNames: %d\n", __LINE__));

	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &pol_sid, &acc_granted, NULL)) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	status = access_check_samr_function(acc_granted,
					    0, /* Don't know the acc_bits yet */
					    "_samr_LookupNames");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_rids > MAX_SAM_ENTRIES) {
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("_samr_LookupNames: truncating entries to %d\n", num_rids));
	}

	rid = talloc_array(p->mem_ctx, uint32, num_rids);
	NT_STATUS_HAVE_NO_MEMORY(rid);

	type = talloc_array(p->mem_ctx, enum lsa_SidType, num_rids);
	NT_STATUS_HAVE_NO_MEMORY(type);

	DEBUG(5,("_samr_LookupNames: looking name on SID %s\n",
		 sid_string_dbg(&pol_sid)));

	for (i = 0; i < num_rids; i++) {

		status = NT_STATUS_NONE_MAPPED;
	        type[i] = SID_NAME_UNKNOWN;

		rid[i] = 0xffffffff;

		if (sid_check_is_builtin(&pol_sid)) {
			if (lookup_builtin_name(r->in.names[i].string,
						&rid[i]))
			{
				type[i] = SID_NAME_ALIAS;
			}
		} else {
			lookup_global_sam_name(r->in.names[i].string, 0,
					       &rid[i], &type[i]);
		}

		if (type[i] != SID_NAME_UNKNOWN) {
			num_mapped++;
		}
	}

	if (num_mapped == num_rids) {
		status = NT_STATUS_OK;
	} else if (num_mapped == 0) {
		status = NT_STATUS_NONE_MAPPED;
	} else {
		status = STATUS_SOME_UNMAPPED;
	}

	rids.count = num_rids;
	rids.ids = rid;

	types.count = num_rids;
	types.ids = type;

	*r->out.rids = rids;
	*r->out.types = types;

	DEBUG(5,("_samr_LookupNames: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 _samr_ChangePasswordUser2
 ********************************************************************/

NTSTATUS _samr_ChangePasswordUser2(pipes_struct *p,
				   struct samr_ChangePasswordUser2 *r)
{
	NTSTATUS status;
	fstring user_name;
	fstring wks;

	DEBUG(5,("_samr_ChangePasswordUser2: %d\n", __LINE__));

	fstrcpy(user_name, r->in.account->string);
	fstrcpy(wks, r->in.server->string);

	DEBUG(5,("_samr_ChangePasswordUser2: user: %s wks: %s\n", user_name, wks));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */

	(void)map_username(user_name);

	/*
	 * UNIX username case mangling not required, pass_oem_change
	 * is case insensitive.
	 */

	status = pass_oem_change(user_name,
				 r->in.lm_password->data,
				 r->in.lm_verifier->hash,
				 r->in.nt_password->data,
				 r->in.nt_verifier->hash,
				 NULL);

	DEBUG(5,("_samr_ChangePasswordUser2: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 _samr_ChangePasswordUser3
 ********************************************************************/

NTSTATUS _samr_ChangePasswordUser3(pipes_struct *p,
				   struct samr_ChangePasswordUser3 *r)
{
	NTSTATUS status;
	fstring user_name;
	const char *wks = NULL;
	uint32 reject_reason;
	struct samr_DomInfo1 *dominfo = NULL;
	struct samr_ChangeReject *reject = NULL;

	DEBUG(5,("_samr_ChangePasswordUser3: %d\n", __LINE__));

	fstrcpy(user_name, r->in.account->string);
	if (r->in.server && r->in.server->string) {
		wks = r->in.server->string;
	}

	DEBUG(5,("_samr_ChangePasswordUser3: user: %s wks: %s\n", user_name, wks));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */

	(void)map_username(user_name);

	/*
	 * UNIX username case mangling not required, pass_oem_change
	 * is case insensitive.
	 */

	status = pass_oem_change(user_name,
				 r->in.lm_password->data,
				 r->in.lm_verifier->hash,
				 r->in.nt_password->data,
				 r->in.nt_verifier->hash,
				 &reject_reason);

	if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_RESTRICTION)) {

		uint32 min_pass_len,pass_hist,password_properties;
		time_t u_expire, u_min_age;
		NTTIME nt_expire, nt_min_age;
		uint32 account_policy_temp;

		dominfo = TALLOC_ZERO_P(p->mem_ctx, struct samr_DomInfo1);
		if (!dominfo) {
			return NT_STATUS_NO_MEMORY;
		}

		reject = TALLOC_ZERO_P(p->mem_ctx, struct samr_ChangeReject);
		if (!reject) {
			return NT_STATUS_NO_MEMORY;
		}

		become_root();

		/* AS ROOT !!! */

		pdb_get_account_policy(AP_MIN_PASSWORD_LEN, &account_policy_temp);
		min_pass_len = account_policy_temp;

		pdb_get_account_policy(AP_PASSWORD_HISTORY, &account_policy_temp);
		pass_hist = account_policy_temp;

		pdb_get_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS, &account_policy_temp);
		password_properties = account_policy_temp;

		pdb_get_account_policy(AP_MAX_PASSWORD_AGE, &account_policy_temp);
		u_expire = account_policy_temp;

		pdb_get_account_policy(AP_MIN_PASSWORD_AGE, &account_policy_temp);
		u_min_age = account_policy_temp;

		/* !AS ROOT */

		unbecome_root();

		unix_to_nt_time_abs(&nt_expire, u_expire);
		unix_to_nt_time_abs(&nt_min_age, u_min_age);

		if (lp_check_password_script() && *lp_check_password_script()) {
			password_properties |= DOMAIN_PASSWORD_COMPLEX;
		}

		init_samr_DomInfo1(dominfo,
				   min_pass_len,
				   pass_hist,
				   password_properties,
				   u_expire,
				   u_min_age);

		reject->reason = reject_reason;

		*r->out.dominfo = dominfo;
		*r->out.reject = reject;
	}

	DEBUG(5,("_samr_ChangePasswordUser3: %d\n", __LINE__));

	return status;
}

/*******************************************************************
makes a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/

static bool make_samr_lookup_rids(TALLOC_CTX *ctx, uint32 num_names,
				  const char **names,
				  struct lsa_String **lsa_name_array_p)
{
	struct lsa_String *lsa_name_array = NULL;
	uint32_t i;

	*lsa_name_array_p = NULL;

	if (num_names != 0) {
		lsa_name_array = TALLOC_ZERO_ARRAY(ctx, struct lsa_String, num_names);
		if (!lsa_name_array) {
			return false;
		}
	}

	for (i = 0; i < num_names; i++) {
		DEBUG(10, ("names[%d]:%s\n", i, names[i] && *names[i] ? names[i] : ""));
		init_lsa_String(&lsa_name_array[i], names[i]);
	}

	*lsa_name_array_p = lsa_name_array;

	return true;
}

/*******************************************************************
 _samr_LookupRids
 ********************************************************************/

NTSTATUS _samr_LookupRids(pipes_struct *p,
			  struct samr_LookupRids *r)
{
	NTSTATUS status;
	const char **names;
	enum lsa_SidType *attrs = NULL;
	uint32 *wire_attrs = NULL;
	DOM_SID pol_sid;
	int num_rids = (int)r->in.num_rids;
	uint32 acc_granted;
	int i;
	struct lsa_Strings names_array;
	struct samr_Ids types_array;
	struct lsa_String *lsa_names = NULL;

	DEBUG(5,("_samr_LookupRids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &pol_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    0, /* Don't know the acc_bits yet */
					    "_samr__LookupRids");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_rids > 1000) {
		DEBUG(0, ("Got asked for %d rids (more than 1000) -- according "
			  "to samba4 idl this is not possible\n", num_rids));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (num_rids) {
		names = TALLOC_ZERO_ARRAY(p->mem_ctx, const char *, num_rids);
		attrs = TALLOC_ZERO_ARRAY(p->mem_ctx, enum lsa_SidType, num_rids);
		wire_attrs = TALLOC_ZERO_ARRAY(p->mem_ctx, uint32, num_rids);

		if ((names == NULL) || (attrs == NULL) || (wire_attrs==NULL))
			return NT_STATUS_NO_MEMORY;
	} else {
		names = NULL;
		attrs = NULL;
		wire_attrs = NULL;
	}

	become_root();  /* lookup_sid can require root privs */
	status = pdb_lookup_rids(&pol_sid, num_rids, r->in.rids,
				 names, attrs);
	unbecome_root();

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED) && (num_rids == 0)) {
		status = NT_STATUS_OK;
	}

	if (!make_samr_lookup_rids(p->mem_ctx, num_rids, names,
				   &lsa_names)) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Convert from enum lsa_SidType to uint32 for wire format. */
	for (i = 0; i < num_rids; i++) {
		wire_attrs[i] = (uint32)attrs[i];
	}

	names_array.count = num_rids;
	names_array.names = lsa_names;

	types_array.count = num_rids;
	types_array.ids = wire_attrs;

	*r->out.names = names_array;
	*r->out.types = types_array;

	DEBUG(5,("_samr_LookupRids: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 _samr_OpenUser
********************************************************************/

NTSTATUS _samr_OpenUser(pipes_struct *p,
			struct samr_OpenUser *r)
{
	struct samu *sampass=NULL;
	DOM_SID sid;
	POLICY_HND domain_pol = *r->in.domain_handle;
	POLICY_HND *user_pol = r->out.user_handle;
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	size_t    sd_size;
	bool ret;
	NTSTATUS nt_status;
	SE_PRIV se_rights;

	/* find the domain policy handle and get domain SID / access bits in the domain policy. */

	if ( !get_lsa_policy_samr_sid(p, &domain_pol, &sid, &acc_granted, NULL) )
		return NT_STATUS_INVALID_HANDLE;

	nt_status = access_check_samr_function(acc_granted,
					       SA_RIGHT_DOMAIN_OPEN_ACCOUNT,
					       "_samr_OpenUser" );

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	if ( !(sampass = samu_new( p->mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	/* append the user's RID to it */

	if (!sid_append_rid(&sid, r->in.rid))
		return NT_STATUS_NO_SUCH_USER;

	/* check if access can be granted as requested by client. */

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &usr_generic_mapping, &sid, SAMR_USR_RIGHTS_WRITE_PW);
	se_map_generic(&des_access, &usr_generic_mapping);

	se_priv_copy( &se_rights, &se_machine_account );
	se_priv_add( &se_rights, &se_add_users );

	nt_status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		&se_rights, GENERIC_RIGHTS_USER_WRITE, des_access,
		&acc_granted, "_samr_OpenUser");

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	become_root();
	ret=pdb_getsampwsid(sampass, &sid);
	unbecome_root();

	/* check that the SID exists in our domain. */
	if (ret == False) {
        	return NT_STATUS_NO_SUCH_USER;
	}

	TALLOC_FREE(sampass);

	/* associate the user's SID and access bits with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*************************************************************************
 *************************************************************************/

static NTSTATUS init_samr_parameters_string(TALLOC_CTX *mem_ctx,
					    DATA_BLOB *blob,
					    struct lsa_BinaryString **_r)
{
	struct lsa_BinaryString *r;

	if (!blob || !_r) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	r = TALLOC_ZERO_P(mem_ctx, struct lsa_BinaryString);
	if (!r) {
		return NT_STATUS_NO_MEMORY;
	}

	r->array = TALLOC_ZERO_ARRAY(mem_ctx, uint16_t, blob->length/2);
	if (!r->array) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(r->array, blob->data, blob->length);
	r->size = blob->length;
	r->length = blob->length;

	if (!r->array) {
		return NT_STATUS_NO_MEMORY;
	}

	*_r = r;

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_7. Safe. Only gives out account_name.
 *************************************************************************/

static NTSTATUS get_user_info_7(TALLOC_CTX *mem_ctx,
				struct samr_UserInfo7 *r,
				DOM_SID *user_sid)
{
	struct samu *smbpass=NULL;
	bool ret;
	const char *account_name = NULL;

	ZERO_STRUCTP(r);

	if ( !(smbpass = samu_new( mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(smbpass, user_sid);
	unbecome_root();

	if ( !ret ) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	account_name = talloc_strdup(mem_ctx, pdb_get_username(smbpass));
	if (!account_name) {
		TALLOC_FREE(smbpass);
		return NT_STATUS_NO_MEMORY;
	}
	TALLOC_FREE(smbpass);

	DEBUG(3,("User:[%s]\n", account_name));

	init_samr_user_info7(r, account_name);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_9. Only gives out primary group SID.
 *************************************************************************/

static NTSTATUS get_user_info_9(TALLOC_CTX *mem_ctx,
				struct samr_UserInfo9 *r,
				DOM_SID *user_sid)
{
	struct samu *smbpass=NULL;
	bool ret;

	ZERO_STRUCTP(r);

	if ( !(smbpass = samu_new( mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(smbpass, user_sid);
	unbecome_root();

	if (ret==False) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(smbpass);
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(3,("User:[%s]\n", pdb_get_username(smbpass) ));

	init_samr_user_info9(r, pdb_get_group_rid(smbpass));

	TALLOC_FREE(smbpass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_16. Safe. Only gives out acb bits.
 *************************************************************************/

static NTSTATUS get_user_info_16(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo16 *r,
				 DOM_SID *user_sid)
{
	struct samu *smbpass=NULL;
	bool ret;

	ZERO_STRUCTP(r);

	if ( !(smbpass = samu_new( mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(smbpass, user_sid);
	unbecome_root();

	if (ret==False) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(smbpass);
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(3,("User:[%s]\n", pdb_get_username(smbpass) ));

	init_samr_user_info16(r, pdb_get_acct_ctrl(smbpass));

	TALLOC_FREE(smbpass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_18. OK - this is the killer as it gives out password info.
 Ensure that this is only allowed on an encrypted connection with a root
 user. JRA.
 *************************************************************************/

static NTSTATUS get_user_info_18(pipes_struct *p,
				 TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo18 *r,
				 DOM_SID *user_sid)
{
	struct samu *smbpass=NULL;
	bool ret;

	ZERO_STRUCTP(r);

	if (p->auth.auth_type != PIPE_AUTH_TYPE_NTLMSSP || p->auth.auth_type != PIPE_AUTH_TYPE_SPNEGO_NTLMSSP) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (p->auth.auth_level != PIPE_AUTH_LEVEL_PRIVACY) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * Do *NOT* do become_root()/unbecome_root() here ! JRA.
	 */

	if ( !(smbpass = samu_new( mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = pdb_getsampwsid(smbpass, user_sid);

	if (ret == False) {
		DEBUG(4, ("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(smbpass);
		return (geteuid() == (uid_t)0) ? NT_STATUS_NO_SUCH_USER : NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(3,("User:[%s] 0x%x\n", pdb_get_username(smbpass), pdb_get_acct_ctrl(smbpass) ));

	if ( pdb_get_acct_ctrl(smbpass) & ACB_DISABLED) {
		TALLOC_FREE(smbpass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	init_samr_user_info18(r, pdb_get_lanman_passwd(smbpass),
			      pdb_get_nt_passwd(smbpass));

	TALLOC_FREE(smbpass);

	return NT_STATUS_OK;
}

/*************************************************************************
 get_user_info_20
 *************************************************************************/

static NTSTATUS get_user_info_20(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo20 *r,
				 DOM_SID *user_sid)
{
	struct samu *sampass=NULL;
	bool ret;
	const char *munged_dial = NULL;
	DATA_BLOB blob;
	NTSTATUS status;
	struct lsa_BinaryString *parameters = NULL;

	ZERO_STRUCTP(r);

	if ( !(sampass = samu_new( mem_ctx )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(sampass, user_sid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(sampass);
		return NT_STATUS_NO_SUCH_USER;
	}

	munged_dial = pdb_get_munged_dial(sampass);

	samr_clear_sam_passwd(sampass);

	DEBUG(3,("User:[%s] has [%s] (length: %d)\n", pdb_get_username(sampass),
		munged_dial, (int)strlen(munged_dial)));

	if (munged_dial) {
		blob = base64_decode_data_blob(munged_dial);
	} else {
		blob = data_blob_string_const("");
	}

	status = init_samr_parameters_string(mem_ctx, &blob, &parameters);
	data_blob_free(&blob);
	TALLOC_FREE(sampass);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	init_samr_user_info20(r, parameters);

	return NT_STATUS_OK;
}


/*************************************************************************
 get_user_info_21
 *************************************************************************/

static NTSTATUS get_user_info_21(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo21 *r,
				 DOM_SID *user_sid,
				 DOM_SID *domain_sid)
{
	NTSTATUS status;
	struct samu *pw = NULL;
	bool ret;
	const DOM_SID *sid_user, *sid_group;
	uint32_t rid, primary_gid;
	NTTIME last_logon, last_logoff, last_password_change,
	       acct_expiry, allow_password_change, force_password_change;
	time_t must_change_time;
	uint8_t password_expired;
	const char *account_name, *full_name, *home_directory, *home_drive,
		   *logon_script, *profile_path, *description,
		   *workstations, *comment;
	struct samr_LogonHours logon_hours;
	struct lsa_BinaryString *parameters = NULL;
	const char *munged_dial = NULL;
	DATA_BLOB blob;

	ZERO_STRUCTP(r);

	if (!(pw = samu_new(mem_ctx))) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(pw, user_sid);
	unbecome_root();

	if (ret == False) {
		DEBUG(4,("User %s not found\n", sid_string_dbg(user_sid)));
		TALLOC_FREE(pw);
		return NT_STATUS_NO_SUCH_USER;
	}

	samr_clear_sam_passwd(pw);

	DEBUG(3,("User:[%s]\n", pdb_get_username(pw)));

	sid_user = pdb_get_user_sid(pw);

	if (!sid_peek_check_rid(domain_sid, sid_user, &rid)) {
		DEBUG(0, ("get_user_info_21: User %s has SID %s, \nwhich conflicts with "
			  "the domain sid %s.  Failing operation.\n",
			  pdb_get_username(pw), sid_string_dbg(sid_user),
			  sid_string_dbg(domain_sid)));
		TALLOC_FREE(pw);
		return NT_STATUS_UNSUCCESSFUL;
	}

	become_root();
	sid_group = pdb_get_group_sid(pw);
	unbecome_root();

	if (!sid_peek_check_rid(domain_sid, sid_group, &primary_gid)) {
		DEBUG(0, ("get_user_info_21: User %s has Primary Group SID %s, \n"
			  "which conflicts with the domain sid %s.  Failing operation.\n",
			  pdb_get_username(pw), sid_string_dbg(sid_group),
			  sid_string_dbg(domain_sid)));
		TALLOC_FREE(pw);
		return NT_STATUS_UNSUCCESSFUL;
	}

	unix_to_nt_time(&last_logon, pdb_get_logon_time(pw));
	unix_to_nt_time(&last_logoff, pdb_get_logoff_time(pw));
	unix_to_nt_time(&acct_expiry, pdb_get_kickoff_time(pw));
	unix_to_nt_time(&last_password_change, pdb_get_pass_last_set_time(pw));
	unix_to_nt_time(&allow_password_change, pdb_get_pass_can_change_time(pw));

	must_change_time = pdb_get_pass_must_change_time(pw);
	if (must_change_time == get_time_t_max()) {
		unix_to_nt_time_abs(&force_password_change, must_change_time);
	} else {
		unix_to_nt_time(&force_password_change, must_change_time);
	}

	if (pdb_get_pass_must_change_time(pw) == 0) {
		password_expired = PASS_MUST_CHANGE_AT_NEXT_LOGON;
	} else {
		password_expired = 0;
	}

	munged_dial = pdb_get_munged_dial(pw);
	if (munged_dial) {
		blob = base64_decode_data_blob(munged_dial);
	} else {
		blob = data_blob_string_const("");
	}

	status = init_samr_parameters_string(mem_ctx, &blob, &parameters);
	data_blob_free(&blob);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(pw);
		return status;
	}

	account_name = talloc_strdup(mem_ctx, pdb_get_username(pw));
	full_name = talloc_strdup(mem_ctx, pdb_get_fullname(pw));
	home_directory = talloc_strdup(mem_ctx, pdb_get_homedir(pw));
	home_drive = talloc_strdup(mem_ctx, pdb_get_dir_drive(pw));
	logon_script = talloc_strdup(mem_ctx, pdb_get_logon_script(pw));
	profile_path = talloc_strdup(mem_ctx, pdb_get_profile_path(pw));
	description = talloc_strdup(mem_ctx, pdb_get_acct_desc(pw));
	workstations = talloc_strdup(mem_ctx, pdb_get_workstations(pw));
	comment = talloc_strdup(mem_ctx, pdb_get_comment(pw));

	logon_hours = get_logon_hours_from_pdb(mem_ctx, pw);
#if 0

	/*
	  Look at a user on a real NT4 PDC with usrmgr, press
	  'ok'. Then you will see that fields_present is set to
	  0x08f827fa. Look at the user immediately after that again,
	  and you will see that 0x00fffff is returned. This solves
	  the problem that you get access denied after having looked
	  at the user.
	  -- Volker
	*/

#endif

	init_samr_user_info21(r,
			      last_logon,
			      last_logoff,
			      last_password_change,
			      acct_expiry,
			      allow_password_change,
			      force_password_change,
			      account_name,
			      full_name,
			      home_directory,
			      home_drive,
			      logon_script,
			      profile_path,
			      description,
			      workstations,
			      comment,
			      parameters,
			      rid,
			      primary_gid,
			      pdb_get_acct_ctrl(pw),
			      pdb_build_fields_present(pw),
			      logon_hours,
			      pdb_get_bad_password_count(pw),
			      pdb_get_logon_count(pw),
			      0, /* country_code */
			      0, /* code_page */
			      0, /* nt_password_set */
			      0, /* lm_password_set */
			      password_expired);
	TALLOC_FREE(pw);

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_QueryUserInfo
 ********************************************************************/

NTSTATUS _samr_QueryUserInfo(pipes_struct *p,
			     struct samr_QueryUserInfo *r)
{
	NTSTATUS status;
	union samr_UserInfo *user_info = NULL;
	struct samr_info *info = NULL;
	DOM_SID domain_sid;
	uint32 rid;

	/* search for the handle */
	if (!find_policy_by_hnd(p, r->in.user_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(info->acc_granted,
					    SAMR_USER_ACCESS_GET_ATTRIBUTES,
					    "_samr_QueryUserInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	domain_sid = info->sid;

	sid_split_rid(&domain_sid, &rid);

	if (!sid_check_is_in_our_domain(&info->sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	DEBUG(5,("_samr_QueryUserInfo: sid:%s\n",
		 sid_string_dbg(&info->sid)));

	user_info = TALLOC_ZERO_P(p->mem_ctx, union samr_UserInfo);
	if (!user_info) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5,("_samr_QueryUserInfo: user info level: %d\n", r->in.level));

	switch (r->in.level) {
	case 7:
		status = get_user_info_7(p->mem_ctx, &user_info->info7, &info->sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;
	case 9:
		status = get_user_info_9(p->mem_ctx, &user_info->info9, &info->sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;
	case 16:
		status = get_user_info_16(p->mem_ctx, &user_info->info16, &info->sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	case 18:
		status = get_user_info_18(p, p->mem_ctx, &user_info->info18, &info->sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	case 20:
		status = get_user_info_20(p->mem_ctx, &user_info->info20, &info->sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	case 21:
		status = get_user_info_21(p->mem_ctx, &user_info->info21,
					  &info->sid, &domain_sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = user_info;

	DEBUG(5,("_samr_QueryUserInfo: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 _samr_GetGroupsForUser
 ********************************************************************/

NTSTATUS _samr_GetGroupsForUser(pipes_struct *p,
				struct samr_GetGroupsForUser *r)
{
	struct samu *sam_pass=NULL;
	DOM_SID  sid;
	DOM_SID *sids;
	struct samr_RidWithAttribute dom_gid;
	struct samr_RidWithAttribute *gids = NULL;
	uint32 primary_group_rid;
	size_t num_groups = 0;
	gid_t *unix_gids;
	size_t i, num_gids;
	uint32 acc_granted;
	bool ret;
	NTSTATUS result;
	bool success = False;

	struct samr_RidWithAttributeArray *rids = NULL;

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

	DEBUG(5,("_samr_GetGroupsForUser: %d\n", __LINE__));

	rids = TALLOC_ZERO_P(p->mem_ctx, struct samr_RidWithAttributeArray);
	if (!rids) {
		return NT_STATUS_NO_MEMORY;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.user_handle, &sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	result = access_check_samr_function(acc_granted,
					    SA_RIGHT_USER_GET_GROUPS,
					    "_samr_GetGroupsForUser");
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (!sid_check_is_in_our_domain(&sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

        if ( !(sam_pass = samu_new( p->mem_ctx )) ) {
                return NT_STATUS_NO_MEMORY;
        }

	become_root();
	ret = pdb_getsampwsid(sam_pass, &sid);
	unbecome_root();

	if (!ret) {
		DEBUG(10, ("pdb_getsampwsid failed for %s\n",
			   sid_string_dbg(&sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	sids = NULL;

	/* make both calls inside the root block */
	become_root();
	result = pdb_enum_group_memberships(p->mem_ctx, sam_pass,
					    &sids, &unix_gids, &num_groups);
	if ( NT_STATUS_IS_OK(result) ) {
		success = sid_peek_check_rid(get_global_sam_sid(),
					     pdb_get_group_sid(sam_pass),
					     &primary_group_rid);
	}
	unbecome_root();

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10, ("pdb_enum_group_memberships failed for %s\n",
			   sid_string_dbg(&sid)));
		return result;
	}

	if ( !success ) {
		DEBUG(5, ("Group sid %s for user %s not in our domain\n",
			  sid_string_dbg(pdb_get_group_sid(sam_pass)),
			  pdb_get_username(sam_pass)));
		TALLOC_FREE(sam_pass);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	gids = NULL;
	num_gids = 0;

	dom_gid.attributes = (SE_GROUP_MANDATORY|SE_GROUP_ENABLED_BY_DEFAULT|
			      SE_GROUP_ENABLED);
	dom_gid.rid = primary_group_rid;
	ADD_TO_ARRAY(p->mem_ctx, struct samr_RidWithAttribute, dom_gid, &gids, &num_gids);

	for (i=0; i<num_groups; i++) {

		if (!sid_peek_check_rid(get_global_sam_sid(),
					&(sids[i]), &dom_gid.rid)) {
			DEBUG(10, ("Found sid %s not in our domain\n",
				   sid_string_dbg(&sids[i])));
			continue;
		}

		if (dom_gid.rid == primary_group_rid) {
			/* We added the primary group directly from the
			 * sam_account. The other SIDs are unique from
			 * enum_group_memberships */
			continue;
		}

		ADD_TO_ARRAY(p->mem_ctx, struct samr_RidWithAttribute, dom_gid, &gids, &num_gids);
	}

	rids->count = num_gids;
	rids->rids = gids;

	*r->out.rids = rids;

	DEBUG(5,("_samr_GetGroupsForUser: %d\n", __LINE__));

	return result;
}

/*******************************************************************
 _samr_QueryDomainInfo
 ********************************************************************/

NTSTATUS _samr_QueryDomainInfo(pipes_struct *p,
			       struct samr_QueryDomainInfo *r)
{
	NTSTATUS status = NT_STATUS_OK;
	struct samr_info *info = NULL;
	union samr_DomainInfo *dom_info;
	uint32 min_pass_len,pass_hist,password_properties;
	time_t u_expire, u_min_age;
	NTTIME nt_expire, nt_min_age;

	time_t u_lock_duration, u_reset_time;
	NTTIME nt_lock_duration, nt_reset_time;
	uint32 lockout;
	time_t u_logout;
	NTTIME nt_logout;

	uint32 account_policy_temp;

	time_t seq_num;
	uint32 server_role;

	uint32 num_users=0, num_groups=0, num_aliases=0;

	DEBUG(5,("_samr_QueryDomainInfo: %d\n", __LINE__));

	dom_info = TALLOC_ZERO_P(p->mem_ctx, union samr_DomainInfo);
	if (!dom_info) {
		return NT_STATUS_NO_MEMORY;
	}

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_SAM_LOOKUP_DOMAIN,
					    "_samr_QueryDomainInfo" );

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	switch (r->in.level) {
		case 0x01:

			become_root();

			/* AS ROOT !!! */

			pdb_get_account_policy(AP_MIN_PASSWORD_LEN, &account_policy_temp);
			min_pass_len = account_policy_temp;

			pdb_get_account_policy(AP_PASSWORD_HISTORY, &account_policy_temp);
			pass_hist = account_policy_temp;

			pdb_get_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS, &account_policy_temp);
			password_properties = account_policy_temp;

			pdb_get_account_policy(AP_MAX_PASSWORD_AGE, &account_policy_temp);
			u_expire = account_policy_temp;

			pdb_get_account_policy(AP_MIN_PASSWORD_AGE, &account_policy_temp);
			u_min_age = account_policy_temp;

			/* !AS ROOT */

			unbecome_root();

			unix_to_nt_time_abs(&nt_expire, u_expire);
			unix_to_nt_time_abs(&nt_min_age, u_min_age);

			if (lp_check_password_script() && *lp_check_password_script()) {
				password_properties |= DOMAIN_PASSWORD_COMPLEX;
			}

			init_samr_DomInfo1(&dom_info->info1,
					   (uint16)min_pass_len,
					   (uint16)pass_hist,
					   password_properties,
					   nt_expire,
					   nt_min_age);
			break;
		case 0x02:

			become_root();

			/* AS ROOT !!! */

			num_users = count_sam_users(info->disp_info, ACB_NORMAL);
			num_groups = count_sam_groups(info->disp_info);
			num_aliases = count_sam_aliases(info->disp_info);

			pdb_get_account_policy(AP_TIME_TO_LOGOUT, &account_policy_temp);
			u_logout = account_policy_temp;

			unix_to_nt_time_abs(&nt_logout, u_logout);

			if (!pdb_get_seq_num(&seq_num))
				seq_num = time(NULL);

			/* !AS ROOT */

			unbecome_root();

			server_role = ROLE_DOMAIN_PDC;
			if (lp_server_role() == ROLE_DOMAIN_BDC)
				server_role = ROLE_DOMAIN_BDC;

			init_samr_DomInfo2(&dom_info->info2,
					   nt_logout,
					   lp_serverstring(),
					   lp_workgroup(),
					   global_myname(),
					   seq_num,
					   1,
					   server_role,
					   1,
					   num_users,
					   num_groups,
					   num_aliases);
			break;
		case 0x03:

			become_root();

			/* AS ROOT !!! */

			{
				uint32 ul;
				pdb_get_account_policy(AP_TIME_TO_LOGOUT, &ul);
				u_logout = (time_t)ul;
			}

			/* !AS ROOT */

			unbecome_root();

			unix_to_nt_time_abs(&nt_logout, u_logout);

			init_samr_DomInfo3(&dom_info->info3,
					   nt_logout);

			break;
		case 0x04:
			init_samr_DomInfo4(&dom_info->info4,
					   lp_serverstring());
			break;
		case 0x05:
			init_samr_DomInfo5(&dom_info->info5,
					   get_global_sam_name());
			break;
		case 0x06:
			/* NT returns its own name when a PDC. win2k and later
			 * only the name of the PDC if itself is a BDC (samba4
			 * idl) */
			init_samr_DomInfo6(&dom_info->info6,
					   global_myname());
			break;
		case 0x07:
			server_role = ROLE_DOMAIN_PDC;
			if (lp_server_role() == ROLE_DOMAIN_BDC)
				server_role = ROLE_DOMAIN_BDC;

			init_samr_DomInfo7(&dom_info->info7,
					   server_role);
			break;
		case 0x08:

			become_root();

			/* AS ROOT !!! */

			if (!pdb_get_seq_num(&seq_num)) {
				seq_num = time(NULL);
			}

			/* !AS ROOT */

			unbecome_root();

			init_samr_DomInfo8(&dom_info->info8,
					   seq_num,
					   0);
			break;
		case 0x0c:

			become_root();

			/* AS ROOT !!! */

			pdb_get_account_policy(AP_LOCK_ACCOUNT_DURATION, &account_policy_temp);
			u_lock_duration = account_policy_temp;
			if (u_lock_duration != -1) {
				u_lock_duration *= 60;
			}

			pdb_get_account_policy(AP_RESET_COUNT_TIME, &account_policy_temp);
			u_reset_time = account_policy_temp * 60;

			pdb_get_account_policy(AP_BAD_ATTEMPT_LOCKOUT, &account_policy_temp);
			lockout = account_policy_temp;

			/* !AS ROOT */

			unbecome_root();

			unix_to_nt_time_abs(&nt_lock_duration, u_lock_duration);
			unix_to_nt_time_abs(&nt_reset_time, u_reset_time);

			init_samr_DomInfo12(&dom_info->info12,
					    nt_lock_duration,
					    nt_reset_time,
					    (uint16)lockout);
            		break;
        	default:
            		return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = dom_info;

	DEBUG(5,("_samr_QueryDomainInfo: %d\n", __LINE__));

	return status;
}

/* W2k3 seems to use the same check for all 3 objects that can be created via
 * SAMR, if you try to create for example "Dialup" as an alias it says
 * "NT_STATUS_USER_EXISTS". This is racy, but we can't really lock the user
 * database. */

static NTSTATUS can_create(TALLOC_CTX *mem_ctx, const char *new_name)
{
	enum lsa_SidType type;
	bool result;

	DEBUG(10, ("Checking whether [%s] can be created\n", new_name));

	become_root();
	/* Lookup in our local databases (LOOKUP_NAME_REMOTE not set)
	 * whether the name already exists */
	result = lookup_name(mem_ctx, new_name, LOOKUP_NAME_LOCAL,
			     NULL, NULL, NULL, &type);
	unbecome_root();

	if (!result) {
		DEBUG(10, ("%s does not exist, can create it\n", new_name));
		return NT_STATUS_OK;
	}

	DEBUG(5, ("trying to create %s, exists as %s\n",
		  new_name, sid_type_lookup(type)));

	if (type == SID_NAME_DOM_GRP) {
		return NT_STATUS_GROUP_EXISTS;
	}
	if (type == SID_NAME_ALIAS) {
		return NT_STATUS_ALIAS_EXISTS;
	}

	/* Yes, the default is NT_STATUS_USER_EXISTS */
	return NT_STATUS_USER_EXISTS;
}

/*******************************************************************
 _samr_CreateUser2
 ********************************************************************/

NTSTATUS _samr_CreateUser2(pipes_struct *p,
			   struct samr_CreateUser2 *r)
{
	const char *account = NULL;
	DOM_SID sid;
	POLICY_HND dom_pol = *r->in.domain_handle;
	uint32_t acb_info = r->in.acct_flags;
	POLICY_HND *user_pol = r->out.user_handle;
	struct samr_info *info = NULL;
	NTSTATUS nt_status;
	uint32 acc_granted;
	SEC_DESC *psd;
	size_t    sd_size;
	/* check this, when giving away 'add computer to domain' privs */
	uint32    des_access = GENERIC_RIGHTS_USER_ALL_ACCESS;
	bool can_add_account = False;
	SE_PRIV se_rights;
	DISP_INFO *disp_info = NULL;

	/* Get the domain SID stored in the domain policy */
	if (!get_lsa_policy_samr_sid(p, &dom_pol, &sid, &acc_granted,
				     &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	nt_status = access_check_samr_function(acc_granted,
					       SA_RIGHT_DOMAIN_CREATE_USER,
					       "_samr_CreateUser2");
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (!(acb_info == ACB_NORMAL || acb_info == ACB_DOMTRUST ||
	      acb_info == ACB_WSTRUST || acb_info == ACB_SVRTRUST)) {
		/* Match Win2k, and return NT_STATUS_INVALID_PARAMETER if
		   this parameter is not an account type */
		return NT_STATUS_INVALID_PARAMETER;
	}

	account = r->in.account_name->string;
	if (account == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = can_create(p->mem_ctx, account);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/* determine which user right we need to check based on the acb_info */

	if ( acb_info & ACB_WSTRUST )
	{
		se_priv_copy( &se_rights, &se_machine_account );
		can_add_account = user_has_privileges(
			p->pipe_user.nt_user_token, &se_rights );
	}
	/* usrmgr.exe (and net rpc trustdom grant) creates a normal user
	   account for domain trusts and changes the ACB flags later */
	else if ( acb_info & ACB_NORMAL &&
		  (account[strlen(account)-1] != '$') )
	{
		se_priv_copy( &se_rights, &se_add_users );
		can_add_account = user_has_privileges(
			p->pipe_user.nt_user_token, &se_rights );
	}
	else 	/* implicit assumption of a BDC or domain trust account here
		 * (we already check the flags earlier) */
	{
		if ( lp_enable_privileges() ) {
			/* only Domain Admins can add a BDC or domain trust */
			se_priv_copy( &se_rights, &se_priv_none );
			can_add_account = nt_token_check_domain_rid(
				p->pipe_user.nt_user_token,
				DOMAIN_GROUP_RID_ADMINS );
		}
	}

	DEBUG(5, ("_samr_CreateUser2: %s can add this account : %s\n",
		  uidtoname(p->pipe_user.ut.uid),
		  can_add_account ? "True":"False" ));

	/********** BEGIN Admin BLOCK **********/

	if ( can_add_account )
		become_root();

	nt_status = pdb_create_user(p->mem_ctx, account, acb_info,
				    r->out.rid);

	if ( can_add_account )
		unbecome_root();

	/********** END Admin BLOCK **********/

	/* now check for failure */

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	/* Get the user's SID */

	sid_compose(&sid, get_global_sam_sid(), *r->out.rid);

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &usr_generic_mapping,
			    &sid, SAMR_USR_RIGHTS_WRITE_PW);
	se_map_generic(&des_access, &usr_generic_mapping);

	nt_status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		&se_rights, GENERIC_RIGHTS_USER_WRITE, des_access,
		&acc_granted, "_samr_CreateUser2");

	if ( !NT_STATUS_IS_OK(nt_status) ) {
		return nt_status;
	}

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(info);
	info->sid = sid;
	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, user_pol, free_samr_info, (void *)info)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* After a "set" ensure we have no cached display info. */
	force_flush_samr_cache(info->disp_info);

	*r->out.access_granted = acc_granted;

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_Connect
 ********************************************************************/

NTSTATUS _samr_Connect(pipes_struct *p,
		       struct samr_Connect *r)
{
	struct samr_info *info = NULL;
	uint32    des_access = r->in.access_mask;

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to _samr_Connect\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* set up the SAMR connect_anon response */

	/* associate the user's SID with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* don't give away the farm but this is probably ok.  The SA_RIGHT_SAM_ENUM_DOMAINS
	   was observed from a win98 client trying to enumerate users (when configured
	   user level access control on shares)   --jerry */

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	se_map_generic( &des_access, &sam_generic_mapping );
	info->acc_granted = des_access & (SA_RIGHT_SAM_ENUM_DOMAINS|SA_RIGHT_SAM_LOOKUP_DOMAIN);

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.connect_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_Connect2
 ********************************************************************/

NTSTATUS _samr_Connect2(pipes_struct *p,
			struct samr_Connect2 *r)
{
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	NTSTATUS  nt_status;
	size_t    sd_size;


	DEBUG(5,("_samr_Connect2: %d\n", __LINE__));

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to _samr_Connect2\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &sam_generic_mapping, NULL, 0);
	se_map_generic(&des_access, &sam_generic_mapping);

	nt_status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		NULL, 0, des_access, &acc_granted, "_samr_Connect2");

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	/* associate the user's SID and access granted with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;
	info->status = r->in.access_mask; /* this looks so wrong... - gd */

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.connect_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_Connect2: %d\n", __LINE__));

	return nt_status;
}

/*******************************************************************
 _samr_Connect4
 ********************************************************************/

NTSTATUS _samr_Connect4(pipes_struct *p,
			struct samr_Connect4 *r)
{
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	NTSTATUS  nt_status;
	size_t    sd_size;


	DEBUG(5,("_samr_Connect4: %d\n", __LINE__));

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_Connect4\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &sam_generic_mapping, NULL, 0);
	se_map_generic(&des_access, &sam_generic_mapping);

	nt_status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		NULL, 0, des_access, &acc_granted, "_samr_Connect4");

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	/* associate the user's SID and access granted with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;
	info->status = r->in.access_mask; /* ??? */

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.connect_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_Connect4: %d\n", __LINE__));

	return NT_STATUS_OK;
}

/*******************************************************************
 _samr_Connect5
 ********************************************************************/

NTSTATUS _samr_Connect5(pipes_struct *p,
			struct samr_Connect5 *r)
{
	struct samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	NTSTATUS  nt_status;
	size_t    sd_size;
	struct samr_ConnectInfo1 info1;

	DEBUG(5,("_samr_Connect5: %d\n", __LINE__));

	/* Access check */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to samr_Connect5\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &sam_generic_mapping, NULL, 0);
	se_map_generic(&des_access, &sam_generic_mapping);

	nt_status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		NULL, 0, des_access, &acc_granted, "_samr_Connect5");

	if ( !NT_STATUS_IS_OK(nt_status) )
		return nt_status;

	/* associate the user's SID and access granted with the new handle. */
	if ((info = get_samr_info_by_sid(NULL)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;
	info->status = r->in.access_mask; /* ??? */

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.connect_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	DEBUG(5,("_samr_Connect5: %d\n", __LINE__));

	info1.client_version = SAMR_CONNECT_AFTER_W2K;
	info1.unknown2 = 0;

	*r->out.level_out = 1;
	r->out.info_out->info1 = info1;

	return NT_STATUS_OK;
}

/**********************************************************************
 _samr_LookupDomain
 **********************************************************************/

NTSTATUS _samr_LookupDomain(pipes_struct *p,
			    struct samr_LookupDomain *r)
{
	NTSTATUS status = NT_STATUS_OK;
	struct samr_info *info;
	const char *domain_name;
	DOM_SID *sid = NULL;

	if (!find_policy_by_hnd(p, r->in.connect_handle, (void**)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* win9x user manager likes to use SA_RIGHT_SAM_ENUM_DOMAINS here.
	   Reverted that change so we will work with RAS servers again */

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_SAM_LOOKUP_DOMAIN,
					    "_samr_LookupDomain");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	domain_name = r->in.domain_name->string;

	sid = TALLOC_ZERO_P(p->mem_ctx, struct dom_sid2);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strequal(domain_name, builtin_domain_name())) {
		sid_copy(sid, &global_sid_Builtin);
	} else {
		if (!secrets_fetch_domain_sid(domain_name, sid)) {
			status = NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	DEBUG(2,("Returning domain sid for domain %s -> %s\n", domain_name,
		 sid_string_dbg(sid)));

	*r->out.sid = sid;

	return status;
}

/**********************************************************************
 _samr_EnumDomains
 **********************************************************************/

NTSTATUS _samr_EnumDomains(pipes_struct *p,
			   struct samr_EnumDomains *r)
{
	NTSTATUS status;
	struct samr_info *info;
	uint32_t num_entries = 2;
	struct samr_SamEntry *entry_array = NULL;
	struct samr_SamArray *sam;

	if (!find_policy_by_hnd(p, r->in.connect_handle, (void**)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_SAM_ENUM_DOMAINS,
					    "_samr_EnumDomains");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sam = TALLOC_ZERO_P(p->mem_ctx, struct samr_SamArray);
	if (!sam) {
		return NT_STATUS_NO_MEMORY;
	}

	entry_array = TALLOC_ZERO_ARRAY(p->mem_ctx,
					struct samr_SamEntry,
					num_entries);
	if (!entry_array) {
		return NT_STATUS_NO_MEMORY;
	}

	entry_array[0].idx = 0;
	init_lsa_String(&entry_array[0].name, get_global_sam_name());

	entry_array[1].idx = 1;
	init_lsa_String(&entry_array[1].name, "Builtin");

	sam->count = num_entries;
	sam->entries = entry_array;

	*r->out.sam = sam;
	*r->out.num_entries = num_entries;

	return status;
}

/*******************************************************************
 _samr_OpenAlias
 ********************************************************************/

NTSTATUS _samr_OpenAlias(pipes_struct *p,
			 struct samr_OpenAlias *r)
{
	DOM_SID sid;
	POLICY_HND domain_pol = *r->in.domain_handle;
	uint32 alias_rid = r->in.rid;
	POLICY_HND *alias_pol = r->out.alias_handle;
	struct    samr_info *info = NULL;
	SEC_DESC *psd = NULL;
	uint32    acc_granted;
	uint32    des_access = r->in.access_mask;
	size_t    sd_size;
	NTSTATUS  status;
	SE_PRIV se_rights;

	/* find the domain policy and get the SID / access bits stored in the domain policy */

	if ( !get_lsa_policy_samr_sid(p, &domain_pol, &sid, &acc_granted, NULL) )
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_DOMAIN_OPEN_ACCOUNT,
					    "_samr_OpenAlias");

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/* append the alias' RID to it */

	if (!sid_append_rid(&sid, alias_rid))
		return NT_STATUS_NO_SUCH_ALIAS;

	/*check if access can be granted as requested by client. */

	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &ali_generic_mapping, NULL, 0);
	se_map_generic(&des_access,&ali_generic_mapping);

	se_priv_copy( &se_rights, &se_add_users );


	status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		&se_rights, GENERIC_RIGHTS_ALIAS_WRITE, des_access,
		&acc_granted, "_samr_OpenAlias");

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	{
		/* Check we actually have the requested alias */
		enum lsa_SidType type;
		bool result;
		gid_t gid;

		become_root();
		result = lookup_sid(NULL, &sid, NULL, NULL, &type);
		unbecome_root();

		if (!result || (type != SID_NAME_ALIAS)) {
			return NT_STATUS_NO_SUCH_ALIAS;
		}

		/* make sure there is a mapping */

		if ( !sid_to_gid( &sid, &gid ) ) {
			return NT_STATUS_NO_SUCH_ALIAS;
		}

	}

	/* associate the alias SID with the new handle. */
	if ((info = get_samr_info_by_sid(&sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, alias_pol, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*******************************************************************
 set_user_info_7
 ********************************************************************/

static NTSTATUS set_user_info_7(TALLOC_CTX *mem_ctx,
				struct samr_UserInfo7 *id7,
				struct samu *pwd)
{
	NTSTATUS rc;

	if (id7 == NULL) {
		DEBUG(5, ("set_user_info_7: NULL id7\n"));
		TALLOC_FREE(pwd);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!id7->account_name.string) {
	        DEBUG(5, ("set_user_info_7: failed to get new username\n"));
		TALLOC_FREE(pwd);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* check to see if the new username already exists.  Note: we can't
	   reliably lock all backends, so there is potentially the
	   possibility that a user can be created in between this check and
	   the rename.  The rename should fail, but may not get the
	   exact same failure status code.  I think this is small enough
	   of a window for this type of operation and the results are
	   simply that the rename fails with a slightly different status
	   code (like UNSUCCESSFUL instead of ALREADY_EXISTS). */

	rc = can_create(mem_ctx, id7->account_name.string);
	if (!NT_STATUS_IS_OK(rc)) {
		return rc;
	}

	rc = pdb_rename_sam_account(pwd, id7->account_name.string);

	TALLOC_FREE(pwd);
	return rc;
}

/*******************************************************************
 set_user_info_16
 ********************************************************************/

static bool set_user_info_16(struct samr_UserInfo16 *id16,
			     struct samu *pwd)
{
	if (id16 == NULL) {
		DEBUG(5, ("set_user_info_16: NULL id16\n"));
		TALLOC_FREE(pwd);
		return False;
	}

	/* FIX ME: check if the value is really changed --metze */
	if (!pdb_set_acct_ctrl(pwd, id16->acct_flags, PDB_CHANGED)) {
		TALLOC_FREE(pwd);
		return False;
	}

	if(!NT_STATUS_IS_OK(pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return False;
	}

	TALLOC_FREE(pwd);

	return True;
}

/*******************************************************************
 set_user_info_18
 ********************************************************************/

static bool set_user_info_18(struct samr_UserInfo18 *id18,
			     struct samu *pwd)
{
	if (id18 == NULL) {
		DEBUG(2, ("set_user_info_18: id18 is NULL\n"));
		TALLOC_FREE(pwd);
		return False;
	}

	if (!pdb_set_lanman_passwd (pwd, id18->lm_pwd.hash, PDB_CHANGED)) {
		TALLOC_FREE(pwd);
		return False;
	}
	if (!pdb_set_nt_passwd     (pwd, id18->nt_pwd.hash, PDB_CHANGED)) {
		TALLOC_FREE(pwd);
		return False;
	}
 	if (!pdb_set_pass_last_set_time (pwd, time(NULL), PDB_CHANGED)) {
		TALLOC_FREE(pwd);
		return False;
	}

	if(!NT_STATUS_IS_OK(pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return False;
 	}

	TALLOC_FREE(pwd);
	return True;
}

/*******************************************************************
 set_user_info_20
 ********************************************************************/

static bool set_user_info_20(struct samr_UserInfo20 *id20,
			     struct samu *pwd)
{
	if (id20 == NULL) {
		DEBUG(5, ("set_user_info_20: NULL id20\n"));
		return False;
	}

	copy_id20_to_sam_passwd(pwd, id20);

	/* write the change out */
	if(!NT_STATUS_IS_OK(pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return False;
 	}

	TALLOC_FREE(pwd);

	return True;
}

/*******************************************************************
 set_user_info_21
 ********************************************************************/

static NTSTATUS set_user_info_21(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo21 *id21,
				 struct samu *pwd)
{
	NTSTATUS status;

	if (id21 == NULL) {
		DEBUG(5, ("set_user_info_21: NULL id21\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* we need to separately check for an account rename first */

	if (id21->account_name.string &&
	    (!strequal(id21->account_name.string, pdb_get_username(pwd))))
	{

		/* check to see if the new username already exists.  Note: we can't
		   reliably lock all backends, so there is potentially the
		   possibility that a user can be created in between this check and
		   the rename.  The rename should fail, but may not get the
		   exact same failure status code.  I think this is small enough
		   of a window for this type of operation and the results are
		   simply that the rename fails with a slightly different status
		   code (like UNSUCCESSFUL instead of ALREADY_EXISTS). */

		status = can_create(mem_ctx, id21->account_name.string);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = pdb_rename_sam_account(pwd, id21->account_name.string);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("set_user_info_21: failed to rename account: %s\n",
				nt_errstr(status)));
			TALLOC_FREE(pwd);
			return status;
		}

		/* set the new username so that later
		   functions can work on the new account */
		pdb_set_username(pwd, id21->account_name.string, PDB_SET);
	}

	copy_id21_to_sam_passwd("INFO_21", pwd, id21);

	/*
	 * The funny part about the previous two calls is
	 * that pwd still has the password hashes from the
	 * passdb entry.  These have not been updated from
	 * id21.  I don't know if they need to be set.    --jerry
	 */

	if ( IS_SAM_CHANGED(pwd, PDB_GROUPSID) ) {
		status = pdb_set_unix_primary_group(mem_ctx, pwd);
		if ( !NT_STATUS_IS_OK(status) ) {
			return status;
		}
	}

	/* Don't worry about writing out the user account since the
	   primary group SID is generated solely from the user's Unix
	   primary group. */

	/* write the change out */
	if(!NT_STATUS_IS_OK(status = pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return status;
 	}

	TALLOC_FREE(pwd);

	return NT_STATUS_OK;
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/

static NTSTATUS set_user_info_23(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo23 *id23,
				 struct samu *pwd)
{
	char *plaintext_buf = NULL;
	uint32 len = 0;
	uint16 acct_ctrl;
	NTSTATUS status;

	if (id23 == NULL) {
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5, ("Attempting administrator password change (level 23) for user %s\n",
		  pdb_get_username(pwd)));

	acct_ctrl = pdb_get_acct_ctrl(pwd);

	if (!decode_pw_buffer(mem_ctx,
				id23->password.data,
				&plaintext_buf,
				&len,
				STR_UNICODE)) {
		TALLOC_FREE(pwd);
		return NT_STATUS_INVALID_PARAMETER;
 	}

	if (!pdb_set_plaintext_passwd (pwd, plaintext_buf)) {
		TALLOC_FREE(pwd);
		return NT_STATUS_ACCESS_DENIED;
	}

	copy_id23_to_sam_passwd(pwd, id23);

	/* if it's a trust account, don't update /etc/passwd */
	if (    ( (acct_ctrl &  ACB_DOMTRUST) == ACB_DOMTRUST ) ||
		( (acct_ctrl &  ACB_WSTRUST) ==  ACB_WSTRUST) ||
		( (acct_ctrl &  ACB_SVRTRUST) ==  ACB_SVRTRUST) ) {
		DEBUG(5, ("Changing trust account.  Not updating /etc/passwd\n"));
	} else  {
		/* update the UNIX password */
		if (lp_unix_password_sync() ) {
			struct passwd *passwd;
			if (pdb_get_username(pwd) == NULL) {
				DEBUG(1, ("chgpasswd: User without name???\n"));
				TALLOC_FREE(pwd);
				return NT_STATUS_ACCESS_DENIED;
			}

			passwd = Get_Pwnam_alloc(pwd, pdb_get_username(pwd));
			if (passwd == NULL) {
				DEBUG(1, ("chgpasswd: Username does not exist in system !?!\n"));
			}

			if(!chgpasswd(pdb_get_username(pwd), passwd, "", plaintext_buf, True)) {
				TALLOC_FREE(pwd);
				return NT_STATUS_ACCESS_DENIED;
			}
			TALLOC_FREE(passwd);
		}
	}

	memset(plaintext_buf, '\0', strlen(plaintext_buf));

	if (IS_SAM_CHANGED(pwd, PDB_GROUPSID) &&
	    (!NT_STATUS_IS_OK(status =  pdb_set_unix_primary_group(mem_ctx,
								   pwd)))) {
		TALLOC_FREE(pwd);
		return status;
	}

	if(!NT_STATUS_IS_OK(status = pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return status;
	}

	TALLOC_FREE(pwd);

	return NT_STATUS_OK;
}

/*******************************************************************
 set_user_info_pw
 ********************************************************************/

static bool set_user_info_pw(uint8 *pass, struct samu *pwd,
			     int level)
{
	uint32 len = 0;
	char *plaintext_buf = NULL;
	uint32 acct_ctrl;
	time_t last_set_time;
	enum pdb_value_state last_set_state;

	DEBUG(5, ("Attempting administrator password change for user %s\n",
		  pdb_get_username(pwd)));

	acct_ctrl = pdb_get_acct_ctrl(pwd);
	/* we need to know if it's expired, because this is an admin change, not a
	   user change, so it's still expired when we're done */
	last_set_state = pdb_get_init_flags(pwd, PDB_PASSLASTSET);
	last_set_time = pdb_get_pass_last_set_time(pwd);

	if (!decode_pw_buffer(talloc_tos(),
				pass,
				&plaintext_buf,
				&len,
				STR_UNICODE)) {
		TALLOC_FREE(pwd);
		return False;
 	}

	if (!pdb_set_plaintext_passwd (pwd, plaintext_buf)) {
		TALLOC_FREE(pwd);
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
			struct passwd *passwd;

			if (pdb_get_username(pwd) == NULL) {
				DEBUG(1, ("chgpasswd: User without name???\n"));
				TALLOC_FREE(pwd);
				return False;
			}

			passwd = Get_Pwnam_alloc(pwd, pdb_get_username(pwd));
			if (passwd == NULL) {
				DEBUG(1, ("chgpasswd: Username does not exist in system !?!\n"));
			}

			if(!chgpasswd(pdb_get_username(pwd), passwd, "", plaintext_buf, True)) {
				TALLOC_FREE(pwd);
				return False;
			}
			TALLOC_FREE(passwd);
		}
	}

	memset(plaintext_buf, '\0', strlen(plaintext_buf));

	/*
	 * A level 25 change does reset the pwdlastset field, a level 24
	 * change does not. I know this is probably not the full story, but
	 * it is needed to make XP join LDAP correctly, without it the later
	 * auth2 check can fail with PWD_MUST_CHANGE.
	 */
	if (level != 25) {
		/*
		 * restore last set time as this is an admin change, not a
		 * user pw change
		 */
		pdb_set_pass_last_set_time (pwd, last_set_time,
					    last_set_state);
	}

	DEBUG(5,("set_user_info_pw: pdb_update_pwd()\n"));

	/* update the SAMBA password */
	if(!NT_STATUS_IS_OK(pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return False;
 	}

	TALLOC_FREE(pwd);

	return True;
}

/*******************************************************************
 set_user_info_25
 ********************************************************************/

static NTSTATUS set_user_info_25(TALLOC_CTX *mem_ctx,
				 struct samr_UserInfo25 *id25,
				 struct samu *pwd)
{
	NTSTATUS status;

	if (id25 == NULL) {
		DEBUG(5, ("set_user_info_25: NULL id25\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	copy_id25_to_sam_passwd(pwd, id25);

	/* write the change out */
	if(!NT_STATUS_IS_OK(status = pdb_update_sam_account(pwd))) {
		TALLOC_FREE(pwd);
		return status;
 	}

	/*
	 * We need to "pdb_update_sam_account" before the unix primary group
	 * is set, because the idealx scripts would also change the
	 * sambaPrimaryGroupSid using the ldap replace method. pdb_ldap uses
	 * the delete explicit / add explicit, which would then fail to find
	 * the previous primaryGroupSid value.
	 */

	if ( IS_SAM_CHANGED(pwd, PDB_GROUPSID) ) {
		status = pdb_set_unix_primary_group(mem_ctx, pwd);
		if ( !NT_STATUS_IS_OK(status) ) {
			return status;
		}
	}

	/* WARNING: No TALLOC_FREE(pwd), we are about to set the password
	 * hereafter! */

	return NT_STATUS_OK;
}

/*******************************************************************
 samr_SetUserInfo
 ********************************************************************/

NTSTATUS _samr_SetUserInfo(pipes_struct *p,
			   struct samr_SetUserInfo *r)
{
	NTSTATUS status;
	struct samu *pwd = NULL;
	DOM_SID sid;
	POLICY_HND *pol = r->in.user_handle;
	union samr_UserInfo *info = r->in.info;
	uint16_t switch_value = r->in.level;
	uint32_t acc_granted;
	uint32_t acc_required;
	bool ret;
	bool has_enough_rights = False;
	uint32_t acb_info;
	DISP_INFO *disp_info = NULL;

	DEBUG(5,("_samr_SetUserInfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, pol, &sid, &acc_granted, &disp_info)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* This is tricky.  A WinXP domain join sets
	  (SA_RIGHT_USER_SET_PASSWORD|SA_RIGHT_USER_SET_ATTRIBUTES|SA_RIGHT_USER_ACCT_FLAGS_EXPIRY)
	  The MMC lusrmgr plugin includes these perms and more in the SamrOpenUser().  But the
	  standard Win32 API calls just ask for SA_RIGHT_USER_SET_PASSWORD in the SamrOpenUser().
	  This should be enough for levels 18, 24, 25,& 26.  Info level 23 can set more so
	  we'll use the set from the WinXP join as the basis. */

	switch (switch_value) {
	case 18:
	case 24:
	case 25:
	case 26:
		acc_required = SA_RIGHT_USER_SET_PASSWORD;
		break;
	default:
		acc_required = SA_RIGHT_USER_SET_PASSWORD |
			       SA_RIGHT_USER_SET_ATTRIBUTES |
			       SA_RIGHT_USER_ACCT_FLAGS_EXPIRY;
		break;
	}

	status = access_check_samr_function(acc_granted,
					    acc_required,
					    "_samr_SetUserInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(5, ("_samr_SetUserInfo: sid:%s, level:%d\n",
		  sid_string_dbg(&sid), switch_value));

	if (info == NULL) {
		DEBUG(5, ("_samr_SetUserInfo: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (!(pwd = samu_new(NULL))) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(pwd, &sid);
	unbecome_root();

	if (!ret) {
		TALLOC_FREE(pwd);
		return NT_STATUS_NO_SUCH_USER;
 	}

	/* deal with machine password changes differently from userinfo changes */
	/* check to see if we have the sufficient rights */

	acb_info = pdb_get_acct_ctrl(pwd);
	if (acb_info & ACB_WSTRUST)
		has_enough_rights = user_has_privileges(p->pipe_user.nt_user_token,
							&se_machine_account);
	else if (acb_info & ACB_NORMAL)
		has_enough_rights = user_has_privileges(p->pipe_user.nt_user_token,
							&se_add_users);
	else if (acb_info & (ACB_SVRTRUST|ACB_DOMTRUST)) {
		if (lp_enable_privileges()) {
			has_enough_rights = nt_token_check_domain_rid(p->pipe_user.nt_user_token,
								      DOMAIN_GROUP_RID_ADMINS);
		}
	}

	DEBUG(5, ("_samr_SetUserInfo: %s does%s possess sufficient rights\n",
		  uidtoname(p->pipe_user.ut.uid),
		  has_enough_rights ? "" : " not"));

	/* ================ BEGIN SeMachineAccountPrivilege BLOCK ================ */

	if (has_enough_rights) {
		become_root();
	}

	/* ok!  user info levels (lots: see MSDEV help), off we go... */

	switch (switch_value) {

		case 7:
			status = set_user_info_7(p->mem_ctx,
						 &info->info7, pwd);
			break;

		case 16:
			if (!set_user_info_16(&info->info16, pwd)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		case 18:
			/* Used by AS/U JRA. */
			if (!set_user_info_18(&info->info18, pwd)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		case 20:
			if (!set_user_info_20(&info->info20, pwd)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		case 21:
			status = set_user_info_21(p->mem_ctx,
						  &info->info21, pwd);
			break;

		case 23:
			if (!p->session_key.length) {
				status = NT_STATUS_NO_USER_SESSION_KEY;
			}
			SamOEMhashBlob(info->info23.password.data, 516,
				       &p->session_key);

			dump_data(100, info->info23.password.data, 516);

			status = set_user_info_23(p->mem_ctx,
						  &info->info23, pwd);
			break;

		case 24:
			if (!p->session_key.length) {
				status = NT_STATUS_NO_USER_SESSION_KEY;
			}
			SamOEMhashBlob(info->info24.password.data,
				       516,
				       &p->session_key);

			dump_data(100, info->info24.password.data, 516);

			if (!set_user_info_pw(info->info24.password.data, pwd,
					      switch_value)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		case 25:
			if (!p->session_key.length) {
				status = NT_STATUS_NO_USER_SESSION_KEY;
			}
			encode_or_decode_arc4_passwd_buffer(info->info25.password.data,
							    &p->session_key);

			dump_data(100, info->info25.password.data, 532);

			status = set_user_info_25(p->mem_ctx,
						  &info->info25, pwd);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
			if (!set_user_info_pw(info->info25.password.data, pwd,
					      switch_value)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		case 26:
			if (!p->session_key.length) {
				status = NT_STATUS_NO_USER_SESSION_KEY;
			}
			encode_or_decode_arc4_passwd_buffer(info->info26.password.data,
							    &p->session_key);

			dump_data(100, info->info26.password.data, 516);

			if (!set_user_info_pw(info->info26.password.data, pwd,
					      switch_value)) {
				status = NT_STATUS_ACCESS_DENIED;
			}
			break;

		default:
			status = NT_STATUS_INVALID_INFO_CLASS;
	}

 done:

	if (has_enough_rights) {
		unbecome_root();
	}

	/* ================ END SeMachineAccountPrivilege BLOCK ================ */

	if (NT_STATUS_IS_OK(status)) {
		force_flush_samr_cache(disp_info);
	}

	return status;
}

/*******************************************************************
 _samr_SetUserInfo2
 ********************************************************************/

NTSTATUS _samr_SetUserInfo2(pipes_struct *p,
			    struct samr_SetUserInfo2 *r)
{
	struct samr_SetUserInfo q;

	q.in.user_handle	= r->in.user_handle;
	q.in.level		= r->in.level;
	q.in.info		= r->in.info;

	return _samr_SetUserInfo(p, &q);
}

/*********************************************************************
 _samr_GetAliasMembership
*********************************************************************/

NTSTATUS _samr_GetAliasMembership(pipes_struct *p,
				  struct samr_GetAliasMembership *r)
{
	size_t num_alias_rids;
	uint32 *alias_rids;
	struct samr_info *info = NULL;
	size_t i;

	NTSTATUS ntstatus1;
	NTSTATUS ntstatus2;

	DOM_SID *members;

	DEBUG(5,("_samr_GetAliasMembership: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	ntstatus1 = access_check_samr_function(info->acc_granted,
					       SA_RIGHT_DOMAIN_LOOKUP_ALIAS_BY_MEM,
					       "_samr_GetAliasMembership");
	ntstatus2 = access_check_samr_function(info->acc_granted,
					       SA_RIGHT_DOMAIN_OPEN_ACCOUNT,
					       "_samr_GetAliasMembership");

	if (!NT_STATUS_IS_OK(ntstatus1) || !NT_STATUS_IS_OK(ntstatus2)) {
		if (!(NT_STATUS_EQUAL(ntstatus1,NT_STATUS_ACCESS_DENIED) && NT_STATUS_IS_OK(ntstatus2)) &&
		    !(NT_STATUS_EQUAL(ntstatus1,NT_STATUS_ACCESS_DENIED) && NT_STATUS_IS_OK(ntstatus1))) {
			return (NT_STATUS_IS_OK(ntstatus1)) ? ntstatus2 : ntstatus1;
		}
	}

	if (!sid_check_is_domain(&info->sid) &&
	    !sid_check_is_builtin(&info->sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	if (r->in.sids->num_sids) {
		members = TALLOC_ARRAY(p->mem_ctx, DOM_SID, r->in.sids->num_sids);

		if (members == NULL)
			return NT_STATUS_NO_MEMORY;
	} else {
		members = NULL;
	}

	for (i=0; i<r->in.sids->num_sids; i++)
		sid_copy(&members[i], r->in.sids->sids[i].sid);

	alias_rids = NULL;
	num_alias_rids = 0;

	become_root();
	ntstatus1 = pdb_enum_alias_memberships(p->mem_ctx, &info->sid, members,
					       r->in.sids->num_sids,
					       &alias_rids, &num_alias_rids);
	unbecome_root();

	if (!NT_STATUS_IS_OK(ntstatus1)) {
		return ntstatus1;
	}

	r->out.rids->count = num_alias_rids;
	r->out.rids->ids = alias_rids;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_GetMembersInAlias
*********************************************************************/

NTSTATUS _samr_GetMembersInAlias(pipes_struct *p,
				 struct samr_GetMembersInAlias *r)
{
	NTSTATUS status;
	size_t i;
	size_t num_sids = 0;
	struct lsa_SidPtr *sids = NULL;
	DOM_SID *pdb_sids = NULL;

	DOM_SID alias_sid;

	uint32 acc_granted;

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &alias_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_ALIAS_GET_MEMBERS,
					    "_samr_GetMembersInAlias");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&alias_sid)));

	become_root();
	status = pdb_enum_aliasmem(&alias_sid, &pdb_sids, &num_sids);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (num_sids) {
		sids = TALLOC_ZERO_ARRAY(p->mem_ctx, struct lsa_SidPtr, num_sids);
		if (sids == NULL) {
			TALLOC_FREE(pdb_sids);
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (i = 0; i < num_sids; i++) {
		sids[i].sid = sid_dup_talloc(p->mem_ctx, &pdb_sids[i]);
		if (!sids[i].sid) {
			TALLOC_FREE(pdb_sids);
			return NT_STATUS_NO_MEMORY;
		}
	}

	r->out.sids->num_sids = num_sids;
	r->out.sids->sids = sids;

	TALLOC_FREE(pdb_sids);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_QueryGroupMember
*********************************************************************/

NTSTATUS _samr_QueryGroupMember(pipes_struct *p,
				struct samr_QueryGroupMember *r)
{
	DOM_SID group_sid;
	size_t i, num_members;

	uint32 *rid=NULL;
	uint32 *attr=NULL;

	uint32 acc_granted;

	NTSTATUS status;
	struct samr_RidTypeArray *rids = NULL;

	rids = TALLOC_ZERO_P(p->mem_ctx, struct samr_RidTypeArray);
	if (!rids) {
		return NT_STATUS_NO_MEMORY;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_GROUP_GET_MEMBERS,
					    "_samr_QueryGroupMember");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&group_sid)));

	if (!sid_check_is_in_our_domain(&group_sid)) {
		DEBUG(3, ("sid %s is not in our domain\n",
			  sid_string_dbg(&group_sid)));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	DEBUG(10, ("lookup on Domain SID\n"));

	become_root();
	status = pdb_enum_group_members(p->mem_ctx, &group_sid,
					&rid, &num_members);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status))
		return status;

	if (num_members) {
		attr=TALLOC_ZERO_ARRAY(p->mem_ctx, uint32, num_members);
		if (attr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		attr = NULL;
	}

	for (i=0; i<num_members; i++)
		attr[i] = SID_NAME_USER;

	rids->count = num_members;
	rids->types = attr;
	rids->rids = rid;

	*r->out.rids = rids;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_AddAliasMember
*********************************************************************/

NTSTATUS _samr_AddAliasMember(pipes_struct *p,
			      struct samr_AddAliasMember *r)
{
	DOM_SID alias_sid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	NTSTATUS status;
	DISP_INFO *disp_info = NULL;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &alias_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_ALIAS_ADD_MEMBER,
					    "_samr_AddAliasMember");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&alias_sid)));

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_add_aliasmem(&alias_sid, r->in.sid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if (NT_STATUS_IS_OK(status)) {
		force_flush_samr_cache(disp_info);
	}

	return status;
}

/*********************************************************************
 _samr_DeleteAliasMember
*********************************************************************/

NTSTATUS _samr_DeleteAliasMember(pipes_struct *p,
				 struct samr_DeleteAliasMember *r)
{
	DOM_SID alias_sid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	NTSTATUS status;
	DISP_INFO *disp_info = NULL;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &alias_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_ALIAS_REMOVE_MEMBER,
					    "_samr_DeleteAliasMember");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("_samr_del_aliasmem:sid is %s\n",
		   sid_string_dbg(&alias_sid)));

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_del_aliasmem(&alias_sid, r->in.sid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if (NT_STATUS_IS_OK(status)) {
		force_flush_samr_cache(disp_info);
	}

	return status;
}

/*********************************************************************
 _samr_AddGroupMember
*********************************************************************/

NTSTATUS _samr_AddGroupMember(pipes_struct *p,
			      struct samr_AddGroupMember *r)
{
	NTSTATUS status;
	DOM_SID group_sid;
	uint32 group_rid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	DISP_INFO *disp_info = NULL;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_GROUP_ADD_MEMBER,
					    "_samr_AddGroupMember");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&group_sid)));

	if (!sid_peek_check_rid(get_global_sam_sid(), &group_sid,
				&group_rid)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_add_groupmem(p->mem_ctx, group_rid, r->in.rid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	force_flush_samr_cache(disp_info);

	return status;
}

/*********************************************************************
 _samr_DeleteGroupMember
*********************************************************************/

NTSTATUS _samr_DeleteGroupMember(pipes_struct *p,
				 struct samr_DeleteGroupMember *r)

{
	NTSTATUS status;
	DOM_SID group_sid;
	uint32 group_rid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	DISP_INFO *disp_info = NULL;

	/*
	 * delete the group member named r->in.rid
	 * who is a member of the sid associated with the handle
	 * the rid is a user's rid as the group is a domain group.
	 */

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_GROUP_REMOVE_MEMBER,
					    "_samr_DeleteGroupMember");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!sid_peek_check_rid(get_global_sam_sid(), &group_sid,
				&group_rid)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_del_groupmem(p->mem_ctx, group_rid, r->in.rid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	force_flush_samr_cache(disp_info);

	return status;
}

/*********************************************************************
 _samr_DeleteUser
*********************************************************************/

NTSTATUS _samr_DeleteUser(pipes_struct *p,
			  struct samr_DeleteUser *r)
{
	NTSTATUS status;
	DOM_SID user_sid;
	struct samu *sam_pass=NULL;
	uint32 acc_granted;
	bool can_add_accounts;
	uint32 acb_info;
	DISP_INFO *disp_info = NULL;
	bool ret;

	DEBUG(5, ("_samr_DeleteUser: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.user_handle, &user_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    STD_RIGHT_DELETE_ACCESS,
					    "_samr_DeleteUser");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!sid_check_is_in_our_domain(&user_sid))
		return NT_STATUS_CANNOT_DELETE;

	/* check if the user exists before trying to delete */
	if ( !(sam_pass = samu_new( NULL )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	ret = pdb_getsampwsid(sam_pass, &user_sid);
	unbecome_root();

	if( !ret ) {
		DEBUG(5,("_samr_DeleteUser: User %s doesn't exist.\n",
			sid_string_dbg(&user_sid)));
		TALLOC_FREE(sam_pass);
		return NT_STATUS_NO_SUCH_USER;
	}

	acb_info = pdb_get_acct_ctrl(sam_pass);

	/* For machine accounts it's the SeMachineAccountPrivilege that counts. */
	if ( acb_info & ACB_WSTRUST ) {
		can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_machine_account );
	} else {
		can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_add_users );
	}

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_delete_user(p->mem_ctx, sam_pass);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("_samr_DeleteUser: Failed to delete entry for "
			 "user %s: %s.\n", pdb_get_username(sam_pass),
			 nt_errstr(status)));
		TALLOC_FREE(sam_pass);
		return status;
	}


	TALLOC_FREE(sam_pass);

	if (!close_policy_hnd(p, r->in.user_handle))
		return NT_STATUS_OBJECT_NAME_INVALID;

	ZERO_STRUCTP(r->out.user_handle);

	force_flush_samr_cache(disp_info);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_DeleteDomainGroup
*********************************************************************/

NTSTATUS _samr_DeleteDomainGroup(pipes_struct *p,
				 struct samr_DeleteDomainGroup *r)
{
	NTSTATUS status;
	DOM_SID group_sid;
	uint32 group_rid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	DISP_INFO *disp_info = NULL;

	DEBUG(5, ("samr_DeleteDomainGroup: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    STD_RIGHT_DELETE_ACCESS,
					    "_samr_DeleteDomainGroup");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&group_sid)));

	if (!sid_peek_check_rid(get_global_sam_sid(), &group_sid,
				&group_rid)) {
		return NT_STATUS_NO_SUCH_GROUP;
	}

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	status = pdb_delete_dom_group(p->mem_ctx, group_rid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("_samr_DeleteDomainGroup: Failed to delete mapping "
			 "entry for group %s: %s\n",
			 sid_string_dbg(&group_sid),
			 nt_errstr(status)));
		return status;
	}

	if (!close_policy_hnd(p, r->in.group_handle))
		return NT_STATUS_OBJECT_NAME_INVALID;

	force_flush_samr_cache(disp_info);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_DeleteDomAlias
*********************************************************************/

NTSTATUS _samr_DeleteDomAlias(pipes_struct *p,
			      struct samr_DeleteDomAlias *r)
{
	DOM_SID alias_sid;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	NTSTATUS status;
	DISP_INFO *disp_info = NULL;

	DEBUG(5, ("_samr_DeleteDomAlias: %d\n", __LINE__));

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &alias_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	/* copy the handle to the outgoing reply */

	memcpy(r->out.alias_handle, r->in.alias_handle, sizeof(r->out.alias_handle));

	status = access_check_samr_function(acc_granted,
					    STD_RIGHT_DELETE_ACCESS,
					    "_samr_DeleteDomAlias");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10, ("sid is %s\n", sid_string_dbg(&alias_sid)));

	/* Don't let Windows delete builtin groups */

	if ( sid_check_is_in_builtin( &alias_sid ) ) {
		return NT_STATUS_SPECIAL_ACCOUNT;
	}

	if (!sid_check_is_in_our_domain(&alias_sid))
		return NT_STATUS_NO_SUCH_ALIAS;

	DEBUG(10, ("lookup on Local SID\n"));

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	/* Have passdb delete the alias */
	status = pdb_delete_alias(&alias_sid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if ( !NT_STATUS_IS_OK(status))
		return status;

	if (!close_policy_hnd(p, r->in.alias_handle))
		return NT_STATUS_OBJECT_NAME_INVALID;

	force_flush_samr_cache(disp_info);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_CreateDomainGroup
*********************************************************************/

NTSTATUS _samr_CreateDomainGroup(pipes_struct *p,
				 struct samr_CreateDomainGroup *r)

{
	NTSTATUS status;
	DOM_SID dom_sid;
	DOM_SID info_sid;
	const char *name;
	struct samr_info *info;
	uint32 acc_granted;
	SE_PRIV se_rights;
	bool can_add_accounts;
	DISP_INFO *disp_info = NULL;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &dom_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_DOMAIN_CREATE_GROUP,
					    "_samr_CreateDomainGroup");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!sid_equal(&dom_sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	name = r->in.name->string;
	if (name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = can_create(p->mem_ctx, name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	/* check that we successfully create the UNIX group */

	status = pdb_create_dom_group(p->mem_ctx, name, r->out.rid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	/* check if we should bail out here */

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	sid_compose(&info_sid, get_global_sam_sid(), *r->out.rid);

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* they created it; let the user do what he wants with it */

	info->acc_granted = GENERIC_RIGHTS_GROUP_ALL_ACCESS;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.group_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	force_flush_samr_cache(disp_info);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_CreateDomAlias
*********************************************************************/

NTSTATUS _samr_CreateDomAlias(pipes_struct *p,
			      struct samr_CreateDomAlias *r)
{
	DOM_SID dom_sid;
	DOM_SID info_sid;
	const char *name = NULL;
	struct samr_info *info;
	uint32 acc_granted;
	gid_t gid;
	NTSTATUS result;
	SE_PRIV se_rights;
	bool can_add_accounts;
	DISP_INFO *disp_info = NULL;

	/* Find the policy handle. Open a policy on it. */
	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &dom_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	result = access_check_samr_function(acc_granted,
					    SA_RIGHT_DOMAIN_CREATE_ALIAS,
					    "_samr_CreateDomAlias");
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (!sid_equal(&dom_sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	name = r->in.alias_name->string;

	se_priv_copy( &se_rights, &se_add_users );
	can_add_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_rights );

	result = can_create(p->mem_ctx, name);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_add_accounts )
		become_root();

	/* Have passdb create the alias */
	result = pdb_create_alias(name, r->out.rid);

	if ( can_add_accounts )
		unbecome_root();

	/******** END SeAddUsers BLOCK *********/

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10, ("pdb_create_alias failed: %s\n",
			   nt_errstr(result)));
		return result;
	}

	sid_copy(&info_sid, get_global_sam_sid());
	sid_append_rid(&info_sid, *r->out.rid);

	if (!sid_to_gid(&info_sid, &gid)) {
		DEBUG(10, ("Could not find alias just created\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* check if the group has been successfully created */
	if ( getgrgid(gid) == NULL ) {
		DEBUG(10, ("getgrgid(%d) of just created alias failed\n",
			   gid));
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	/* they created it; let the user do what he wants with it */

	info->acc_granted = GENERIC_RIGHTS_ALIAS_ALL_ACCESS;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.alias_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	force_flush_samr_cache(disp_info);

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_QueryGroupInfo
*********************************************************************/

NTSTATUS _samr_QueryGroupInfo(pipes_struct *p,
			      struct samr_QueryGroupInfo *r)
{
	NTSTATUS status;
	DOM_SID group_sid;
	GROUP_MAP map;
	union samr_GroupInfo *info = NULL;
	uint32 acc_granted;
	bool ret;
	uint32_t attributes = SE_GROUP_MANDATORY |
			      SE_GROUP_ENABLED_BY_DEFAULT |
			      SE_GROUP_ENABLED;
	const char *group_name = NULL;
	const char *group_description = NULL;

	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_GROUP_LOOKUP_INFO,
					    "_samr_QueryGroupInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	become_root();
	ret = get_domain_group_from_sid(group_sid, &map);
	unbecome_root();
	if (!ret)
		return NT_STATUS_INVALID_HANDLE;

	/* FIXME: map contains fstrings */
	group_name = talloc_strdup(r, map.nt_name);
	group_description = talloc_strdup(r, map.comment);

	info = TALLOC_ZERO_P(p->mem_ctx, union samr_GroupInfo);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
		case 1: {
			uint32 *members;
			size_t num_members;

			become_root();
			status = pdb_enum_group_members(
				p->mem_ctx, &group_sid, &members, &num_members);
			unbecome_root();

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			init_samr_group_info1(&info->all,
					      group_name,
					      attributes,
					      num_members,
					      group_description);
			break;
		}
		case 2:
			init_samr_group_info2(&info->name,
					      group_name);
			break;
		case 3:
			init_samr_group_info3(&info->attributes,
					      attributes);
			break;
		case 4:
			init_samr_group_info4(&info->description,
					      group_description);
			break;
		case 5: {
			/*
			uint32 *members;
			size_t num_members;
			*/

			/*
			become_root();
			status = pdb_enum_group_members(
				p->mem_ctx, &group_sid, &members, &num_members);
			unbecome_root();

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			*/
			init_samr_group_info5(&info->all2,
					      group_name,
					      attributes,
					      0, /* num_members - in w2k3 this is always 0 */
					      group_description);

			break;
		}
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	*r->out.info = info;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_SetGroupInfo
*********************************************************************/

NTSTATUS _samr_SetGroupInfo(pipes_struct *p,
			    struct samr_SetGroupInfo *r)
{
	DOM_SID group_sid;
	GROUP_MAP map;
	uint32 acc_granted;
	NTSTATUS status;
	bool ret;
	bool can_mod_accounts;
	DISP_INFO *disp_info = NULL;

	if (!get_lsa_policy_samr_sid(p, r->in.group_handle, &group_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_GROUP_SET_INFO,
					    "_samr_SetGroupInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	become_root();
	ret = get_domain_group_from_sid(group_sid, &map);
	unbecome_root();
	if (!ret)
		return NT_STATUS_NO_SUCH_GROUP;

	switch (r->in.level) {
		case 1:
			fstrcpy(map.comment, r->in.info->all.description.string);
			break;
		case 4:
			fstrcpy(map.comment, r->in.info->description.string);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	can_mod_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_add_users );

	/******** BEGIN SeAddUsers BLOCK *********/

	if ( can_mod_accounts )
		become_root();

	status = pdb_update_group_mapping_entry(&map);

	if ( can_mod_accounts )
		unbecome_root();

	/******** End SeAddUsers BLOCK *********/

	if (NT_STATUS_IS_OK(status)) {
		force_flush_samr_cache(disp_info);
	}

	return status;
}

/*********************************************************************
 _samr_SetAliasInfo
*********************************************************************/

NTSTATUS _samr_SetAliasInfo(pipes_struct *p,
			    struct samr_SetAliasInfo *r)
{
	DOM_SID group_sid;
	struct acct_info info;
	uint32 acc_granted;
	bool can_mod_accounts;
	NTSTATUS status;
	DISP_INFO *disp_info = NULL;

	if (!get_lsa_policy_samr_sid(p, r->in.alias_handle, &group_sid, &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_ALIAS_SET_INFO,
					    "_samr_SetAliasInfo");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* get the current group information */

	become_root();
	status = pdb_get_aliasinfo( &group_sid, &info );
	unbecome_root();

	if ( !NT_STATUS_IS_OK(status))
		return status;

	switch (r->in.level) {
		case ALIASINFONAME:
		{
			fstring group_name;

			/* We currently do not support renaming groups in the
			   the BUILTIN domain.  Refer to util_builtin.c to understand
			   why.  The eventually needs to be fixed to be like Windows
			   where you can rename builtin groups, just not delete them */

			if ( sid_check_is_in_builtin( &group_sid ) ) {
				return NT_STATUS_SPECIAL_ACCOUNT;
			}

			/* There has to be a valid name (and it has to be different) */

			if ( !r->in.info->name.string )
				return NT_STATUS_INVALID_PARAMETER;

			/* If the name is the same just reply "ok".  Yes this
			   doesn't allow you to change the case of a group name. */

			if ( strequal( r->in.info->name.string, info.acct_name ) )
				return NT_STATUS_OK;

			fstrcpy( info.acct_name, r->in.info->name.string);

			/* make sure the name doesn't already exist as a user
			   or local group */

			fstr_sprintf( group_name, "%s\\%s", global_myname(), info.acct_name );
			status = can_create( p->mem_ctx, group_name );
			if ( !NT_STATUS_IS_OK( status ) )
				return status;
			break;
		}
		case ALIASINFODESCRIPTION:
			if (r->in.info->description.string) {
				fstrcpy(info.acct_desc,
					r->in.info->description.string);
			} else {
				fstrcpy( info.acct_desc, "" );
			}
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

        can_mod_accounts = user_has_privileges( p->pipe_user.nt_user_token, &se_add_users );

        /******** BEGIN SeAddUsers BLOCK *********/

        if ( can_mod_accounts )
                become_root();

        status = pdb_set_aliasinfo( &group_sid, &info );

        if ( can_mod_accounts )
                unbecome_root();

        /******** End SeAddUsers BLOCK *********/

	if (NT_STATUS_IS_OK(status))
		force_flush_samr_cache(disp_info);

	return status;
}

/****************************************************************
 _samr_GetDomPwInfo
****************************************************************/

NTSTATUS _samr_GetDomPwInfo(pipes_struct *p,
			    struct samr_GetDomPwInfo *r)
{
	uint32_t min_password_length = 0;
	uint32_t password_properties = 0;

	/* Perform access check.  Since this rpc does not require a
	   policy handle it will not be caught by the access checks on
	   SAMR_CONNECT or SAMR_CONNECT_ANON. */

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to _samr_GetDomPwInfo\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	become_root();
	pdb_get_account_policy(AP_MIN_PASSWORD_LEN,
			       &min_password_length);
	pdb_get_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS,
			       &password_properties);
	unbecome_root();

	if (lp_check_password_script() && *lp_check_password_script()) {
		password_properties |= DOMAIN_PASSWORD_COMPLEX;
	}

	r->out.info->min_password_length = min_password_length;
	r->out.info->password_properties = password_properties;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_OpenGroup
*********************************************************************/

NTSTATUS _samr_OpenGroup(pipes_struct *p,
			 struct samr_OpenGroup *r)

{
	DOM_SID sid;
	DOM_SID info_sid;
	GROUP_MAP map;
	struct samr_info *info;
	SEC_DESC         *psd = NULL;
	uint32            acc_granted;
	uint32            des_access = r->in.access_mask;
	size_t            sd_size;
	NTSTATUS          status;
	fstring sid_string;
	bool ret;
	SE_PRIV se_rights;

	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &sid, &acc_granted, NULL))
		return NT_STATUS_INVALID_HANDLE;

	status = access_check_samr_function(acc_granted,
					    SA_RIGHT_DOMAIN_OPEN_ACCOUNT,
					    "_samr_OpenGroup");

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/*check if access can be granted as requested by client. */
	map_max_allowed_access(p->pipe_user.nt_user_token, &des_access);

	make_samr_object_sd(p->mem_ctx, &psd, &sd_size, &grp_generic_mapping, NULL, 0);
	se_map_generic(&des_access,&grp_generic_mapping);

	se_priv_copy( &se_rights, &se_add_users );

	status = access_check_samr_object(psd, p->pipe_user.nt_user_token,
		&se_rights, GENERIC_RIGHTS_GROUP_WRITE, des_access,
		&acc_granted, "_samr_OpenGroup");

	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/* this should not be hard-coded like this */

	if (!sid_equal(&sid, get_global_sam_sid()))
		return NT_STATUS_ACCESS_DENIED;

	sid_copy(&info_sid, get_global_sam_sid());
	sid_append_rid(&info_sid, r->in.rid);
	sid_to_fstring(sid_string, &info_sid);

	if ((info = get_samr_info_by_sid(&info_sid)) == NULL)
		return NT_STATUS_NO_MEMORY;

	info->acc_granted = acc_granted;

	DEBUG(10, ("_samr_OpenGroup:Opening SID: %s\n", sid_string));

	/* check if that group really exists */
	become_root();
	ret = get_domain_group_from_sid(info->sid, &map);
	unbecome_root();
	if (!ret)
		return NT_STATUS_NO_SUCH_GROUP;

	/* get a (unique) handle.  open a policy on it. */
	if (!create_policy_hnd(p, r->out.group_handle, free_samr_info, (void *)info))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*********************************************************************
 _samr_RemoveMemberFromForeignDomain
*********************************************************************/

NTSTATUS _samr_RemoveMemberFromForeignDomain(pipes_struct *p,
					     struct samr_RemoveMemberFromForeignDomain *r)
{
	DOM_SID			delete_sid, domain_sid;
	uint32 			acc_granted;
	NTSTATUS		result;
	DISP_INFO *disp_info = NULL;

	sid_copy( &delete_sid, r->in.sid );

	DEBUG(5,("_samr_RemoveMemberFromForeignDomain: removing SID [%s]\n",
		sid_string_dbg(&delete_sid)));

	/* Find the policy handle. Open a policy on it. */

	if (!get_lsa_policy_samr_sid(p, r->in.domain_handle, &domain_sid,
				     &acc_granted, &disp_info))
		return NT_STATUS_INVALID_HANDLE;

	result = access_check_samr_function(acc_granted,
					    STD_RIGHT_DELETE_ACCESS,
					    "_samr_RemoveMemberFromForeignDomain");

	if (!NT_STATUS_IS_OK(result))
		return result;

	DEBUG(8, ("_samr_RemoveMemberFromForeignDomain: sid is %s\n",
		  sid_string_dbg(&domain_sid)));

	/* we can only delete a user from a group since we don't have
	   nested groups anyways.  So in the latter case, just say OK */

	/* TODO: The above comment nowadays is bogus. Since we have nested
	 * groups now, and aliases members are never reported out of the unix
	 * group membership, the "just say OK" makes this call a no-op. For
	 * us. This needs fixing however. */

	/* I've only ever seen this in the wild when deleting a user from
	 * usrmgr.exe. domain_sid is the builtin domain, and the sid to delete
	 * is the user about to be deleted. I very much suspect this is the
	 * only application of this call. To verify this, let people report
	 * other cases. */

	if (!sid_check_is_builtin(&domain_sid)) {
		DEBUG(1,("_samr_RemoveMemberFromForeignDomain: domain_sid = %s, "
			 "global_sam_sid() = %s\n",
			 sid_string_dbg(&domain_sid),
			 sid_string_dbg(get_global_sam_sid())));
		DEBUGADD(1,("please report to samba-technical@samba.org!\n"));
		return NT_STATUS_OK;
	}

	force_flush_samr_cache(disp_info);

	result = NT_STATUS_OK;

	return result;
}

/*******************************************************************
 _samr_QueryDomainInfo2
 ********************************************************************/

NTSTATUS _samr_QueryDomainInfo2(pipes_struct *p,
				struct samr_QueryDomainInfo2 *r)
{
	struct samr_QueryDomainInfo q;

	q.in.domain_handle	= r->in.domain_handle;
	q.in.level		= r->in.level;

	q.out.info		= r->out.info;

	return _samr_QueryDomainInfo(p, &q);
}

/*******************************************************************
 _samr_SetDomainInfo
 ********************************************************************/

NTSTATUS _samr_SetDomainInfo(pipes_struct *p,
			     struct samr_SetDomainInfo *r)
{
	struct samr_info *info = NULL;
	time_t u_expire, u_min_age;
	time_t u_logout;
	time_t u_lock_duration, u_reset_time;
	NTSTATUS result;

	DEBUG(5,("_samr_SetDomainInfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info))
		return NT_STATUS_INVALID_HANDLE;

	/* We do have different access bits for info
	 * levels here, but we're really just looking for
	 * GENERIC_RIGHTS_DOMAIN_WRITE access. Unfortunately
	 * this maps to different specific bits. So
	 * assume if we have SA_RIGHT_DOMAIN_SET_INFO_1
	 * set we are ok. */

	result = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_SET_INFO_1,
					    "_samr_SetDomainInfo");

	if (!NT_STATUS_IS_OK(result))
		return result;

	DEBUG(5,("_samr_SetDomainInfo: level: %d\n", r->in.level));

	switch (r->in.level) {
        	case 0x01:
			u_expire=nt_time_to_unix_abs((NTTIME *)&r->in.info->info1.max_password_age);
			u_min_age=nt_time_to_unix_abs((NTTIME *)&r->in.info->info1.min_password_age);
			pdb_set_account_policy(AP_MIN_PASSWORD_LEN, (uint32)r->in.info->info1.min_password_length);
			pdb_set_account_policy(AP_PASSWORD_HISTORY, (uint32)r->in.info->info1.password_history_length);
			pdb_set_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS, (uint32)r->in.info->info1.password_properties);
			pdb_set_account_policy(AP_MAX_PASSWORD_AGE, (int)u_expire);
			pdb_set_account_policy(AP_MIN_PASSWORD_AGE, (int)u_min_age);
            		break;
        	case 0x02:
			break;
		case 0x03:
			u_logout=nt_time_to_unix_abs((NTTIME *)&r->in.info->info3.force_logoff_time);
			pdb_set_account_policy(AP_TIME_TO_LOGOUT, (int)u_logout);
			break;
		case 0x05:
			break;
		case 0x06:
			break;
		case 0x07:
			break;
		case 0x0c:
			u_lock_duration=nt_time_to_unix_abs((NTTIME *)&r->in.info->info12.lockout_duration);
			if (u_lock_duration != -1)
				u_lock_duration /= 60;

			u_reset_time=nt_time_to_unix_abs((NTTIME *)&r->in.info->info12.lockout_window)/60;

			pdb_set_account_policy(AP_LOCK_ACCOUNT_DURATION, (int)u_lock_duration);
			pdb_set_account_policy(AP_RESET_COUNT_TIME, (int)u_reset_time);
			pdb_set_account_policy(AP_BAD_ATTEMPT_LOCKOUT, (uint32)r->in.info->info12.lockout_threshold);
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	DEBUG(5,("_samr_SetDomainInfo: %d\n", __LINE__));

	return NT_STATUS_OK;
}

/****************************************************************
 _samr_GetDisplayEnumerationIndex
****************************************************************/

NTSTATUS _samr_GetDisplayEnumerationIndex(pipes_struct *p,
					  struct samr_GetDisplayEnumerationIndex *r)
{
	struct samr_info *info = NULL;
	uint32_t max_entries = (uint32_t) -1;
	uint32_t enum_context = 0;
	int i;
	uint32_t num_account = 0;
	struct samr_displayentry *entries = NULL;
	NTSTATUS status;

	DEBUG(5,("_samr_GetDisplayEnumerationIndex: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!find_policy_by_hnd(p, r->in.domain_handle, (void **)(void *)&info)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	status = access_check_samr_function(info->acc_granted,
					    SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
					    "_samr_GetDisplayEnumerationIndex");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((r->in.level < 1) || (r->in.level > 3)) {
		DEBUG(0,("_samr_GetDisplayEnumerationIndex: "
			"Unknown info level (%u)\n",
			r->in.level));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	become_root();

	/* The following done as ROOT. Don't return without unbecome_root(). */

	switch (r->in.level) {
	case 1:
		if (info->disp_info->users == NULL) {
			info->disp_info->users = pdb_search_users(ACB_NORMAL);
			if (info->disp_info->users == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"starting user enumeration at index %u\n",
				(unsigned int)enum_context));
		} else {
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"using cached user enumeration at index %u\n",
				(unsigned int)enum_context));
		}
		num_account = pdb_search_entries(info->disp_info->users,
						 enum_context, max_entries,
						 &entries);
		break;
	case 2:
		if (info->disp_info->machines == NULL) {
			info->disp_info->machines =
				pdb_search_users(ACB_WSTRUST|ACB_SVRTRUST);
			if (info->disp_info->machines == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"starting machine enumeration at index %u\n",
				(unsigned int)enum_context));
		} else {
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"using cached machine enumeration at index %u\n",
				(unsigned int)enum_context));
		}
		num_account = pdb_search_entries(info->disp_info->machines,
						 enum_context, max_entries,
						 &entries);
		break;
	case 3:
		if (info->disp_info->groups == NULL) {
			info->disp_info->groups = pdb_search_groups();
			if (info->disp_info->groups == NULL) {
				unbecome_root();
				return NT_STATUS_ACCESS_DENIED;
			}
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"starting group enumeration at index %u\n",
				(unsigned int)enum_context));
		} else {
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"using cached group enumeration at index %u\n",
				(unsigned int)enum_context));
		}
		num_account = pdb_search_entries(info->disp_info->groups,
						 enum_context, max_entries,
						 &entries);
		break;
	default:
		unbecome_root();
		smb_panic("info class changed");
		break;
	}

	unbecome_root();

	/* Ensure we cache this enumeration. */
	set_disp_info_cache_timeout(info->disp_info, DISP_INFO_CACHE_TIMEOUT);

	DEBUG(10,("_samr_GetDisplayEnumerationIndex: looking for :%s\n",
		r->in.name->string));

	for (i=0; i<num_account; i++) {
		if (strequal(entries[i].account_name, r->in.name->string)) {
			DEBUG(10,("_samr_GetDisplayEnumerationIndex: "
				"found %s at idx %d\n",
				r->in.name->string, i));
			*r->out.idx = i;
			return NT_STATUS_OK;
		}
	}

	/* assuming account_name lives at the very end */
	*r->out.idx = num_account;

	return NT_STATUS_NO_MORE_ENTRIES;
}

/****************************************************************
 _samr_GetDisplayEnumerationIndex2
****************************************************************/

NTSTATUS _samr_GetDisplayEnumerationIndex2(pipes_struct *p,
					   struct samr_GetDisplayEnumerationIndex2 *r)
{
	struct samr_GetDisplayEnumerationIndex q;

	q.in.domain_handle	= r->in.domain_handle;
	q.in.level		= r->in.level;
	q.in.name		= r->in.name;

	q.out.idx		= r->out.idx;

	return _samr_GetDisplayEnumerationIndex(p, &q);
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_Shutdown(pipes_struct *p,
			struct samr_Shutdown *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_CreateUser(pipes_struct *p,
			  struct samr_CreateUser *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_SetMemberAttributesOfGroup(pipes_struct *p,
					  struct samr_SetMemberAttributesOfGroup *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_ChangePasswordUser(pipes_struct *p,
				  struct samr_ChangePasswordUser *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_TestPrivateFunctionsDomain(pipes_struct *p,
					  struct samr_TestPrivateFunctionsDomain *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_TestPrivateFunctionsUser(pipes_struct *p,
					struct samr_TestPrivateFunctionsUser *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_QueryUserInfo2(pipes_struct *p,
			      struct samr_QueryUserInfo2 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_AddMultipleMembersToAlias(pipes_struct *p,
					 struct samr_AddMultipleMembersToAlias *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_RemoveMultipleMembersFromAlias(pipes_struct *p,
					      struct samr_RemoveMultipleMembersFromAlias *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_OemChangePasswordUser2(pipes_struct *p,
				      struct samr_OemChangePasswordUser2 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_SetBootKeyInformation(pipes_struct *p,
				     struct samr_SetBootKeyInformation *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_GetBootKeyInformation(pipes_struct *p,
				     struct samr_GetBootKeyInformation *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_Connect3(pipes_struct *p,
			struct samr_Connect3 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_RidToSid(pipes_struct *p,
			struct samr_RidToSid *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_SetDsrmPassword(pipes_struct *p,
			       struct samr_SetDsrmPassword *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _samr_ValidatePassword(pipes_struct *p,
				struct samr_ValidatePassword *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}
