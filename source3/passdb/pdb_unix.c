/*
 * Unix password backend for samba
 * Copyright (C) Jelmer Vernooij 2002
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

static NTSTATUS unixsam_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *user, const char *sname)
{
	struct passwd *pass;
	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (!sname) {
		DEBUG(0,("invalid name specified"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	pass = Get_Pwnam(sname);

	return pdb_fill_sam_pw(user, pass);
}


/***************************************************************************
  Search by rid
 **************************************************************************/

static NTSTATUS unixsam_getsampwrid (struct pdb_methods *methods, 
				 SAM_ACCOUNT *user, uint32 rid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct passwd *pass = NULL;
	const char *guest_account = lp_guestaccount();
	if (!(guest_account && *guest_account)) {
		DEBUG(1, ("NULL guest account!?!?\n"));
		return nt_status;
	}

	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return nt_status;
	}
	
	if (rid == DOMAIN_USER_RID_GUEST) {
		pass = getpwnam_alloc(guest_account);
		if (!pass) {
			DEBUG(1, ("guest account %s does not seem to exist...\n", guest_account));
			return nt_status;
		}
	} else if (pdb_rid_is_user(rid)) {
		pass = getpwuid_alloc(fallback_pdb_user_rid_to_uid (rid));
	}

	if (pass == NULL) {
		return nt_status;
	}

	nt_status = pdb_fill_sam_pw(user, pass);
	passwd_free(&pass);

	return nt_status;
}

static NTSTATUS unixsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_UNSUCCESSFUL;
	return unixsam_getsampwrid(my_methods, user, rid);
}

/***************************************************************************
  Adds an existing SAM_ACCOUNT
 ****************************************************************************/

static NTSTATUS unixsam_add_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	DEBUG(0,("pdb_unix should not be listed as the first passdb backend! You can't add users to it.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/***************************************************************************
  Updates a SAM_ACCOUNT

  This isn't a particulary practical option for pdb_unix.  We certainly don't
  want to twidde the filesystem, so what should we do?

  Current plan is to transparently add the account.  It should appear
  as if the pdb_unix version was modified, but its actually stored somehwere.
 ****************************************************************************/

static NTSTATUS unixsam_update_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	return methods->parent->pdb_add_sam_account(methods->parent, newpwd);
}

static NTSTATUS unixsam_delete_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *pwd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_setsampwent(struct pdb_methods *methods, BOOL update)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT *user)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static void unixsam_endsampwent(struct pdb_methods *methods)
{
	return; /* NT_STATUS_NOT_IMPLEMENTED; */
}

static NTSTATUS unixsam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid, BOOL with_priv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid, BOOL with_priv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 char *name, BOOL with_priv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS unixsam_enum_group_mapping(struct pdb_methods *methods,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only, BOOL with_priv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS pdb_init_unixsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	
	if (!pdb_context) {
		DEBUG(0, ("invalid pdb_context specified\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}
	
	(*pdb_method)->name = "unixsam";
	
	(*pdb_method)->setsampwent = unixsam_setsampwent;
	(*pdb_method)->endsampwent = unixsam_endsampwent;
	(*pdb_method)->getsampwent = unixsam_getsampwent;
	(*pdb_method)->getsampwnam = unixsam_getsampwnam;
	(*pdb_method)->getsampwsid = unixsam_getsampwsid;
	(*pdb_method)->add_sam_account = unixsam_add_sam_account;
	(*pdb_method)->update_sam_account = unixsam_update_sam_account;
	(*pdb_method)->delete_sam_account = unixsam_delete_sam_account;
	(*pdb_method)->getgrsid = unixsam_getgrsid;
	(*pdb_method)->getgrgid = unixsam_getgrgid;
	(*pdb_method)->getgrnam = unixsam_getgrnam;
	(*pdb_method)->add_group_mapping_entry = unixsam_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = unixsam_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = unixsam_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = unixsam_enum_group_mapping;
	
	/* There's not very much to initialise here */
	return NT_STATUS_OK;
}
