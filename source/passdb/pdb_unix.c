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

static BOOL unixsam_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *user, const char *sname)
{
	struct passwd *pass;
	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return False;
	}
	if (!sname) {
		DEBUG(0,("invalid name specified"));
		return False;
	}
	pass = Get_Pwnam(sname);

	return NT_STATUS_IS_OK(pdb_fill_sam_pw(user, pass));
}


/***************************************************************************
  Search by rid
 **************************************************************************/

static BOOL unixsam_getsampwrid (struct pdb_methods *methods, 
				 SAM_ACCOUNT *user, uint32 rid)
{
	struct passwd *pass;
	BOOL ret = False;
	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return False;
	}

	if (pdb_rid_is_user(rid)) {
		pass = getpwuid_alloc(fallback_pdb_user_rid_to_uid (rid));
		
		if (pass) {
			ret = NT_STATUS_IS_OK(pdb_fill_sam_pw(user, pass));
			passwd_free(&pass);
		}
	}
	return ret;
}

static BOOL unixsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, DOM_SID *sid)
{
	uint32 rid;
	sid_peek_rid(sid, &rid);
	return unixsam_getsampwrid(my_methods, user, rid);
}

/***************************************************************************
  Adds an existing SAM_ACCOUNT
 ****************************************************************************/

static BOOL unixsam_add_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	DEBUG(0,("pdb_unix should not be listed as the first passdb backend! You can't add users to it.\n"));
	return False;
}

/***************************************************************************
  Updates a SAM_ACCOUNT

  This isn't a particulary practical option for pdb_unix.  We certainly don't
  want to twidde the filesystem, so what should we do?

  Current plan is to transparently add the account.  It should appear
  as if the pdb_unix version was modified, but its actually stored somehwere.
 ****************************************************************************/

static BOOL unixsam_update_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	return methods->parent->pdb_add_sam_account(methods->parent, newpwd);
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
	
	(*pdb_method)->setsampwent = NULL;
	(*pdb_method)->endsampwent = NULL;
	(*pdb_method)->getsampwent = NULL;
	(*pdb_method)->getsampwnam = unixsam_getsampwnam;
	(*pdb_method)->getsampwsid = unixsam_getsampwsid;
	(*pdb_method)->add_sam_account = unixsam_add_sam_account;
	(*pdb_method)->update_sam_account = unixsam_update_sam_account;
	(*pdb_method)->delete_sam_account = NULL;
	
	/* There's not very much to initialise here */
	return NT_STATUS_OK;
}
