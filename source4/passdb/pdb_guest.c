/*
 * 'Guest' password backend for samba
 * Copyright (C) Jelmer Vernooij 2002
 * Copyright (C) Andrew Bartlett 2003
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

static NTSTATUS guestsam_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *user, const char *sname)
{
	NTSTATUS nt_status;
	struct passwd *pass;
	const char *guest_account = lp_guestaccount();
	if (!(guest_account && *guest_account)) {
		DEBUG(1, ("NULL guest account!?!?\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (!sname) {
		DEBUG(0,("invalid name specified"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!strequal(guest_account, sname)) {
		return NT_STATUS_NO_SUCH_USER;
	}
		
	pass = getpwnam_alloc(guest_account);

	nt_status = pdb_fill_sam_pw(user, pass);

	passwd_free(&pass);
	return nt_status;
}


/***************************************************************************
  Search by rid
 **************************************************************************/

static NTSTATUS guestsam_getsampwrid (struct pdb_methods *methods, 
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
			return NT_STATUS_NO_SUCH_USER;
		}
	} else {
		return NT_STATUS_NO_SUCH_USER;
	}

	nt_status = pdb_fill_sam_pw(user, pass);
	passwd_free(&pass);

	return nt_status;
}

static NTSTATUS guestsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_NO_SUCH_USER;
	return guestsam_getsampwrid(my_methods, user, rid);
}

static NTSTATUS pdb_init_guestsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	
	if (!pdb_context) {
		DEBUG(0, ("invalid pdb_context specified\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}
	
	(*pdb_method)->name = "guestsam";
	
	(*pdb_method)->getsampwnam = guestsam_getsampwnam;
	(*pdb_method)->getsampwsid = guestsam_getsampwsid;
	
	/* There's not very much to initialise here */
	return NT_STATUS_OK;
}

NTSTATUS pdb_guest_init(void)
{
	NTSTATUS ret;
	struct passdb_ops ops;

	ZERO_STRUCT(ops);

	/* fill in our name */
	ops.name = "guestsam";
	/* fill in all the operations */
	ops.init = pdb_init_guestsam;

	/* register ourselves with the PASSDB subsystem. */
	ret = register_backend("passdb", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' PASSDB backend!\n",
			ops.name));
		return ret;
	}

	/* fill in our name */
	ops.name = "guest";
	/* fill in all the operations */
	ops.init = pdb_init_guestsam;

	/* register ourselves with the PASSDB subsystem. */
	ret = register_backend("passdb", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' PASSDB backend!\n",
			ops.name));
		return ret;
	}

	return ret;
}
