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

static NTSTATUS guestsam_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *sam_account, const char *sname)
{
	const char *guest_account = lp_guestaccount();

	if (!sam_account || !sname) {
		DEBUG(0,("invalid name specified"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!(guest_account && *guest_account)) {
		DEBUG(1, ("NULL guest account!?!?\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!methods) {
		DEBUG(0,("invalid methods\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (!strequal(guest_account, sname)) {
		return NT_STATUS_NO_SUCH_USER;
	}
		
	pdb_fill_default_sam(sam_account);
	
	if (!pdb_set_username(sam_account, guest_account, PDB_SET))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!pdb_set_fullname(sam_account, guest_account, PDB_SET))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!pdb_set_domain(sam_account, get_global_sam_name(), PDB_DEFAULT))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!pdb_set_acct_ctrl(sam_account, ACB_NORMAL, PDB_DEFAULT))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!pdb_set_user_sid_from_rid(sam_account, DOMAIN_USER_RID_GUEST, PDB_SET))
		return NT_STATUS_UNSUCCESSFUL;
	
	if (!pdb_set_group_sid_from_rid(sam_account, DOMAIN_GROUP_RID_GUESTS, PDB_DEFAULT))
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}


/***************************************************************************
  Search by rid
 **************************************************************************/

static NTSTATUS guestsam_getsampwrid (struct pdb_methods *methods, 
				 SAM_ACCOUNT *sam_account, uint32 rid)
{
	if (rid != DOMAIN_USER_RID_GUEST) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if (!sam_account) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return guestsam_getsampwnam (methods, sam_account, lp_guestaccount());
}

static NTSTATUS guestsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_NO_SUCH_USER;

	return guestsam_getsampwrid(my_methods, user, rid);
}


/***************************************************************************
  Updates a SAM_ACCOUNT

  This isn't a particulary practical option for pdb_guest.  We certainly don't
  want to twidde the filesystem, so what should we do?

  Current plan is to transparently add the account.  It should appear
  as if the pdb_guest version was modified, but its actually stored somehwere.
 ****************************************************************************/

static NTSTATUS guestsam_update_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
#if 1	/* JERRY */

	/* apparently thr build farm relies upon this heavior :-( */

	return methods->parent->pdb_add_sam_account(methods->parent, newpwd);
#else
	/* I don't think we should allow any modification of 
	   the guest account as SID will could messed up with 
	   the smbpasswd backend   --jerry */

	return NT_STATUS_NOT_IMPLEMENTED;
#endif
}

NTSTATUS pdb_init_guestsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
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
	(*pdb_method)->update_sam_account = guestsam_update_sam_account;
	
	/* we should do no group mapping here */
	(*pdb_method)->getgrsid = pdb_nop_getgrsid;
	(*pdb_method)->getgrgid = pdb_nop_getgrgid;
	(*pdb_method)->getgrnam = pdb_nop_getgrnam;
	(*pdb_method)->add_group_mapping_entry = pdb_nop_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = pdb_nop_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = pdb_nop_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = pdb_nop_enum_group_mapping;
	
	
	/* There's not very much to initialise here */
	return NT_STATUS_OK;
}

NTSTATUS pdb_guest_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "guest", pdb_init_guestsam);
}

