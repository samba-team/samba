/*
 * GUMS password backend for samba
 * Copyright (C) Simo Sorce 2003-2004
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

#define SET_OR_FAIL(func, label) do { if (!NT_STATUS_IS_OK(func)) { DEBUG(0, ("%s: Setting gums object data failed!\n", FUNCTION_MACRO)); goto label; } } while(0)
#define BOOL_SET_OR_FAIL(func, label) do { if (!func) { DEBUG(0, ("%s: Setting sam object data failed!\n", FUNCTION_MACRO)); goto label; } } while(0)

struct gums_gw_data {
	GUMS_FUNCTIONS *fns;
	void *handle;
};

static NTSTATUS gums_object_to_sam_account(SAM_ACCOUNT *sa, GUMS_OBJECT *go)
{
	NTSTATUS ret;
	NTTIME nt_time;
	DATA_BLOB pwd;

	if (!go || !sa)
		return NT_STATUS_INVALID_PARAMETER;
/*
	if (!NT_STATUS_IS_OK(ret = pdb_init_sam(sa))) {
		DEBUG(0, ("gums_object_to_sam_account: error occurred while creating sam_account object!\n"));
		goto error;
	}
*/
	if (gums_get_object_type(go) != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	BOOL_SET_OR_FAIL(pdb_set_acct_ctrl(sa, gums_get_user_acct_ctrl(go), PDB_SET), error);

	/* domain */
	/* unix_homedir ? */

	nt_time = gums_get_user_logon_time(go);
	BOOL_SET_OR_FAIL(pdb_set_logon_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	nt_time = gums_get_user_logoff_time(go);
	BOOL_SET_OR_FAIL(pdb_set_logoff_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	nt_time = gums_get_user_kickoff_time(go);
	BOOL_SET_OR_FAIL(pdb_set_kickoff_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	nt_time = gums_get_user_pass_last_set_time(go);
	BOOL_SET_OR_FAIL(pdb_set_pass_last_set_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	nt_time = gums_get_user_pass_can_change_time(go);
	BOOL_SET_OR_FAIL(pdb_set_pass_can_change_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	nt_time = gums_get_user_pass_must_change_time(go);
	BOOL_SET_OR_FAIL(pdb_set_pass_must_change_time(sa, nt_time_to_unix(&nt_time), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_hours_len(sa, gums_get_user_hours_len(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_logon_divs(sa, gums_get_user_logon_divs(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_user_sid(sa, gums_get_object_sid(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_group_sid(sa, gums_get_user_pri_group(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_username(sa, gums_get_object_name(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_nt_username(sa, gums_get_object_name(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_fullname(sa, gums_get_user_fullname(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_logon_script(sa, gums_get_user_logon_script(go), PDB_SET), error);
	BOOL_SET_OR_FAIL(pdb_set_profile_path(sa, gums_get_user_profile_path(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_dir_drive(sa, gums_get_user_dir_drive(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_homedir(sa, gums_get_user_homedir(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_acct_desc(sa, gums_get_object_description(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_workstations(sa, gums_get_user_workstations(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_unknown_str(sa, gums_get_user_unknown_str(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_munged_dial(sa, gums_get_user_munged_dial(go), PDB_SET), error); 

	pwd = gums_get_user_nt_pwd(go);
	if (!pdb_set_nt_passwd(sa, pwd.data, PDB_SET)) {
		DEBUG(5, ("gums_object_to_sam_account: unable to set nt password"));
		data_blob_clear_free(&pwd);
		ret = NT_STATUS_UNSUCCESSFUL;
		goto error;
	}
	data_blob_clear_free(&pwd);
	pwd = gums_get_user_lm_pwd(go);
	if (!pdb_set_lanman_passwd(sa, pwd.data, PDB_SET)) {
		DEBUG(5, ("gums_object_to_sam_account: unable to set lanman password"));
		data_blob_clear_free(&pwd);
		ret = NT_STATUS_UNSUCCESSFUL;
		goto error;
	}
	data_blob_clear_free(&pwd);

	BOOL_SET_OR_FAIL(pdb_set_bad_password_count(sa, gums_get_user_bad_password_count(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_unknown_6(sa, gums_get_user_unknown_6(go), PDB_SET), error); 
	BOOL_SET_OR_FAIL(pdb_set_hours(sa, gums_get_user_hours(go), PDB_SET), error); 

	return NT_STATUS_OK;

error:
	if (sa && (sa->free_fn)) {
		sa->free_fn(&sa);
	}

	return ret;
}

static NTSTATUS sam_account_to_gums_object(GUMS_OBJECT *go, SAM_ACCOUNT *sa)
{
	NTSTATUS ret;
	NTTIME nt_time;
	DATA_BLOB pwd;

	if (!go || !sa)
		return NT_STATUS_INVALID_PARAMETER;

/*
	ret = gums_create_object(go, GUMS_OBJ_NORMAL_USER);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("sam_account_to_gums_object: error occurred while creating gums object!\n"));
		goto error;
	}
*/

	/* sec_desc */

	SET_OR_FAIL(gums_set_object_name(go, pdb_get_username(sa)), error);

	SET_OR_FAIL(gums_set_object_sid(go, pdb_get_user_sid(sa)), error);
	SET_OR_FAIL(gums_set_user_pri_group(go, pdb_get_group_sid(sa)), error);

	if (pdb_get_acct_desc(sa))
		SET_OR_FAIL(gums_set_object_description(go, pdb_get_acct_desc(sa)), error);
	if (pdb_get_fullname(sa))
		SET_OR_FAIL(gums_set_user_fullname(go, pdb_get_fullname(sa)), error);
	if (pdb_get_homedir(sa))
		SET_OR_FAIL(gums_set_user_homedir(go, pdb_get_homedir(sa)), error);
	if (pdb_get_dir_drive(sa))
		SET_OR_FAIL(gums_set_user_dir_drive(go, pdb_get_dir_drive(sa)), error);
	if (pdb_get_logon_script(sa))
		SET_OR_FAIL(gums_set_user_logon_script(go, pdb_get_logon_script(sa)), error);
	if (pdb_get_profile_path(sa))
		SET_OR_FAIL(gums_set_user_profile_path(go, pdb_get_profile_path(sa)), error);
	if (pdb_get_workstations(sa))
		SET_OR_FAIL(gums_set_user_workstations(go, pdb_get_workstations(sa)), error);
	if (pdb_get_unknown_str(sa))
		SET_OR_FAIL(gums_set_user_unknown_str(go, pdb_get_unknown_str(sa)), error);
	if (pdb_get_munged_dial(sa))
		SET_OR_FAIL(gums_set_user_munged_dial(go, pdb_get_munged_dial(sa)), error);
	SET_OR_FAIL(gums_set_user_logon_divs(go, pdb_get_logon_divs(sa)), error);
	if (pdb_get_hours(sa))
		SET_OR_FAIL(gums_set_user_hours(go, pdb_get_hours_len(sa), pdb_get_hours(sa)), error);
	SET_OR_FAIL(gums_set_user_bad_password_count(go, pdb_get_bad_password_count(sa)), error);
	SET_OR_FAIL(gums_set_user_unknown_6(go, pdb_get_unknown_6(sa)), error);

	unix_to_nt_time(&nt_time, pdb_get_logon_time(sa));
	SET_OR_FAIL(gums_set_user_logon_time(go, nt_time), error);
	unix_to_nt_time(&nt_time, pdb_get_logoff_time(sa));
	SET_OR_FAIL(gums_set_user_logoff_time(go, nt_time), error);
	unix_to_nt_time(&nt_time, pdb_get_kickoff_time(sa));
	SET_OR_FAIL(gums_set_user_kickoff_time(go, nt_time), error);
	unix_to_nt_time(&nt_time, pdb_get_pass_last_set_time(sa));
	SET_OR_FAIL(gums_set_user_pass_last_set_time(go, nt_time), error);
	unix_to_nt_time(&nt_time, pdb_get_pass_can_change_time(sa));
	SET_OR_FAIL(gums_set_user_pass_can_change_time(go, nt_time), error);
	unix_to_nt_time(&nt_time, pdb_get_pass_must_change_time(sa));
	SET_OR_FAIL(gums_set_user_pass_must_change_time(go, nt_time), error);

	pwd = data_blob(pdb_get_nt_passwd(sa), NT_HASH_LEN);
	ret = gums_set_user_nt_pwd(go, pwd);
	data_blob_clear_free(&pwd);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(5, ("sam_account_to_gums_object: failed to set nt password!\n"));
		goto error;
	}
	pwd = data_blob(pdb_get_lanman_passwd(sa), LM_HASH_LEN);
	ret = gums_set_user_lm_pwd(go, pwd);
	data_blob_clear_free(&pwd);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(5, ("sam_account_to_gums_object: failed to set lanman password!\n"));
		goto error;
	}

	SET_OR_FAIL(gums_set_user_acct_ctrl(go, pdb_get_acct_ctrl(sa)), error);

	return NT_STATUS_OK;

error:
	gums_reset_object(go);
	return ret;
}

static NTSTATUS gums_setsampwent(struct pdb_methods *methods, BOOL update)
{
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	return ggwd->fns->enumerate_objects_start(&(ggwd->handle), NULL, GUMS_OBJ_NORMAL_USER);
}

static NTSTATUS gums_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT *account)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->enumerate_objects_get_next(&go, ggwd->handle))) {
		return ret;
	}

	ret = gums_object_to_sam_account(account, go);

	gums_destroy_object(&go);
	return ret;
}

static void gums_endsampwent(struct pdb_methods *methods)
{
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	ggwd->fns->enumerate_objects_stop(ggwd->handle);
}

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

static NTSTATUS gums_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *account, const char *name)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!account || !name)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->get_object_from_name(&go, global_myname(), name, GUMS_OBJ_NORMAL_USER))) {
		DEBUG(10, ("gums_getsampwnam: unable to find account with name %s", name));
		return ret;
	}

	ret = gums_object_to_sam_account(account, go);

	gums_destroy_object(&go);
	return ret;
}

/***************************************************************************
  Search by SID
 **************************************************************************/

static NTSTATUS gums_getsampwsid(struct pdb_methods *methods, SAM_ACCOUNT *account, const DOM_SID *sid)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!account || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->get_object_from_sid(&go, sid, GUMS_OBJ_NORMAL_USER))) {
		DEBUG(10, ("gums_getsampwsid: unable to find account with sid %s", sid_string_static(sid)));
		return ret;
	}

	ret = gums_object_to_sam_account(account, go);

	gums_destroy_object(&go);
	return ret;
}

/***************************************************************************
  Search by rid
 **************************************************************************/

#if 0

static NTSTATUS gums_getsampwrid (struct pdb_methods *methods, 
				 SAM_ACCOUNT *account, uint32 rid)
{
	DOM_SID sid;

	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, rid);
	gums_getsampwsid(methods, account, &sid);

	return NT_STATUS_OK;
}

#endif

/***************************************************************************
  Updates a SAM_ACCOUNT

  This isn't a particulary practical option for pdb_guest.  We certainly don't
  want to twidde the filesystem, so what should we do?

  Current plan is to transparently add the account.  It should appear
  as if the pdb_guest version was modified, but its actually stored somehwere.
 ****************************************************************************/

static NTSTATUS gums_add_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *account)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!account)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_create_object(&go, GUMS_OBJ_NORMAL_USER))) {
		DEBUG(0, ("gums_add_sam_account: error occurred while creating gums object!\n"));
		return ret;
	}

	if (!NT_STATUS_IS_OK(ret = sam_account_to_gums_object(go, account))) {
		DEBUG(0, ("gums_add_sam_account: error occurred while converting object!\n"));
		goto done;
	}

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->set_object(go))) {
		DEBUG(0, ("gums_add_sam_account: unable to store account!\n"));
		goto done;
	}

done:
	gums_destroy_object(&go);
	return ret;
}

static NTSTATUS gums_update_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *account)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!account)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->get_object_from_sid(&go, pdb_get_user_sid(account), GUMS_OBJ_NORMAL_USER))) {
		DEBUG(0, ("gums_update_sam_account: update on invalid account!\n"));
		return ret;
	}

	if (!NT_STATUS_IS_OK(ret = sam_account_to_gums_object(go, account))) {
		DEBUG(0, ("gums_update_sam_account: error occurred while converting object!\n"));
		goto done;
	}

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->set_object(go))) {
		DEBUG(0, ("gums_update_sam_account: unable to store account!\n"));
		goto done;
	}

done:
	gums_destroy_object(&go);
	return ret;
}

static NTSTATUS gums_delete_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *account)
{
	NTSTATUS ret;
	struct gums_gw_data *ggwd = (struct gums_gw_data *)(methods->private_data);

	if (!account)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = ggwd->fns->delete_object(pdb_get_user_sid(account)))) {
		DEBUG(0, ("gums_add_sam_account: unable to store account!\n"));
	}

	return ret;
}


static void free_gw_private_data(void **vp)
{
	struct gums_gw_data *ggwd = (struct gums_gw_data *)vp;
	ggwd->fns->free_private_data(&(ggwd->fns->private_data));
	ggwd->fns = NULL;
	ggwd->handle = NULL;
	SAFE_FREE(vp);
}

NTSTATUS pdb_init_gums_gateway(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS ret;
	struct gums_gw_data *ggwd;
	
	if (!pdb_context) {
		DEBUG(0, ("invalid pdb_context specified\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(ret = gums_setup_backend(lp_gums_backend()))) {
		DEBUG(0, ("pdb_init_gums_gateway: initialization error!\n"));
		return ret;
	}
	
	ggwd = (struct gums_gw_data *)malloc(sizeof(struct gums_gw_data));
	if (!ggwd)
		return NT_STATUS_NO_MEMORY;
	memset(ggwd, 0, sizeof(struct gums_gw_data));

	if (!NT_STATUS_IS_OK(ret = get_gums_fns(&(ggwd->fns)))) {
		goto error;
	}

	if (!NT_STATUS_IS_OK(ret = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		goto error;
	}
	
	(*pdb_method)->name = "gums_gateway";
	
	(*pdb_method)->setsampwent = gums_setsampwent;
	(*pdb_method)->getsampwent = gums_getsampwent;
	(*pdb_method)->endsampwent = gums_endsampwent;
	(*pdb_method)->getsampwnam = gums_getsampwnam;
	(*pdb_method)->getsampwsid = gums_getsampwsid;
	(*pdb_method)->add_sam_account = gums_add_sam_account;
	(*pdb_method)->update_sam_account = gums_update_sam_account;
	(*pdb_method)->delete_sam_account = gums_delete_sam_account;
	
	/* we should do no group mapping here */
/*	(*pdb_method)->getgrsid = gums_getgrsid;
	(*pdb_method)->getgrgid = gums_getgrgid;
	(*pdb_method)->getgrnam = gums_getgrnam;
	(*pdb_method)->add_group_mapping_entry = gums_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = gums_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = gums_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = gums_enum_group_mapping;*/
	
	/* we do not handle groups in guest backend */
/*	FIXME
	(*pdb_method)->get_group_info_by_sid = gums_get_group_info_by_sid;
	(*pdb_method)->get_group_list = gums_get_group_list;
	(*pdb_method)->get_group_sids = gums_get_group_sids;
	(*pdb_method)->add_group = gums_add_group;
	(*pdb_method)->update_group = gums_update_group;
	(*pdb_method)->delete_group = gums_delete_group;
	(*pdb_method)->add_sid_to_group = gums_add_sid_to_group;
	(*pdb_method)->remove_sid_from_group = gums_remove_sid_from_group;
	(*pdb_method)->get_group_info_by_name = gums_get_group_info_by_name;
	(*pdb_method)->get_group_info_by_nt_name = gums_get_group_info_by_nt_name;
	(*pdb_method)->get_group_uids = gums_get_group_uids;
*/	

	(*pdb_method)->private_data = ggwd;
	(*pdb_method)->free_private_data = free_gw_private_data;
	
	return NT_STATUS_OK;

error:
	SAFE_FREE(ggwd);
	return ret;
}

NTSTATUS pdb_gums_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "gums", pdb_init_gums_gateway);
}

