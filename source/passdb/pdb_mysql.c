/*
 * MySQL password backend for samba
 * Copyright (C) Jelmer Vernooij 2002-2004
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
#include <mysql/mysql.h>

#define CONFIG_HOST_DEFAULT				"localhost"
#define CONFIG_USER_DEFAULT				"samba"
#define CONFIG_PASS_DEFAULT				""
#define CONFIG_PORT_DEFAULT				"3306"
#define CONFIG_DB_DEFAULT				"samba"

static int mysqlsam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS mysqlsam_debug_level

typedef struct pdb_mysql_data {
	MYSQL *handle;
	MYSQL_RES *pwent;
	const char *location;
} pdb_mysql_data;

#define SET_DATA(data,methods) { \
	if(!methods){ \
		DEBUG(0, ("invalid methods!\n")); \
			return NT_STATUS_INVALID_PARAMETER; \
	} \
	data = (struct pdb_mysql_data *)methods->private_data; \
		if(!data || !(data->handle)){ \
			DEBUG(0, ("invalid handle!\n")); \
				return NT_STATUS_INVALID_HANDLE; \
		} \
}

#define config_value( data, name, default_value ) \
  lp_parm_const_string( GLOBAL_SECTION_SNUM, (data)->location, name, default_value )

static long xatol(const char *d)
{
	if(!d) return 0;
	return atol(d);
}

static NTSTATUS row_to_sam_account(MYSQL_RES * r, SAM_ACCOUNT * u)
{
	MYSQL_ROW row;
	pstring temp;
	unsigned int num_fields;
	DOM_SID sid;

	num_fields = mysql_num_fields(r);
	row = mysql_fetch_row(r);
	if (!row)
		return NT_STATUS_INVALID_PARAMETER;

	pdb_set_logon_time(u, xatol(row[0]), PDB_SET);
	pdb_set_logoff_time(u, xatol(row[1]), PDB_SET);
	pdb_set_kickoff_time(u, xatol(row[2]), PDB_SET);
	pdb_set_pass_last_set_time(u, xatol(row[3]), PDB_SET);
	pdb_set_pass_can_change_time(u, xatol(row[4]), PDB_SET);
	pdb_set_pass_must_change_time(u, xatol(row[5]), PDB_SET);
	pdb_set_username(u, row[6], PDB_SET);
	pdb_set_domain(u, row[7], PDB_SET);
	pdb_set_nt_username(u, row[8], PDB_SET);
	pdb_set_fullname(u, row[9], PDB_SET);
	pdb_set_homedir(u, row[10], PDB_SET);
	pdb_set_dir_drive(u, row[11], PDB_SET);
	pdb_set_logon_script(u, row[12], PDB_SET);
	pdb_set_profile_path(u, row[13], PDB_SET);
	pdb_set_acct_desc(u, row[14], PDB_SET);
	pdb_set_workstations(u, row[15], PDB_SET);
	pdb_set_unknown_str(u, row[16], PDB_SET);
	pdb_set_munged_dial(u, row[17], PDB_SET);

	if(!row[18] || !string_to_sid(&sid, row[18])) {
		DEBUG(0,("No user SID retrieved from database!\n"));
	} else {
		pdb_set_user_sid(u, &sid, PDB_SET);
	}

	if(row[19]) {
		string_to_sid(&sid, row[19]);
		pdb_set_group_sid(u, &sid, PDB_SET);
	}

	if (pdb_gethexpwd(row[20], temp))
		pdb_set_lanman_passwd(u, temp, PDB_SET);
	if (pdb_gethexpwd(row[21], temp))
		pdb_set_nt_passwd(u, temp, PDB_SET);

	/* Only use plaintext password storage when lanman and nt are
	 * NOT used */
	if (!row[20] || !row[21])
		pdb_set_plaintext_passwd(u, row[22]);

	pdb_set_acct_ctrl(u, xatol(row[23]), PDB_SET);
	pdb_set_logon_divs(u, xatol(row[25]), PDB_SET);
	pdb_set_hours_len(u, xatol(row[26]), PDB_SET);
	pdb_set_bad_password_count(u, xatol(row[27]), PDB_SET);
	pdb_set_logon_count(u, xatol(row[28]), PDB_SET);
	pdb_set_unknown_6(u, xatol(row[29]), PDB_SET);

	return NT_STATUS_OK;
}

static NTSTATUS mysqlsam_setsampwent(struct pdb_methods *methods, BOOL update)
{
	struct pdb_mysql_data *data =
		(struct pdb_mysql_data *) methods->private_data;
	char *query;
	int ret;

	if (!data || !(data->handle)) {
		DEBUG(0, ("invalid handle!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	query = sql_account_query_select(data->location, update, SQL_SEARCH_NONE, NULL);

	ret = mysql_query(data->handle, query);
	SAFE_FREE(query);

	if (ret) {
		DEBUG(0,
			   ("Error executing MySQL query %s\n", mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	data->pwent = mysql_store_result(data->handle);

	if (data->pwent == NULL) {
		DEBUG(0,
			("Error storing results: %s\n", mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	DEBUG(5,
		("mysqlsam_setsampwent succeeded(%llu results)!\n",
				mysql_num_rows(data->pwent)));
	
	return NT_STATUS_OK;
}

/***************************************************************
  End enumeration of the passwd list.
 ****************************************************************/

static void mysqlsam_endsampwent(struct pdb_methods *methods)
{
	struct pdb_mysql_data *data =
		(struct pdb_mysql_data *) methods->private_data;

	if (data == NULL) {
		DEBUG(0, ("invalid handle!\n"));
		return;
	}

	if (data->pwent != NULL)
		mysql_free_result(data->pwent);

	data->pwent = NULL;

	DEBUG(5, ("mysql_endsampwent called\n"));
}

/*****************************************************************
  Get one SAM_ACCOUNT from the list (next in line)
 *****************************************************************/

static NTSTATUS mysqlsam_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT * user)
{
	struct pdb_mysql_data *data;

	SET_DATA(data, methods);

	if (data->pwent == NULL) {
		DEBUG(0, ("invalid pwent\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return row_to_sam_account(data->pwent, user);
}

static NTSTATUS mysqlsam_select_by_field(struct pdb_methods * methods, SAM_ACCOUNT * user,
						 enum sql_search_field field, const char *sname)
{
	char *esc_sname;
	char *query;
	NTSTATUS ret;
	MYSQL_RES *res;
	int mysql_ret;
	struct pdb_mysql_data *data;
	char *tmp_sname;

	SET_DATA(data, methods);

	esc_sname = malloc(strlen(sname) * 2 + 1);
	if (!esc_sname) {
		return NT_STATUS_NO_MEMORY; 
	}

	tmp_sname = smb_xstrdup(sname);
	
	/* Escape sname */
	mysql_real_escape_string(data->handle, esc_sname, tmp_sname,
							 strlen(tmp_sname));

	SAFE_FREE(tmp_sname);

	if (user == NULL) {
		DEBUG(0, ("pdb_getsampwnam: SAM_ACCOUNT is NULL.\n"));
		SAFE_FREE(esc_sname);
		return NT_STATUS_INVALID_PARAMETER;
	}

	query = sql_account_query_select(data->location, True, field, esc_sname);

	SAFE_FREE(esc_sname);

	DEBUG(5, ("Executing query %s\n", query));
	
	mysql_ret = mysql_query(data->handle, query);
	
	SAFE_FREE(query);
	
	if (mysql_ret) {
		DEBUG(0,
			("Error while executing MySQL query %s\n", 
				mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	res = mysql_store_result(data->handle);
	if (res == NULL) {
		DEBUG(0,
			("Error storing results: %s\n", mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	ret = row_to_sam_account(res, user);
	mysql_free_result(res);

	return ret;
}

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

static NTSTATUS mysqlsam_getsampwnam(struct pdb_methods *methods, SAM_ACCOUNT * user,
					 const char *sname)
{
	struct pdb_mysql_data *data;

	SET_DATA(data, methods);

	if (!sname) {
		DEBUG(0, ("invalid name specified"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return mysqlsam_select_by_field(methods, user,
			SQL_SEARCH_USER_NAME, sname);
}


/***************************************************************************
  Search by sid
 **************************************************************************/

static NTSTATUS mysqlsam_getsampwsid(struct pdb_methods *methods, SAM_ACCOUNT * user,
					 const DOM_SID * sid)
{
	struct pdb_mysql_data *data;
	fstring sid_str;

	SET_DATA(data, methods);

	sid_to_string(sid_str, sid);

	return mysqlsam_select_by_field(methods, user, SQL_SEARCH_USER_SID, sid_str);
}

/***************************************************************************
  Delete a SAM_ACCOUNT
 ****************************************************************************/

static NTSTATUS mysqlsam_delete_sam_account(struct pdb_methods *methods,
							SAM_ACCOUNT * sam_pass)
{
	const char *sname = pdb_get_username(sam_pass);
	char *esc;
	char *query;
	int ret;
	struct pdb_mysql_data *data;
	char *tmp_sname;

	SET_DATA(data, methods);

	if (!methods) {
		DEBUG(0, ("invalid methods!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data = (struct pdb_mysql_data *) methods->private_data;
	if (!data || !(data->handle)) {
		DEBUG(0, ("invalid handle!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!sname) {
		DEBUG(0, ("invalid name specified\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Escape sname */
	esc = malloc(strlen(sname) * 2 + 1);
	if (!esc) {
		DEBUG(0, ("Can't allocate memory to store escaped name\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	tmp_sname = smb_xstrdup(sname);
	
	mysql_real_escape_string(data->handle, esc, tmp_sname,
							 strlen(tmp_sname));

	SAFE_FREE(tmp_sname);

	query = sql_account_query_delete(data->location, esc);

	SAFE_FREE(esc);

	ret = mysql_query(data->handle, query);

	SAFE_FREE(query);

	if (ret) {
		DEBUG(0,
			  ("Error while executing query: %s\n",
			   mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(5, ("User '%s' deleted\n", sname));
	return NT_STATUS_OK;
}

static NTSTATUS mysqlsam_replace_sam_account(struct pdb_methods *methods,
							 const SAM_ACCOUNT * newpwd, char isupdate)
{
	struct pdb_mysql_data *data;
	char *query;

	if (!methods) {
		DEBUG(0, ("invalid methods!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data = (struct pdb_mysql_data *) methods->private_data;

	if (data == NULL || data->handle == NULL) {
		DEBUG(0, ("invalid handle!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	query = sql_account_query_update(data->location, newpwd, isupdate);
	
	/* Execute the query */
	if (mysql_query(data->handle, query)) {
		DEBUG(0,
			  ("Error executing %s, %s\n", query,
			   mysql_error(data->handle)));
		return NT_STATUS_INVALID_PARAMETER;
	}
	SAFE_FREE(query);

	return NT_STATUS_OK;
}

static NTSTATUS mysqlsam_add_sam_account(struct pdb_methods *methods, SAM_ACCOUNT * newpwd)
{
	return mysqlsam_replace_sam_account(methods, newpwd, 0);
}

static NTSTATUS mysqlsam_update_sam_account(struct pdb_methods *methods,
							SAM_ACCOUNT * newpwd)
{
	return mysqlsam_replace_sam_account(methods, newpwd, 1);
}

static NTSTATUS mysqlsam_init(struct pdb_context * pdb_context, struct pdb_methods ** pdb_method,
		 const char *location)
{
	NTSTATUS nt_status;
	struct pdb_mysql_data *data;

	mysqlsam_debug_level = debug_add_class("mysqlsam");
	if (mysqlsam_debug_level == -1) {
		mysqlsam_debug_level = DBGC_ALL;
		DEBUG(0,
			  ("mysqlsam: Couldn't register custom debugging class!\n"));
	}


	if (!pdb_context) {
		DEBUG(0, ("invalid pdb_methods specified\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK
		(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "mysqlsam";

	(*pdb_method)->setsampwent = mysqlsam_setsampwent;
	(*pdb_method)->endsampwent = mysqlsam_endsampwent;
	(*pdb_method)->getsampwent = mysqlsam_getsampwent;
	(*pdb_method)->getsampwnam = mysqlsam_getsampwnam;
	(*pdb_method)->getsampwsid = mysqlsam_getsampwsid;
	(*pdb_method)->add_sam_account = mysqlsam_add_sam_account;
	(*pdb_method)->update_sam_account = mysqlsam_update_sam_account;
	(*pdb_method)->delete_sam_account = mysqlsam_delete_sam_account;

	data = talloc(pdb_context->mem_ctx, sizeof(struct pdb_mysql_data));
	(*pdb_method)->private_data = data;
	data->handle = NULL;
	data->pwent = NULL;

	if (!location) {
		DEBUG(0, ("No identifier specified. Check the Samba HOWTO Collection for details\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data->location = smb_xstrdup(location);

	DEBUG(1,
		  ("Connecting to database server, host: %s, user: %s, password: %s, database: %s, port: %ld\n",
		   config_value(data, "mysql host", CONFIG_HOST_DEFAULT),
		   config_value(data, "mysql user", CONFIG_USER_DEFAULT),
		   config_value(data, "mysql password", CONFIG_PASS_DEFAULT),
		   config_value(data, "mysql database", CONFIG_DB_DEFAULT),
		   xatol(config_value(data, "mysql port", CONFIG_PORT_DEFAULT))));

	/* Do the mysql initialization */
	data->handle = mysql_init(NULL);
	if (!data->handle) {
		DEBUG(0, ("Failed to connect to server\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if(!sql_account_config_valid(data->location)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	/* Process correct entry in $HOME/.my.conf */
	if (!mysql_real_connect(data->handle,
			config_value(data, "mysql host", CONFIG_HOST_DEFAULT),
			config_value(data, "mysql user", CONFIG_USER_DEFAULT),
			config_value(data, "mysql password", CONFIG_PASS_DEFAULT),
			config_value(data, "mysql database", CONFIG_DB_DEFAULT),
			xatol(config_value (data, "mysql port", CONFIG_PORT_DEFAULT)), 
			NULL, 0)) {
		DEBUG(0,
			  ("Failed to connect to mysql database: error: %s\n",
			   mysql_error(data->handle)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	DEBUG(5, ("Connected to mysql db\n"));

	return NT_STATUS_OK;
}

NTSTATUS pdb_mysql_init(void) 
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "mysql", mysqlsam_init);
}
