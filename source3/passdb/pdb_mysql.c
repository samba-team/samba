
/*
 * MySQL password backend for samba
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
#include <mysql/mysql.h>

#define CONFIG_TABLE_DEFAULT				"user"
#define CONFIG_LOGON_TIME_DEFAULT			"logon_time"
#define CONFIG_LOGOFF_TIME_DEFAULT			"logoff_time"
#define CONFIG_KICKOFF_TIME_DEFAULT			"kickoff_time"
#define CONFIG_PASS_LAST_SET_TIME_DEFAULT		"pass_last_set_time"
#define CONFIG_PASS_CAN_CHANGE_TIME_DEFAULT		"pass_can_change_time"
#define CONFIG_PASS_MUST_CHANGE_TIME_DEFAULT 		"pass_must_change_time"
#define CONFIG_USERNAME_DEFAULT 			"username"
#define CONFIG_DOMAIN_DEFAULT				"domain"
#define CONFIG_NT_USERNAME_DEFAULT  			"nt_username"
#define CONFIG_FULLNAME_DEFAULT				"nt_fullname"
#define CONFIG_HOME_DIR_DEFAULT				"home_dir"
#define CONFIG_DIR_DRIVE_DEFAULT			"dir_drive"
#define CONFIG_LOGON_SCRIPT_DEFAULT			"logon_script"
#define CONFIG_PROFILE_PATH_DEFAULT			"profile_path"
#define CONFIG_ACCT_DESC_DEFAULT			"acct_desc"
#define CONFIG_WORKSTATIONS_DEFAULT			"workstations"
#define CONFIG_UNKNOWN_STR_DEFAULT			"unknown_str"
#define CONFIG_MUNGED_DIAL_DEFAULT			"munged_dial"
#define CONFIG_USER_SID_DEFAULT				"user_sid"
#define CONFIG_GROUP_SID_DEFAULT			"group_sid"
#define CONFIG_LM_PW_DEFAULT				"lm_pw"
#define CONFIG_NT_PW_DEFAULT				"nt_pw"
#define CONFIG_PLAIN_PW_DEFAULT				"NULL"
#define CONFIG_ACCT_CTRL_DEFAULT			"acct_ctrl"
#define CONFIG_UNKNOWN_3_DEFAULT			"unknown_3"
#define CONFIG_LOGON_DIVS_DEFAULT			"logon_divs"
#define CONFIG_HOURS_LEN_DEFAULT			"hours_len"
#define CONFIG_UNKNOWN_5_DEFAULT			"unknown_5"
#define CONFIG_UNKNOWN_6_DEFAULT			"unknown_6"
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

/* Used to construct insert and update queries */

typedef struct pdb_mysql_query {
	char update;
	TALLOC_CTX *mem_ctx;
	char *part1;
	char *part2;
} pdb_mysql_query;
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

static void pdb_mysql_int_field(struct pdb_methods *m,
					struct pdb_mysql_query *q, const char *name, int value)
{
	if (!name || strchr(name, '\''))
		return;                 /* This field shouldn't be set by us */

	if (q->update) {
		q->part1 =
			talloc_asprintf_append(q->mem_ctx, q->part1,
								   "%s = %d,", name, value);
	} else {
		q->part1 =
			talloc_asprintf_append(q->mem_ctx, q->part1, "%s,", name);
		q->part2 =
			talloc_asprintf_append(q->mem_ctx, q->part2, "%d,", value);
	}
}

static NTSTATUS pdb_mysql_string_field(struct pdb_methods *methods,
					   struct pdb_mysql_query *q,
					   const char *name, const char *value)
{
	char *esc_value;
	struct pdb_mysql_data *data;
	char *tmp_value;

	SET_DATA(data, methods);

	if (!name || !value || !strcmp(value, "") || strchr(name, '\''))
		return NT_STATUS_INVALID_PARAMETER;   /* This field shouldn't be set by module */

	esc_value = malloc(strlen(value) * 2 + 1);

	tmp_value = smb_xstrdup(value);
	mysql_real_escape_string(data->handle, esc_value, tmp_value,
							 strlen(tmp_value));
	SAFE_FREE(tmp_value);

	if (q->update) {
		q->part1 =
			talloc_asprintf_append(q->mem_ctx, q->part1,
								   "%s = '%s',", name, esc_value);
	} else {
		q->part1 =
			talloc_asprintf_append(q->mem_ctx, q->part1, "%s,", name);
		q->part2 =
			talloc_asprintf_append(q->mem_ctx, q->part2, "'%s',",
								   esc_value);
	}

	SAFE_FREE(esc_value);

	return NT_STATUS_OK;
}

#define config_value(data,name,default_value) \
	lp_parm_const_string(GLOBAL_SECTION_SNUM, (data)->location, name, default_value)

static const char * config_value_write(pdb_mysql_data * data, const char *name, const char *default_value) {
	char const *v = NULL;
	char const *swrite = NULL;

	v = lp_parm_const_string(GLOBAL_SECTION_SNUM, data->location, name, default_value);

	if (!v)
		return NULL;

	swrite = strchr(v, ':');

	/* Default to the same field as read field */
	if (!swrite)
		return v;

	swrite++;

	/* If the field is 0 chars long, we shouldn't write to it */
	if (!strlen(swrite) || !strcmp(swrite, "NULL"))
		return NULL;

	/* Otherwise, use the additionally specified */
	return swrite;
}

static const char * config_value_read(pdb_mysql_data * data, const char *name, const char *default_value)
{
	char *v = NULL;
	char *swrite;

	v = lp_parm_talloc_string(GLOBAL_SECTION_SNUM, data->location, name, default_value);

	if (!v)
		return "NULL";

	swrite = strchr(v, ':');

	/* If no write is specified, there are no problems */
	if (!swrite) {
		if (strlen(v) == 0)
			return "NULL";
		return (const char *)v;
	}

	/* Otherwise, we have to cut the ':write_part' */
	*swrite = '\0';
	if (strlen(v) == 0)
		return "NULL";

	return (const char *)v;
}

/* Wrapper for atol that returns 0 if 'a' points to NULL */
static long xatol(const char *a)
{
	long ret = 0;

	if (a != NULL)
		ret = atol(a);

	return ret;
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

	string_to_sid(&sid, row[18]);
	pdb_set_user_sid(u, &sid, PDB_SET);
	string_to_sid(&sid, row[19]);
	pdb_set_group_sid(u, &sid, PDB_SET);

	if (pdb_gethexpwd(row[20], temp), PDB_SET)
		pdb_set_lanman_passwd(u, temp, PDB_SET);
	if (pdb_gethexpwd(row[21], temp), PDB_SET)
		pdb_set_nt_passwd(u, temp, PDB_SET);

	/* Only use plaintext password storage when lanman and nt are
	 * NOT used */
	if (!row[20] || !row[21])
		pdb_set_plaintext_passwd(u, row[22]);

	pdb_set_acct_ctrl(u, xatol(row[23]), PDB_SET);
	pdb_set_unknown_3(u, xatol(row[24]), PDB_SET);
	pdb_set_logon_divs(u, xatol(row[25]), PDB_SET);
	pdb_set_hours_len(u, xatol(row[26]), PDB_SET);
	pdb_set_unknown_5(u, xatol(row[27]), PDB_SET);
	pdb_set_unknown_6(u, xatol(row[28]), PDB_SET);

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

	asprintf(&query,
			 "SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s FROM %s",
			 config_value_read(data, "logon time column",
							   CONFIG_LOGON_TIME_DEFAULT),
			 config_value_read(data, "logoff time column",
							   CONFIG_LOGOFF_TIME_DEFAULT),
			 config_value_read(data, "kickoff time column",
							   CONFIG_KICKOFF_TIME_DEFAULT),
			 config_value_read(data, "pass last set time column",
							   CONFIG_PASS_LAST_SET_TIME_DEFAULT),
			 config_value_read(data, "pass can change time column",
							   CONFIG_PASS_CAN_CHANGE_TIME_DEFAULT),
			 config_value_read(data, "pass must change time column",
							   CONFIG_PASS_MUST_CHANGE_TIME_DEFAULT),
			 config_value_read(data, "username column",
							   CONFIG_USERNAME_DEFAULT),
			 config_value_read(data, "domain column",
							   CONFIG_DOMAIN_DEFAULT),
			 config_value_read(data, "nt username column",
							   CONFIG_NT_USERNAME_DEFAULT),
			 config_value_read(data, "fullname column",
							   CONFIG_FULLNAME_DEFAULT),
			 config_value_read(data, "home dir column",
							   CONFIG_HOME_DIR_DEFAULT),
			 config_value_read(data, "dir drive column",
							   CONFIG_DIR_DRIVE_DEFAULT),
			 config_value_read(data, "logon script column",
							   CONFIG_LOGON_SCRIPT_DEFAULT),
			 config_value_read(data, "profile path column",
							   CONFIG_PROFILE_PATH_DEFAULT),
			 config_value_read(data, "acct desc column",
							   CONFIG_ACCT_DESC_DEFAULT),
			 config_value_read(data, "workstations column",
							   CONFIG_WORKSTATIONS_DEFAULT),
			 config_value_read(data, "unknown string column",
							   CONFIG_UNKNOWN_STR_DEFAULT),
			 config_value_read(data, "munged dial column",
							   CONFIG_MUNGED_DIAL_DEFAULT),
			 config_value_read(data, "user sid column",
							   CONFIG_USER_SID_DEFAULT),
			 config_value_read(data, "group sid column",
							   CONFIG_GROUP_SID_DEFAULT),
			 config_value_read(data, "lanman pass column",
							   CONFIG_LM_PW_DEFAULT),
			 config_value_read(data, "nt pass column",
							   CONFIG_NT_PW_DEFAULT),
			 config_value_read(data, "plain pass column",
							   CONFIG_PLAIN_PW_DEFAULT),
			 config_value_read(data, "acct ctrl column",
							   CONFIG_ACCT_CTRL_DEFAULT),
			 config_value_read(data, "unknown 3 column",
							   CONFIG_UNKNOWN_3_DEFAULT),
			 config_value_read(data, "logon divs column",
							   CONFIG_LOGON_DIVS_DEFAULT),
			 config_value_read(data, "hours len column",
							   CONFIG_HOURS_LEN_DEFAULT),
			 config_value_read(data, "unknown 5 column",
							   CONFIG_UNKNOWN_5_DEFAULT),
			 config_value_read(data, "unknown 6 column",
							   CONFIG_UNKNOWN_6_DEFAULT),
			 config_value(data, "table", CONFIG_TABLE_DEFAULT)
				 );
	DEBUG(5, ("Executing query %s\n", query));
	
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
						 const char *field, const char *sname)
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

	DEBUG(5,
		  ("mysqlsam_select_by_field: getting data where %s = %s(nonescaped)\n",
		   field, sname));

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

	asprintf(&query,
			 "SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s FROM %s WHERE %s = '%s'",
			 config_value_read(data, "logon time column",
							   CONFIG_LOGON_TIME_DEFAULT),
			 config_value_read(data, "logoff time column",
							   CONFIG_LOGOFF_TIME_DEFAULT),
			 config_value_read(data, "kickoff time column",
							   CONFIG_KICKOFF_TIME_DEFAULT),
			 config_value_read(data, "pass last set time column",
							   CONFIG_PASS_LAST_SET_TIME_DEFAULT),
			 config_value_read(data, "pass can change time column",
							   CONFIG_PASS_CAN_CHANGE_TIME_DEFAULT),
			 config_value_read(data, "pass must change time column",
							   CONFIG_PASS_MUST_CHANGE_TIME_DEFAULT),
			 config_value_read(data, "username column",
							   CONFIG_USERNAME_DEFAULT),
			 config_value_read(data, "domain column",
							   CONFIG_DOMAIN_DEFAULT),
			 config_value_read(data, "nt username column",
							   CONFIG_NT_USERNAME_DEFAULT),
			 config_value_read(data, "fullname column",
							   CONFIG_FULLNAME_DEFAULT),
			 config_value_read(data, "home dir column",
							   CONFIG_HOME_DIR_DEFAULT),
			 config_value_read(data, "dir drive column",
							   CONFIG_DIR_DRIVE_DEFAULT),
			 config_value_read(data, "logon script column",
							   CONFIG_LOGON_SCRIPT_DEFAULT),
			 config_value_read(data, "profile path column",
							   CONFIG_PROFILE_PATH_DEFAULT),
			 config_value_read(data, "acct desc column",
							   CONFIG_ACCT_DESC_DEFAULT),
			 config_value_read(data, "workstations column",
							   CONFIG_WORKSTATIONS_DEFAULT),
			 config_value_read(data, "unknown string column",
							   CONFIG_UNKNOWN_STR_DEFAULT),
			 config_value_read(data, "munged dial column",
							   CONFIG_MUNGED_DIAL_DEFAULT),
			 config_value_read(data, "user sid column",
							   CONFIG_USER_SID_DEFAULT),
			 config_value_read(data, "group sid column",
							   CONFIG_GROUP_SID_DEFAULT),
			 config_value_read(data, "lanman pass column",
							   CONFIG_LM_PW_DEFAULT),
			 config_value_read(data, "nt pass column",
							   CONFIG_NT_PW_DEFAULT),
			 config_value_read(data, "plain pass column",
							   CONFIG_PLAIN_PW_DEFAULT),
			 config_value_read(data, "acct ctrl column",
							   CONFIG_ACCT_CTRL_DEFAULT),
			 config_value_read(data, "unknown 3 column",
							   CONFIG_UNKNOWN_3_DEFAULT),
			 config_value_read(data, "logon divs column",
							   CONFIG_LOGON_DIVS_DEFAULT),
			 config_value_read(data, "hours len column",
							   CONFIG_HOURS_LEN_DEFAULT),
			 config_value_read(data, "unknown 5 column",
							   CONFIG_UNKNOWN_5_DEFAULT),
			 config_value_read(data, "unknown 6 column",
							   CONFIG_UNKNOWN_6_DEFAULT),
			 config_value(data, "table", CONFIG_TABLE_DEFAULT), field,
			 esc_sname);
	
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
			config_value_read(data, "username column",
				CONFIG_USERNAME_DEFAULT), sname);
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

	return mysqlsam_select_by_field(methods, user,
			config_value_read(data, "user sid column",
				CONFIG_USER_SID_DEFAULT), sid_str);
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

	asprintf(&query, "DELETE FROM %s WHERE %s = '%s'",
			 config_value(data, "table", CONFIG_TABLE_DEFAULT),
			 config_value_read(data, "username column",
							   CONFIG_USERNAME_DEFAULT), esc);

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
	pstring temp;
	struct pdb_mysql_data *data;
	pdb_mysql_query query;
	fstring sid_str;

	if (!methods) {
		DEBUG(0, ("invalid methods!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data = (struct pdb_mysql_data *) methods->private_data;
	if (data == NULL || data->handle == NULL) {
		DEBUG(0, ("invalid handle!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}
	query.update = isupdate;

	/* I know this is somewhat overkill but only the talloc 
	 * functions have asprint_append and the 'normal' asprintf 
	 * is a GNU extension */
	query.mem_ctx = talloc_init("mysqlsam_replace_sam_account");
	query.part2 = talloc_asprintf(query.mem_ctx, "%s", "");
	if (query.update) {
		query.part1 =
			talloc_asprintf(query.mem_ctx, "UPDATE %s SET ",
							config_value(data, "table",
										 CONFIG_TABLE_DEFAULT));
	} else {
		query.part1 =
			talloc_asprintf(query.mem_ctx, "INSERT INTO %s (",
							config_value(data, "table",
										 CONFIG_TABLE_DEFAULT));
	}

	pdb_mysql_int_field(methods, &query,
						config_value_write(data, "acct ctrl column",
										   CONFIG_ACCT_CTRL_DEFAULT),
						pdb_get_acct_ctrl(newpwd));

	if (pdb_get_init_flags(newpwd, PDB_LOGONTIME) != PDB_DEFAULT) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "logon time column",
											   CONFIG_LOGON_TIME_DEFAULT),
							pdb_get_logon_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_LOGOFFTIME) != PDB_DEFAULT) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "logoff time column",
											   CONFIG_LOGOFF_TIME_DEFAULT),
							pdb_get_logoff_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_KICKOFFTIME) != PDB_DEFAULT) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "kickoff time column",
											   CONFIG_KICKOFF_TIME_DEFAULT),
							pdb_get_kickoff_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_CANCHANGETIME) != PDB_DEFAULT) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "pass can change time column",
											   CONFIG_PASS_CAN_CHANGE_TIME_DEFAULT),
							pdb_get_pass_can_change_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_MUSTCHANGETIME) != PDB_DEFAULT) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "pass must change time column",
											   CONFIG_PASS_MUST_CHANGE_TIME_DEFAULT),
							pdb_get_pass_must_change_time(newpwd));
	}

	if (pdb_get_pass_last_set_time(newpwd)) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "pass last set time column",
											   CONFIG_PASS_LAST_SET_TIME_DEFAULT),
							pdb_get_pass_last_set_time(newpwd));
	}

	if (pdb_get_hours_len(newpwd)) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "hours len column",
											   CONFIG_HOURS_LEN_DEFAULT),
							pdb_get_hours_len(newpwd));
	}

	if (pdb_get_logon_divs(newpwd)) {
		pdb_mysql_int_field(methods, &query,
							config_value_write(data,
											   "logon divs column",
											   CONFIG_LOGON_DIVS_DEFAULT),
							pdb_get_logon_divs(newpwd));
	}

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "user sid column",
											  CONFIG_USER_SID_DEFAULT),
						   sid_to_string(sid_str, 
										 pdb_get_user_sid(newpwd)));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "group sid column",
											  CONFIG_GROUP_SID_DEFAULT),
						   sid_to_string(sid_str,
										 pdb_get_group_sid(newpwd)));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "username column",
											  CONFIG_USERNAME_DEFAULT),
						   pdb_get_username(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "domain column",
											  CONFIG_DOMAIN_DEFAULT),
						   pdb_get_domain(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "nt username column",
											  CONFIG_NT_USERNAME_DEFAULT),
						   pdb_get_nt_username(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "fullname column",
											  CONFIG_FULLNAME_DEFAULT),
						   pdb_get_fullname(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "logon script column",
											  CONFIG_LOGON_SCRIPT_DEFAULT),
						   pdb_get_logon_script(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "profile path column",
											  CONFIG_PROFILE_PATH_DEFAULT),
						   pdb_get_profile_path(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "dir drive column",
											  CONFIG_DIR_DRIVE_DEFAULT),
						   pdb_get_dir_drive(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "home dir column",
											  CONFIG_HOME_DIR_DEFAULT),
						   pdb_get_homedir(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "workstations column",
											  CONFIG_WORKSTATIONS_DEFAULT),
						   pdb_get_workstations(newpwd));

	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "unknown string column",
											  CONFIG_UNKNOWN_STR_DEFAULT),
						   pdb_get_workstations(newpwd));

	pdb_sethexpwd(temp, pdb_get_lanman_passwd(newpwd),
				  pdb_get_acct_ctrl(newpwd));
	pdb_mysql_string_field(methods, &query,
						   config_value_write(data,
											  "lanman pass column",
											  CONFIG_LM_PW_DEFAULT), temp);

	pdb_sethexpwd(temp, pdb_get_nt_passwd(newpwd),
				  pdb_get_acct_ctrl(newpwd));
	pdb_mysql_string_field(methods, &query,
						   config_value_write(data, "nt pass column",
											  CONFIG_NT_PW_DEFAULT), temp);

	if (query.update) {
		query.part1[strlen(query.part1) - 1] = '\0';
		query.part1 =
			talloc_asprintf_append(query.mem_ctx, query.part1,
								   " WHERE %s = '%s'",
								   config_value_read(data,
													 "user sid column",
													 CONFIG_USER_SID_DEFAULT),
								   sid_to_string(sid_str, pdb_get_user_sid (newpwd)));
	} else {
		query.part2[strlen(query.part2) - 1] = ')';
		query.part1[strlen(query.part1) - 1] = ')';
		query.part1 =
			talloc_asprintf_append(query.mem_ctx, query.part1,
								   " VALUES (%s", query.part2);
	}

	DEBUG(0, ("%s\n", query.part1));
	/* Execute the query */
	if (mysql_query(data->handle, query.part1)) {
		DEBUG(0,
			  ("Error executing %s, %s\n", query.part1,
			   mysql_error(data->handle)));
		return NT_STATUS_INVALID_PARAMETER;
	}
	talloc_destroy(query.mem_ctx);
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
