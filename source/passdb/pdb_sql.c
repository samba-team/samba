/*
 * Common PDB SQL backend functions
 * Copyright (C) Jelmer Vernooij 2003-2004
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
#define CONFIG_LOGON_DIVS_DEFAULT			"logon_divs"
#define CONFIG_HOURS_LEN_DEFAULT			"hours_len"
#define CONFIG_BAD_PASSWORD_COUNT_DEFAULT		"bad_password_count"
#define CONFIG_LOGON_COUNT_DEFAULT			"logon_count"
#define CONFIG_UNKNOWN_6_DEFAULT			"unknown_6"

/* Used to construct insert and update queries */

typedef struct pdb_sql_query {
	char update;
	TALLOC_CTX *mem_ctx;
	char *part1;
	char *part2;
} pdb_sql_query;

static void pdb_sql_int_field(struct pdb_sql_query *q, const char *name, int value)
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

char *sql_escape_string(const char *unesc)
{
	char *esc = malloc(strlen(unesc) * 2 + 3);
	size_t pos_unesc = 0, pos_esc = 0;

	for(pos_unesc = 0; unesc[pos_unesc]; pos_unesc++) {
		switch(unesc[pos_unesc]) {
		case '\\':
		case '\'':
		case '"':
			esc[pos_esc] = '\\'; pos_esc++;
		default:
			esc[pos_esc] = unesc[pos_unesc]; pos_esc++;
			break;
		}
	}

	esc[pos_esc] = '\0';
	
	return esc;
}

static NTSTATUS pdb_sql_string_field(struct pdb_sql_query *q,
					   const char *name, const char *value)
{
	char *esc_value;

	if (!name || !value || !strcmp(value, "") || strchr(name, '\''))
		return NT_STATUS_INVALID_PARAMETER;   /* This field shouldn't be set by module */

	esc_value = sql_escape_string(value);

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
	lp_parm_const_string(GLOBAL_SECTION_SNUM, data, name, default_value)

static const char * config_value_write(const char *location, const char *name, const char *default_value) 
{
	char const *v = NULL;
	char const *swrite = NULL;

	v = lp_parm_const_string(GLOBAL_SECTION_SNUM, location, name, default_value);

	if (!v)
		return NULL;

	swrite = strrchr(v, ':');

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

static const char * config_value_read(const char *location, const char *name, const char *default_value)
{
	char *v = NULL;
	char *swrite;

	v = lp_parm_talloc_string(GLOBAL_SECTION_SNUM, location, name, default_value);

	if (!v)
		return "NULL";

	swrite = strrchr(v, ':');

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

char *sql_account_query_select(const char *data, BOOL update, enum sql_search_field field, const char *value)
{
	const char *field_string;
	char *query;

	switch(field) {
	case SQL_SEARCH_NONE: 
		field_string = "'1'"; 
		value = "1"; 
		break;
		
	case SQL_SEARCH_USER_SID: 
		field_string = config_value_read(data, "user sid column", 
										 CONFIG_USER_SID_DEFAULT); 
		break;
		
	case SQL_SEARCH_USER_NAME: 
		field_string = config_value_read(data, "username column", 
										 CONFIG_USERNAME_DEFAULT);
		break;
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
			 config_value_read(data, "logon divs column",
							   CONFIG_LOGON_DIVS_DEFAULT),
			 config_value_read(data, "hours len column",
							   CONFIG_HOURS_LEN_DEFAULT),
			 config_value_read(data, "bad password count column",
							   CONFIG_BAD_PASSWORD_COUNT_DEFAULT),
			 config_value_read(data, "logon count column",
							   CONFIG_LOGON_COUNT_DEFAULT),
			 config_value_read(data, "unknown 6 column",
							   CONFIG_UNKNOWN_6_DEFAULT),
			 config_value(data, "table", CONFIG_TABLE_DEFAULT), 
			 field_string, value
				 );
	 return query;
}

char *sql_account_query_delete(const char *data, const char *esc) 
{
	char *query;
	
	asprintf(&query, "DELETE FROM %s WHERE %s = '%s'",
			 config_value(data, "table", CONFIG_TABLE_DEFAULT),
			 config_value_read(data, "username column",
							   CONFIG_USERNAME_DEFAULT), esc);
	return query;
}

char *sql_account_query_update(const char *location, const SAM_ACCOUNT *newpwd, char isupdate)
{
	char *ret;
	pstring temp;
	pdb_sql_query query;
	fstring sid_str;

	query.update = isupdate;

	/* I know this is somewhat overkill but only the talloc 
	 * functions have asprint_append and the 'normal' asprintf 
	 * is a GNU extension */
	query.mem_ctx = talloc_init("sql_query_update");
	query.part2 = talloc_asprintf(query.mem_ctx, "%s", "");
	if (query.update) {
		query.part1 =
			talloc_asprintf(query.mem_ctx, "UPDATE %s SET ",
							config_value(location, "table",
										 CONFIG_TABLE_DEFAULT));
	} else {
		query.part1 =
			talloc_asprintf(query.mem_ctx, "INSERT INTO %s (",
							config_value(location, "table",
										 CONFIG_TABLE_DEFAULT));
	}

	pdb_sql_int_field(&query,
						config_value_write(location, "acct ctrl column",
										   CONFIG_ACCT_CTRL_DEFAULT),
						pdb_get_acct_ctrl(newpwd));

	if (pdb_get_init_flags(newpwd, PDB_LOGONTIME) != PDB_DEFAULT) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "logon time column",
											   CONFIG_LOGON_TIME_DEFAULT),
							pdb_get_logon_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_LOGOFFTIME) != PDB_DEFAULT) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "logoff time column",
											   CONFIG_LOGOFF_TIME_DEFAULT),
							pdb_get_logoff_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_KICKOFFTIME) != PDB_DEFAULT) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "kickoff time column",
											   CONFIG_KICKOFF_TIME_DEFAULT),
							pdb_get_kickoff_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_CANCHANGETIME) != PDB_DEFAULT) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "pass can change time column",
											   CONFIG_PASS_CAN_CHANGE_TIME_DEFAULT),
							pdb_get_pass_can_change_time(newpwd));
	}

	if (pdb_get_init_flags(newpwd, PDB_MUSTCHANGETIME) != PDB_DEFAULT) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "pass must change time column",
											   CONFIG_PASS_MUST_CHANGE_TIME_DEFAULT),
							pdb_get_pass_must_change_time(newpwd));
	}

	if (pdb_get_pass_last_set_time(newpwd)) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "pass last set time column",
											   CONFIG_PASS_LAST_SET_TIME_DEFAULT),
							pdb_get_pass_last_set_time(newpwd));
	}

	if (pdb_get_hours_len(newpwd)) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "hours len column",
											   CONFIG_HOURS_LEN_DEFAULT),
							pdb_get_hours_len(newpwd));
	}

	if (pdb_get_logon_divs(newpwd)) {
		pdb_sql_int_field(&query,
							config_value_write(location,
											   "logon divs column",
											   CONFIG_LOGON_DIVS_DEFAULT),
							pdb_get_logon_divs(newpwd));
	}

	pdb_sql_string_field(&query,
						   config_value_write(location, "user sid column",
											  CONFIG_USER_SID_DEFAULT),
						   sid_to_string(sid_str, 
										 pdb_get_user_sid(newpwd)));

	pdb_sql_string_field(&query,
						   config_value_write(location, "group sid column",
											  CONFIG_GROUP_SID_DEFAULT),
						   sid_to_string(sid_str,
										 pdb_get_group_sid(newpwd)));

	pdb_sql_string_field(&query,
						   config_value_write(location, "username column",
											  CONFIG_USERNAME_DEFAULT),
						   pdb_get_username(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location, "domain column",
											  CONFIG_DOMAIN_DEFAULT),
						   pdb_get_domain(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "nt username column",
											  CONFIG_NT_USERNAME_DEFAULT),
						   pdb_get_nt_username(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location, "fullname column",
											  CONFIG_FULLNAME_DEFAULT),
						   pdb_get_fullname(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "logon script column",
											  CONFIG_LOGON_SCRIPT_DEFAULT),
						   pdb_get_logon_script(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "profile path column",
											  CONFIG_PROFILE_PATH_DEFAULT),
						   pdb_get_profile_path(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location, "dir drive column",
											  CONFIG_DIR_DRIVE_DEFAULT),
						   pdb_get_dir_drive(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location, "home dir column",
											  CONFIG_HOME_DIR_DEFAULT),
						   pdb_get_homedir(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "workstations column",
											  CONFIG_WORKSTATIONS_DEFAULT),
						   pdb_get_workstations(newpwd));

	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "unknown string column",
											  CONFIG_UNKNOWN_STR_DEFAULT),
						   pdb_get_workstations(newpwd));

	pdb_sethexpwd(temp, pdb_get_lanman_passwd(newpwd),
				  pdb_get_acct_ctrl(newpwd));
	pdb_sql_string_field(&query,
						   config_value_write(location,
											  "lanman pass column",
											  CONFIG_LM_PW_DEFAULT), temp);

	pdb_sethexpwd(temp, pdb_get_nt_passwd(newpwd),
				  pdb_get_acct_ctrl(newpwd));
	pdb_sql_string_field(&query,
						   config_value_write(location, "nt pass column",
											  CONFIG_NT_PW_DEFAULT), temp);

	if (query.update) {
		query.part1[strlen(query.part1) - 1] = '\0';
		query.part1 =
			talloc_asprintf_append(query.mem_ctx, query.part1,
								   " WHERE %s = '%s'",
								   config_value_read(location,
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

	ret = strdup(query.part1);
	talloc_destroy(query.mem_ctx);
	return ret;
}

BOOL sql_account_config_valid(const char *data)
{
	const char *sid_column, *username_column;
	
    sid_column = config_value_read(data, "user sid column", CONFIG_USER_SID_DEFAULT);
    username_column = config_value_read(data, "username column", CONFIG_USERNAME_DEFAULT);
	
    if(!strcmp(sid_column,"NULL") || !strcmp(username_column, "NULL")) {
        DEBUG(0,("Please specify both a valid 'user sid column' and a valid 'username column' in smb.conf\n"));
        return False;
    }

	return True;
}
