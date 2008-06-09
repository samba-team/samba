/*
   Unix SMB/CIFS implementation.
   SAMR Pipe utility functions.

   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Guenther Deschner		2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define STRING_CHANGED (old_string && !new_string) ||\
		    (!old_string && new_string) ||\
		(old_string && new_string && (strcmp(old_string, new_string) != 0))

#define STRING_CHANGED_NC(s1,s2) ((s1) && !(s2)) ||\
		    (!(s1) && (s2)) ||\
		((s1) && (s2) && (strcmp((s1), (s2)) != 0))

/*************************************************************
 Copies a struct samr_UserInfo20 to a struct samu
**************************************************************/

void copy_id20_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo20 *from)
{
	const char *old_string;
	char *new_string;
	DATA_BLOB mung;

	if (from == NULL || to == NULL) {
		return;
	}

	if (from->parameters.array) {
		old_string = pdb_get_munged_dial(to);
		mung = data_blob_const(from->parameters.array,
				       from->parameters.length);
		new_string = (mung.length == 0) ?
			NULL : base64_encode_data_blob(talloc_tos(), mung);
		DEBUG(10,("INFO_20 PARAMETERS: %s -> %s\n",
			old_string, new_string));
		if (STRING_CHANGED_NC(old_string,new_string)) {
			pdb_set_munged_dial(to, new_string, PDB_CHANGED);
		}

		TALLOC_FREE(new_string);
	}
}

/*************************************************************
 Copies a struct samr_UserInfo21 to a struct samu
**************************************************************/

void copy_id21_to_sam_passwd(const char *log_prefix,
			     struct samu *to,
			     struct samr_UserInfo21 *from)
{
	time_t unix_time, stored_time;
	const char *old_string, *new_string;
	const char *l;

	if (from == NULL || to == NULL) {
		return;
	}

	if (log_prefix) {
		l = log_prefix;
	} else {
		l = "INFO_21";
	}

	if (from->fields_present & SAMR_FIELD_LAST_LOGON) {
		unix_time = nt_time_to_unix(from->last_logon);
		stored_time = pdb_get_logon_time(to);
		DEBUG(10,("%s SAMR_FIELD_LAST_LOGON: %lu -> %lu\n", l,
			(long unsigned int)stored_time,
			(long unsigned int)unix_time));
		if (stored_time != unix_time) {
			pdb_set_logon_time(to, unix_time, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_LAST_LOGOFF) {
		unix_time = nt_time_to_unix(from->last_logoff);
		stored_time = pdb_get_logoff_time(to);
		DEBUG(10,("%s SAMR_FIELD_LAST_LOGOFF: %lu -> %lu\n", l,
			(long unsigned int)stored_time,
			(long unsigned int)unix_time));
		if (stored_time != unix_time) {
			pdb_set_logoff_time(to, unix_time, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_ACCT_EXPIRY) {
		unix_time = nt_time_to_unix(from->acct_expiry);
		stored_time = pdb_get_kickoff_time(to);
		DEBUG(10,("%s SAMR_FIELD_ACCT_EXPIRY: %lu -> %lu\n", l,
			(long unsigned int)stored_time,
			(long unsigned int)unix_time));
		if (stored_time != unix_time) {
			pdb_set_kickoff_time(to, unix_time , PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_LAST_PWD_CHANGE) {
		unix_time = nt_time_to_unix(from->last_password_change);
		stored_time = pdb_get_pass_last_set_time(to);
		DEBUG(10,("%s SAMR_FIELD_LAST_PWD_CHANGE: %lu -> %lu\n", l,
			(long unsigned int)stored_time,
			(long unsigned int)unix_time));
		if (stored_time != unix_time) {
			pdb_set_pass_last_set_time(to, unix_time, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_ACCOUNT_NAME) &&
	    (from->account_name.string)) {
		old_string = pdb_get_username(to);
		new_string = from->account_name.string;
		DEBUG(10,("%s SAMR_FIELD_ACCOUNT_NAME: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_username(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_FULL_NAME) &&
	    (from->full_name.string)) {
		old_string = pdb_get_fullname(to);
		new_string = from->full_name.string;
		DEBUG(10,("%s SAMR_FIELD_FULL_NAME: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_fullname(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_HOME_DIRECTORY) &&
	    (from->home_directory.string)) {
		old_string = pdb_get_homedir(to);
		new_string = from->home_directory.string;
		DEBUG(10,("%s SAMR_FIELD_HOME_DIRECTORY: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_homedir(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_HOME_DRIVE) &&
	    (from->home_drive.string)) {
		old_string = pdb_get_dir_drive(to);
		new_string = from->home_drive.string;
		DEBUG(10,("%s SAMR_FIELD_HOME_DRIVE: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_dir_drive(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_LOGON_SCRIPT) &&
	    (from->logon_script.string)) {
		old_string = pdb_get_logon_script(to);
		new_string = from->logon_script.string;
		DEBUG(10,("%s SAMR_FIELD_LOGON_SCRIPT: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_logon_script(to  , new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_PROFILE_PATH) &&
	    (from->profile_path.string)) {
		old_string = pdb_get_profile_path(to);
		new_string = from->profile_path.string;
		DEBUG(10,("%s SAMR_FIELD_PROFILE_PATH: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_profile_path(to  , new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_DESCRIPTION) &&
	    (from->description.string)) {
		old_string = pdb_get_acct_desc(to);
		new_string = from->description.string;
		DEBUG(10,("%s SAMR_FIELD_DESCRIPTION: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_acct_desc(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_WORKSTATIONS) &&
	    (from->workstations.string)) {
		old_string = pdb_get_workstations(to);
		new_string = from->workstations.string;
		DEBUG(10,("%s SAMR_FIELD_WORKSTATIONS: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_workstations(to  , new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_COMMENT) &&
	    (from->comment.string)) {
		old_string = pdb_get_comment(to);
		new_string = from->comment.string;
		DEBUG(10,("%s SAMR_FIELD_COMMENT: %s -> %s\n", l,
			old_string, new_string));
		if (STRING_CHANGED) {
			pdb_set_comment(to, new_string, PDB_CHANGED);
		}
	}

	if ((from->fields_present & SAMR_FIELD_PARAMETERS) &&
	    (from->parameters.array)) {
		char *newstr;
		DATA_BLOB mung;
		old_string = pdb_get_munged_dial(to);

		mung = data_blob_const(from->parameters.array,
				       from->parameters.length);
		newstr = (mung.length == 0) ?
			NULL : base64_encode_data_blob(talloc_tos(), mung);
		DEBUG(10,("%s SAMR_FIELD_PARAMETERS: %s -> %s\n", l,
			old_string, newstr));
		if (STRING_CHANGED_NC(old_string,newstr)) {
			pdb_set_munged_dial(to, newstr, PDB_CHANGED);
		}

		TALLOC_FREE(newstr);
	}

	if (from->fields_present & SAMR_FIELD_RID) {
		if (from->rid == 0) {
			DEBUG(10,("%s: Asked to set User RID to 0 !? Skipping change!\n", l));
		} else if (from->rid != pdb_get_user_rid(to)) {
			DEBUG(10,("%s SAMR_FIELD_RID: %u -> %u NOT UPDATED!\n", l,
				pdb_get_user_rid(to), from->rid));
		}
	}

	if (from->fields_present & SAMR_FIELD_PRIMARY_GID) {
		if (from->primary_gid == 0) {
			DEBUG(10,("%s: Asked to set Group RID to 0 !? Skipping change!\n", l));
		} else if (from->primary_gid != pdb_get_group_rid(to)) {
			DEBUG(10,("%s SAMR_FIELD_PRIMARY_GID: %u -> %u\n", l,
				pdb_get_group_rid(to), from->primary_gid));
			pdb_set_group_sid_from_rid(to,
				from->primary_gid, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_ACCT_FLAGS) {
		DEBUG(10,("%s SAMR_FIELD_ACCT_FLAGS: %08X -> %08X\n", l,
			pdb_get_acct_ctrl(to), from->acct_flags));
		if (from->acct_flags != pdb_get_acct_ctrl(to)) {
			if (!(from->acct_flags & ACB_AUTOLOCK) &&
			     (pdb_get_acct_ctrl(to) & ACB_AUTOLOCK)) {
				/* We're unlocking a previously locked user. Reset bad password counts.
				   Patch from Jianliang Lu. <Jianliang.Lu@getronics.com> */
				pdb_set_bad_password_count(to, 0, PDB_CHANGED);
				pdb_set_bad_password_time(to, 0, PDB_CHANGED);
			}
			pdb_set_acct_ctrl(to, from->acct_flags, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_LOGON_HOURS) {
		char oldstr[44]; /* hours strings are 42 bytes. */
		char newstr[44];
		DEBUG(15,("%s SAMR_FIELD_LOGON_HOURS (units_per_week): %08X -> %08X\n", l,
			pdb_get_logon_divs(to), from->logon_hours.units_per_week));
		if (from->logon_hours.units_per_week != pdb_get_logon_divs(to)) {
			pdb_set_logon_divs(to,
				from->logon_hours.units_per_week, PDB_CHANGED);
		}

		DEBUG(15,("%s SAMR_FIELD_LOGON_HOURS (units_per_week/8): %08X -> %08X\n", l,
			pdb_get_hours_len(to),
			from->logon_hours.units_per_week/8));
		if (from->logon_hours.units_per_week/8 != pdb_get_hours_len(to)) {
			pdb_set_hours_len(to,
				from->logon_hours.units_per_week/8, PDB_CHANGED);
		}

		DEBUG(15,("%s SAMR_FIELD_LOGON_HOURS (bits): %s -> %s\n", l,
			pdb_get_hours(to), from->logon_hours.bits));
		pdb_sethexhours(oldstr, pdb_get_hours(to));
		pdb_sethexhours(newstr, from->logon_hours.bits);
		if (!strequal(oldstr, newstr)) {
			pdb_set_hours(to, from->logon_hours.bits, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_BAD_PWD_COUNT) {
		DEBUG(10,("%s SAMR_FIELD_BAD_PWD_COUNT: %08X -> %08X\n", l,
			pdb_get_bad_password_count(to), from->bad_password_count));
		if (from->bad_password_count != pdb_get_bad_password_count(to)) {
			pdb_set_bad_password_count(to,
				from->bad_password_count, PDB_CHANGED);
		}
	}

	if (from->fields_present & SAMR_FIELD_NUM_LOGONS) {
		DEBUG(10,("%s SAMR_FIELD_NUM_LOGONS: %08X -> %08X\n", l,
			pdb_get_logon_count(to), from->logon_count));
		if (from->logon_count != pdb_get_logon_count(to)) {
			pdb_set_logon_count(to, from->logon_count, PDB_CHANGED);
		}
	}

	/* If the must change flag is set, the last set time goes to zero.
	   the must change and can change fields also do, but they are
	   calculated from policy, not set from the wire */

	if (from->fields_present & SAMR_FIELD_EXPIRED_FLAG) {
		DEBUG(10,("%s SAMR_FIELD_EXPIRED_FLAG: %02X\n", l,
			from->password_expired));
		if (from->password_expired == PASS_MUST_CHANGE_AT_NEXT_LOGON) {
			pdb_set_pass_last_set_time(to, 0, PDB_CHANGED);
		} else {
			/* A subtlety here: some windows commands will
			   clear the expired flag even though it's not
			   set, and we don't want to reset the time
			   in these caess.  "net user /dom <user> /active:y"
			   for example, to clear an autolocked acct.
			   We must check to see if it's expired first. jmcd */
			stored_time = pdb_get_pass_last_set_time(to);
			if (stored_time == 0)
				pdb_set_pass_last_set_time(to, time(NULL),PDB_CHANGED);
		}
	}
}


/*************************************************************
 Copies a struct samr_UserInfo23 to a struct samu
**************************************************************/

void copy_id23_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo23 *from)
{
	if (from == NULL || to == NULL) {
		return;
	}

	copy_id21_to_sam_passwd("INFO 23", to, &from->info);
}

/*************************************************************
 Copies a struct samr_UserInfo25 to a struct samu
**************************************************************/

void copy_id25_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo25 *from)
{
	if (from == NULL || to == NULL) {
		return;
	}

	copy_id21_to_sam_passwd("INFO_25", to, &from->info);
}
