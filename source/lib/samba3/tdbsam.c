/* 
   Unix SMB/CIFS implementation.
   tdb passdb backend format routines

	Copyright (C) Simo Sorce        2000-2003
    Copyright (C) Jelmer Vernooij 	2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "lib/samba3/samba3.h"

#define TDB_FORMAT_STRING_V0       "ddddddBBBBBBBBBBBBddBBwdwdBwwd"
#define TDB_FORMAT_STRING_V1       "dddddddBBBBBBBBBBBBddBBwdwdBwwd"
#define TDB_FORMAT_STRING_V2       "dddddddBBBBBBBBBBBBddBBBwwdBwwd"
#define TDBSAM_VERSION_STRING      "INFO/version"

static BOOL init_sam_from_buffer_v0(TDB_CONTEXT *tdb, struct samba3_samaccount *sampass, TDB_DATA buf)
{
	uint32_t	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32_t	remove_me;
	uint32_t		len = 0;
	uint32_t		lm_pw_len, nt_pw_len, hourslen;
	
	if(sampass == NULL || buf.dptr == NULL) {
		DEBUG(0, ("init_sam_from_buffer_v0: NULL parameters found!\n"));
		return False;
	}

	/* unpack the buffer into variables */
	len = tdb_unpack (tdb, (char *)buf.dptr, buf.dsize, TDB_FORMAT_STRING_V0,
		&sampass->logon_time,					/* d */
		&sampass->logoff_time,					/* d */
		&sampass->kickoff_time,					/* d */
		&sampass->pass_last_set_time,				/* d */
		&sampass->pass_can_change_time,				/* d */
		&sampass->pass_must_change_time,			/* d */
		&username_len, &sampass->username,			/* B */
		&domain_len, &sampass->domain,				/* B */
		&nt_username_len, &sampass->nt_username,		/* B */
		&fullname_len, &sampass->fullname,			/* B */
		&homedir_len, &sampass->homedir,			/* B */
		&dir_drive_len, &sampass->dir_drive,			/* B */
		&logon_script_len, &sampass->logon_script,		/* B */
		&profile_path_len, &sampass->profile_path,		/* B */
		&acct_desc_len, &sampass->acct_desc,			/* B */
		&workstations_len, &sampass->workstations,		/* B */
		&unknown_str_len, &sampass->unknown_str,		/* B */
		&munged_dial_len, &sampass->munged_dial,		/* B */
		&sampass->user_rid,					/* d */
		&sampass->group_rid,					/* d */
		&lm_pw_len, sampass->lm_pw.hash,			/* B */
		&nt_pw_len, sampass->nt_pw.hash,			/* B */
		&sampass->acct_ctrl,					/* w */
		&remove_me, /* remove on the next TDB_FORMAT upgarde */	/* d */
		&sampass->logon_divs,					/* w */
		&sampass->hours_len,					/* d */
		&hourslen, &sampass->hours,				/* B */
		&sampass->bad_password_count,				/* w */
		&sampass->logon_count,					/* w */
		&sampass->unknown_6);					/* d */
		
	if (len == (uint32_t) -1)  {
		return False;
	}

	return True;
}

static BOOL init_sam_from_buffer_v1(TDB_CONTEXT *tdb, struct samba3_samaccount *sampass, TDB_DATA buf)
{
	uint32_t	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32_t	remove_me;
	uint32_t		len = 0;
	uint32_t		lm_pw_len, nt_pw_len, hourslen;
	
	if(sampass == NULL || buf.dptr == NULL) {
		DEBUG(0, ("init_sam_from_buffer_v1: NULL parameters found!\n"));
		return False;
	}

	/* unpack the buffer into variables */
	len = tdb_unpack (tdb, (char *)buf.dptr, buf.dsize, TDB_FORMAT_STRING_V1,
		&sampass->logon_time,					/* d */
		&sampass->logoff_time,					/* d */
		&sampass->kickoff_time,				/* d */
		/* Change from V0 is addition of bad_password_time field. */
		&sampass->bad_password_time,				/* d */
		&sampass->pass_last_set_time,				/* d */
		&sampass->pass_can_change_time,			/* d */
		&sampass->pass_must_change_time,			/* d */
		&username_len, &sampass->username,			/* B */
		&domain_len, &sampass->domain,		/* B */
		&nt_username_len, &sampass->nt_username,	/* B */
		&fullname_len, &sampass->fullname,			/* B */
		&homedir_len, &sampass->homedir,			/* B */
		&dir_drive_len, &sampass->dir_drive,			/* B */
		&logon_script_len, &sampass->logon_script,		/* B */
		&profile_path_len, &sampass->profile_path,		/* B */
		&acct_desc_len, &sampass->acct_desc,			/* B */
		&workstations_len, &sampass->workstations,		/* B */
		&unknown_str_len, &sampass->unknown_str,		/* B */
		&munged_dial_len, &sampass->munged_dial,		/* B */
		&sampass->user_rid,					/* d */
		&sampass->group_rid,					/* d */
		&lm_pw_len, sampass->lm_pw.hash,			/* B */
		&nt_pw_len, sampass->nt_pw.hash,			/* B */
		&sampass->acct_ctrl,					/* w */
		&remove_me,						/* d */
		&sampass->logon_divs,					/* w */
		&sampass->hours_len,					/* d */
		&hourslen, &sampass->hours,				/* B */
		&sampass->bad_password_count,				/* w */
		&sampass->logon_count,					/* w */
		&sampass->unknown_6);					/* d */
		
	if (len == (uint32_t) -1)  {
		return False;
	}

	return True;
}

static BOOL init_sam_from_buffer_v2(TDB_CONTEXT *tdb, struct samba3_samaccount *sampass, TDB_DATA buf)
{
	uint32_t	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32_t		len = 0;
	uint32_t		lm_pw_len, nt_pw_len, nt_pw_hist_len, hourslen;
	
	if(sampass == NULL || buf.dptr == NULL) {
		DEBUG(0, ("init_sam_from_buffer_v2: NULL parameters found!\n"));
		return False;
	}

	/* unpack the buffer into variables */
	len = tdb_unpack (tdb, (char *)buf.dptr, buf.dsize, TDB_FORMAT_STRING_V2,
		&sampass->logon_time,					/* d */
		&sampass->logoff_time,					/* d */
		&sampass->kickoff_time,					/* d */
		&sampass->bad_password_time,				/* d */
		&sampass->pass_last_set_time,				/* d */
		&sampass->pass_can_change_time,				/* d */
		&sampass->pass_must_change_time,			/* d */
		&username_len, &sampass->username,			/* B */
		&domain_len, &sampass->domain,				/* B */
		&nt_username_len, &sampass->nt_username,		/* B */
		&fullname_len, &sampass->fullname,			/* B */
		&homedir_len, &sampass->homedir,			/* B */
		&dir_drive_len, &sampass->dir_drive,			/* B */
		&logon_script_len, &sampass->logon_script,		/* B */
		&profile_path_len, &sampass->profile_path,		/* B */
		&acct_desc_len, &sampass->acct_desc,			/* B */
		&workstations_len, &sampass->workstations,		/* B */
		&unknown_str_len, &sampass->unknown_str,		/* B */
		&munged_dial_len, &sampass->munged_dial,		/* B */
		&sampass->user_rid,					/* d */
		&sampass->group_rid,					/* d */
		&lm_pw_len, sampass->lm_pw.hash,			/* B */
		&nt_pw_len, sampass->nt_pw.hash,			/* B */
		/* Change from V1 is addition of password history field. */
		&nt_pw_hist_len, &sampass->nt_pw_hist_ptr,		/* B */
		&sampass->acct_ctrl,					/* w */
		/* Also "remove_me" field was removed. */
		&sampass->logon_divs,					/* w */
		&sampass->hours_len,					/* d */
		&hourslen, &sampass->hours,				/* B */
		&sampass->bad_password_count,				/* w */
		&sampass->logon_count,					/* w */
		&sampass->unknown_6);					/* d */
		
	if (len == (uint32_t) -1)  {
		return False;
	}

	return True;
}

NTSTATUS samba3_read_tdbsam(const char *filename, TALLOC_CTX *ctx, struct samba3_samaccount **accounts, uint32_t *count)
{
	int32_t version;
	TDB_CONTEXT *tdb;
	TDB_DATA key, val;

	/* Try to open tdb passwd */
	if (!(tdb = tdb_open(filename, 0, TDB_DEFAULT, O_RDONLY, 0600))) {
		DEBUG(0, ("Unable to open TDB passwd file '%s'\n", filename));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Check the version */
	version = tdb_fetch_int32(tdb, 
						TDBSAM_VERSION_STRING);
	if (version == -1)
		version = 0;	/* Version not found, assume version 0 */
	
	/* Compare the version */
	if (version > 2) {
		/* Version more recent than the latest known */ 
		DEBUG(0, ("TDBSAM version unknown: %d\n", version));
		tdb_close(tdb);
		return NT_STATUS_NOT_SUPPORTED;
	} 
	
	*accounts = NULL;
	*count = 0;

	for (key = tdb_firstkey(tdb); key.dptr; key = tdb_nextkey(tdb, key))
	{
		BOOL ret;
		if (strncmp((const char *)key.dptr, "USER_", 5) != 0) 
			continue;

		val = tdb_fetch(tdb, key);

		*accounts = talloc_realloc(ctx, *accounts, struct samba3_samaccount, (*count)+1);

		switch (version) 
		{
			case 0: ret = init_sam_from_buffer_v0(tdb, &(*accounts)[*count], val); break;
			case 1: ret = init_sam_from_buffer_v1(tdb, &(*accounts)[*count], val); break;
			case 2: ret = init_sam_from_buffer_v2(tdb, &(*accounts)[*count], val); break;
			default: ret = False; break;

		}

		if (!ret) {
			DEBUG(0, ("Unable to parse SAM account %s\n", key.dptr));
		}

		(*count)++;
	}
	
	tdb_close(tdb);
	
	return NT_STATUS_OK;
}
