/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Simo Sorce 2000-2002
 * Copyright (C) Gerald Carter 2000
 * Copyright (C) Jeremy Allison 2001
 * Copyright (C) Andrew Bartlett 2002
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

#if 0 /* when made a module use this */

static int tdbsam_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbsam_debug_level

#else

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

#endif

#ifdef WITH_TDB_SAM

#define PDB_VERSION		"20010830"
#define PASSDB_FILE_NAME	"passdb.tdb"
#define TDB_FORMAT_STRING	"ddddddBBBBBBBBBBBBddBBwdwdBdd"
#define USERPREFIX		"USER_"
#define RIDPREFIX		"RID_"

struct tdbsam_privates {
	TDB_CONTEXT 	*passwd_tdb;
	TDB_DATA 	key;

	/* retrive-once info */
	const char *tdbsam_location;

	BOOL permit_non_unix_accounts;

	BOOL algorithmic_rids;

	uint32 low_nua_rid; 
	uint32 high_nua_rid;
};

/**********************************************************************
 Intialize a SAM_ACCOUNT struct from a BYTE buffer of size len
 *********************************************************************/

static BOOL init_sam_from_buffer (struct tdbsam_privates *tdb_state,
				  SAM_ACCOUNT *sampass, uint8 *buf, uint32 buflen)
{

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;
	char *username;
	char *domain;
	char *nt_username;
	char *dir_drive;
	char *unknown_str;
	char *munged_dial;
	char *fullname;
	char *homedir;
	char *logon_script;
	char *profile_path;
	char *acct_desc;
	char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;
		
	uint32	user_rid, group_rid, unknown_3, hours_len, unknown_5, unknown_6;
	uint16	acct_ctrl, logon_divs;
	uint8	*hours;
	static uint8	*lm_pw_ptr, *nt_pw_ptr;
	uint32		len = 0;
	uint32		lm_pw_len, nt_pw_len, hourslen;
	BOOL ret = True;
	struct passwd *pw;
	uid_t uid = -1;
	gid_t gid = -1; /* This is what standard sub advanced expects if no gid is known */
	
	if(sampass == NULL || buf == NULL) {
		DEBUG(0, ("init_sam_from_buffer: NULL parameters found!\n"));
		return False;
	}
									
	/* unpack the buffer into variables */
	len = tdb_unpack (buf, buflen, TDB_FORMAT_STRING,
		&logon_time,
		&logoff_time,
		&kickoff_time,
		&pass_last_set_time,
		&pass_can_change_time,
		&pass_must_change_time,
		&username_len, &username,
		&domain_len, &domain,
		&nt_username_len, &nt_username,
		&fullname_len, &fullname,
		&homedir_len, &homedir,
		&dir_drive_len, &dir_drive,
		&logon_script_len, &logon_script,
		&profile_path_len, &profile_path,
		&acct_desc_len, &acct_desc,
		&workstations_len, &workstations,
		&unknown_str_len, &unknown_str,
		&munged_dial_len, &munged_dial,
		&user_rid,
		&group_rid,
		&lm_pw_len, &lm_pw_ptr,
		&nt_pw_len, &nt_pw_ptr,
		&acct_ctrl,
		&unknown_3,
		&logon_divs,
		&hours_len,
		&hourslen, &hours,
		&unknown_5,
		&unknown_6);
		
	if (len == -1)  {
		ret = False;
		goto done;
	}

	/* validate the account and fill in UNIX uid and gid. Standard
	 * getpwnam() is used instead of Get_Pwnam() as we do not need
	 * to try case permutations
	 */
	if (!username || !(pw = getpwnam_alloc(username))) {
		if (!(tdb_state->permit_non_unix_accounts)) {
			DEBUG(0,("tdbsam: getpwnam_alloc(%s) return NULL.  User does not exist!\n", username));
			ret = False;
			goto done;
		}
	}
		
	if (pw) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		
		pdb_set_unix_homedir(sampass, pw->pw_dir, PDB_SET);

		passwd_free(&pw);

		pdb_set_uid(sampass, uid, PDB_SET);
		pdb_set_gid(sampass, gid, PDB_SET);
	}

	pdb_set_logon_time(sampass, logon_time, PDB_SET);
	pdb_set_logoff_time(sampass, logoff_time, PDB_SET);
	pdb_set_kickoff_time(sampass, kickoff_time, PDB_SET);
	pdb_set_pass_can_change_time(sampass, pass_can_change_time, PDB_SET);
	pdb_set_pass_must_change_time(sampass, pass_must_change_time, PDB_SET);
	pdb_set_pass_last_set_time(sampass, pass_last_set_time, PDB_SET);

	pdb_set_username     (sampass, username, PDB_SET); 
	pdb_set_domain       (sampass, domain, PDB_SET);
	pdb_set_nt_username  (sampass, nt_username, PDB_SET);
	pdb_set_fullname     (sampass, fullname, PDB_SET);

	if (homedir) {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}
	else {
		pdb_set_homedir(sampass, 
				talloc_sub_specified(sampass->mem_ctx, 
						       lp_logon_home(),
						       username, domain, 
						       uid, gid),
				PDB_DEFAULT);
	}

	if (dir_drive) 	
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	else {
		pdb_set_dir_drive(sampass, 
				  talloc_sub_specified(sampass->mem_ctx, 
							 lp_logon_drive(),
							 username, domain, 
							 uid, gid),
				  PDB_DEFAULT);
	}

	if (logon_script) 
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	else {
		pdb_set_logon_script(sampass, 
				     talloc_sub_specified(sampass->mem_ctx, 
							    lp_logon_script(),
							    username, domain, 
							    uid, gid),
				  PDB_DEFAULT);
	}
	
	if (profile_path) {	
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	} else {
		pdb_set_profile_path(sampass, 
				     talloc_sub_specified(sampass->mem_ctx, 
							    lp_logon_path(),
							    username, domain, 
							    uid, gid),
				     PDB_DEFAULT);
	}

	pdb_set_acct_desc    (sampass, acct_desc, PDB_SET);
	pdb_set_workstations (sampass, workstations, PDB_SET);
	pdb_set_munged_dial  (sampass, munged_dial, PDB_SET);

	if (lm_pw_ptr && lm_pw_len == LM_HASH_LEN) {
		if (!pdb_set_lanman_passwd(sampass, lm_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	if (nt_pw_ptr && nt_pw_len == NT_HASH_LEN) {
		if (!pdb_set_nt_passwd(sampass, nt_pw_ptr, PDB_SET)) {
			ret = False;
			goto done;
		}
	}

	pdb_set_user_sid_from_rid(sampass, user_rid, PDB_SET);
	pdb_set_group_sid_from_rid(sampass, group_rid, PDB_SET);
	pdb_set_unknown_3(sampass, unknown_3, PDB_SET);
	pdb_set_hours_len(sampass, hours_len, PDB_SET);
	pdb_set_unknown_5(sampass, unknown_5, PDB_SET);
	pdb_set_unknown_6(sampass, unknown_6, PDB_SET);
	pdb_set_acct_ctrl(sampass, acct_ctrl, PDB_SET);
	pdb_set_logon_divs(sampass, logon_divs, PDB_SET);
	pdb_set_hours(sampass, hours, PDB_SET);

done:

	SAFE_FREE(username);
	SAFE_FREE(domain);
	SAFE_FREE(nt_username);
	SAFE_FREE(fullname);
	SAFE_FREE(homedir);
	SAFE_FREE(dir_drive);
	SAFE_FREE(logon_script);
	SAFE_FREE(profile_path);
	SAFE_FREE(acct_desc);
	SAFE_FREE(workstations);
	SAFE_FREE(munged_dial);

	return ret;
}

/**********************************************************************
 Intialize a BYTE buffer from a SAM_ACCOUNT struct
 *********************************************************************/
static uint32 init_buffer_from_sam (struct tdbsam_privates *tdb_state,
				    uint8 **buf, const SAM_ACCOUNT *sampass)
{
	size_t		len, buflen;

	/* times are stored as 32bit integer
	   take care on system with 64bit wide time_t
	   --SSS */
	uint32	logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;

	uint32  user_rid, group_rid;

	const char *username;
	const char *domain;
	const char *nt_username;
	const char *dir_drive;
	const char *unknown_str;
	const char *munged_dial;
	const char *fullname;
	const char *homedir;
	const char *logon_script;
	const char *profile_path;
	const char *acct_desc;
	const char *workstations;
	uint32	username_len, domain_len, nt_username_len,
		dir_drive_len, unknown_str_len, munged_dial_len,
		fullname_len, homedir_len, logon_script_len,
		profile_path_len, acct_desc_len, workstations_len;

	const uint8 *lm_pw;
	const uint8 *nt_pw;
	uint32	lm_pw_len = 16;
	uint32	nt_pw_len = 16;

	/* do we have a valid SAM_ACCOUNT pointer? */
	if (sampass == NULL) {
		DEBUG(0, ("init_buffer_from_sam: SAM_ACCOUNT is NULL!\n"));
		return -1;
	}
	
	*buf = NULL;
	buflen = 0;

	logon_time = (uint32)pdb_get_logon_time(sampass);
	logoff_time = (uint32)pdb_get_logoff_time(sampass);
	kickoff_time = (uint32)pdb_get_kickoff_time(sampass);
	pass_can_change_time = (uint32)pdb_get_pass_can_change_time(sampass);
	pass_must_change_time = (uint32)pdb_get_pass_must_change_time(sampass);
	pass_last_set_time = (uint32)pdb_get_pass_last_set_time(sampass);

	user_rid = pdb_get_user_rid(sampass);
	group_rid = pdb_get_group_rid(sampass);

	username = pdb_get_username(sampass);
	if (username) username_len = strlen(username) +1;
	else username_len = 0;

	domain = pdb_get_domain(sampass);
	if (domain) domain_len = strlen(domain) +1;
	else domain_len = 0;

	nt_username = pdb_get_nt_username(sampass);
	if (nt_username) nt_username_len = strlen(nt_username) +1;
	else nt_username_len = 0;

	fullname = pdb_get_fullname(sampass);
	if (fullname) fullname_len = strlen(fullname) +1;
	else fullname_len = 0;

	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */

	if (!IS_SAM_DEFAULT(sampass, PDB_DRIVE)) 
	  dir_drive = pdb_get_dir_drive(sampass);
	else dir_drive = NULL;
	if (dir_drive) dir_drive_len = strlen(dir_drive) +1;
	else dir_drive_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_SMBHOME)) homedir = pdb_get_homedir(sampass);
	else homedir = NULL;
	if (homedir) homedir_len = strlen(homedir) +1;
	else homedir_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_LOGONSCRIPT)) logon_script = pdb_get_logon_script(sampass);
	else logon_script = NULL;
	if (logon_script) logon_script_len = strlen(logon_script) +1;
	else logon_script_len = 0;

	if (!IS_SAM_DEFAULT(sampass, PDB_PROFILE)) profile_path = pdb_get_profile_path(sampass);
	else profile_path = NULL;
	if (profile_path) profile_path_len = strlen(profile_path) +1;
	else profile_path_len = 0;
	
	lm_pw = pdb_get_lanman_passwd(sampass);
	if (!lm_pw) lm_pw_len = 0;
	
	nt_pw = pdb_get_nt_passwd(sampass);
	if (!nt_pw) nt_pw_len = 0;
		
	acct_desc = pdb_get_acct_desc(sampass);
	if (acct_desc) acct_desc_len = strlen(acct_desc) +1;
	else acct_desc_len = 0;

	workstations = pdb_get_workstations(sampass);
	if (workstations) workstations_len = strlen(workstations) +1;
	else workstations_len = 0;

	unknown_str = NULL;
	unknown_str_len = 0;

	munged_dial = pdb_get_munged_dial(sampass);
	if (munged_dial) munged_dial_len = strlen(munged_dial) +1;
	else munged_dial_len = 0;	
		
	/* one time to get the size needed */
	len = tdb_pack(NULL, 0,  TDB_FORMAT_STRING,
		logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		pdb_get_unknown_3(sampass),
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_unknown_5(sampass),
		pdb_get_unknown_6(sampass));


	/* malloc the space needed */
	if ( (*buf=(uint8*)malloc(len)) == NULL) {
		DEBUG(0,("init_buffer_from_sam: Unable to malloc() memory for buffer!\n"));
		return (-1);
	}
	
	/* now for the real call to tdb_pack() */
	buflen = tdb_pack(*buf, len,  TDB_FORMAT_STRING,
		logon_time,
		logoff_time,
		kickoff_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time,
		username_len, username,
		domain_len, domain,
		nt_username_len, nt_username,
		fullname_len, fullname,
		homedir_len, homedir,
		dir_drive_len, dir_drive,
		logon_script_len, logon_script,
		profile_path_len, profile_path,
		acct_desc_len, acct_desc,
		workstations_len, workstations,
		unknown_str_len, unknown_str,
		munged_dial_len, munged_dial,
		user_rid,
		group_rid,
		lm_pw_len, lm_pw,
		nt_pw_len, nt_pw,
		pdb_get_acct_ctrl(sampass),
		pdb_get_unknown_3(sampass),
		pdb_get_logon_divs(sampass),
		pdb_get_hours_len(sampass),
		MAX_HOURS_LEN, pdb_get_hours(sampass),
		pdb_get_unknown_5(sampass),
		pdb_get_unknown_6(sampass));
	
	
	/* check to make sure we got it correct */
	if (buflen != len) {
		DEBUG(0, ("init_buffer_from_sam: somthing odd is going on here: bufflen (%d) != len (%d) in tdb_pack operations!\n", 
			  buflen, len));  
		/* error */
		SAFE_FREE (*buf);
		return (-1);
	}

	return (buflen);
}

/***************************************************************
 Open the TDB passwd database for SAM account enumeration.
****************************************************************/

static NTSTATUS tdbsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	
	/* Open tdb passwd */
	if (!(tdb_state->passwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, update?(O_RDWR|O_CREAT):O_RDONLY, 0600)))
	{
		DEBUG(0, ("Unable to open/create TDB passwd\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	tdb_state->key = tdb_firstkey(tdb_state->passwd_tdb);

	return NT_STATUS_OK;
}

static void close_tdb(struct tdbsam_privates *tdb_state) 
{
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}
}

/***************************************************************
 End enumeration of the TDB passwd list.
****************************************************************/

static void tdbsam_endsampwent(struct pdb_methods *my_methods)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	close_tdb(tdb_state);
	
	DEBUG(7, ("endtdbpwent: closed sam database.\n"));
}

/*****************************************************************
 Get one SAM_ACCOUNT from the TDB (next in line)
*****************************************************************/

static NTSTATUS tdbsam_getsampwent(struct pdb_methods *my_methods, SAM_ACCOUNT *user)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_DATA 	data;
	const char *prefix = USERPREFIX;
	int  prefixlen = strlen (prefix);


	if (user==NULL) {
		DEBUG(0,("pdb_get_sampwent: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* skip all non-USER entries (eg. RIDs) */
	while ((tdb_state->key.dsize != 0) && (strncmp(tdb_state->key.dptr, prefix, prefixlen)))
		/* increment to next in line */
		tdb_state->key = tdb_nextkey(tdb_state->passwd_tdb, tdb_state->key);

	/* do we have an valid iteration pointer? */
	if(tdb_state->passwd_tdb == NULL) {
		DEBUG(0,("pdb_get_sampwent: Bad TDB Context pointer.\n"));
		return nt_status;
	}

	data = tdb_fetch(tdb_state->passwd_tdb, tdb_state->key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwent: database entry not found.\n"));
		return nt_status;
	}
  
  	/* unpack the buffer */
	if (!init_sam_from_buffer(tdb_state, user, data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		SAFE_FREE(data.dptr);
		return nt_status;
	}
	SAFE_FREE(data.dptr);
	
	/* increment to next in line */
	tdb_state->key = tdb_nextkey(tdb_state->passwd_tdb, tdb_state->key);

	return NT_STATUS_OK;
}

/******************************************************************
 Lookup a name in the SAM TDB
******************************************************************/

static NTSTATUS tdbsam_getsampwnam (struct pdb_methods *my_methods, SAM_ACCOUNT *user, const char *sname)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	data, key;
	fstring 	keystr;
	fstring		name;

	if (user==NULL) {
		DEBUG(0,("pdb_getsampwnam: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* Data is stored in all lower-case */
	unix_strlower(sname, -1, name, sizeof(name));

	/* set search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDONLY, 0600))) {
		DEBUG(0, ("pdb_getsampwnam: Unable to open TDB passwd (%s)!\n", tdb_state->tdbsam_location));
		return nt_status;
	}

	/* get the record */
	data = tdb_fetch(pwd_tdb, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		tdb_close(pwd_tdb);
		return nt_status;
	}
  
  	/* unpack the buffer */
	if (!init_sam_from_buffer(tdb_state, user, data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad SAM_ACCOUNT entry returned from TDB!\n"));
		SAFE_FREE(data.dptr);
		tdb_close(pwd_tdb);
		return nt_status;
	}
	SAFE_FREE(data.dptr);

	/* no further use for database, close it now */
	tdb_close(pwd_tdb);
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Search by rid
 **************************************************************************/

static NTSTATUS tdbsam_getsampwrid (struct pdb_methods *my_methods, SAM_ACCOUNT *user, uint32 rid)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 		*pwd_tdb;
	TDB_DATA 		data, key;
	fstring 		keystr;
	fstring			name;
	
	if (user==NULL) {
		DEBUG(0,("pdb_getsampwrid: SAM_ACCOUNT is NULL.\n"));
		return nt_status;
	}

	/* set search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* open the accounts TDB */
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDONLY, 0600))) {
		DEBUG(0, ("pdb_getsampwrid: Unable to open TDB rid database!\n"));
		return nt_status;
	}

	/* get the record */
	data = tdb_fetch (pwd_tdb, key);
	if (!data.dptr) {
		DEBUG(5,("pdb_getsampwrid (TDB): error looking up RID %d by key %s.\n", rid, keystr));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close (pwd_tdb);
		return nt_status;
	}

	fstrcpy (name, data.dptr);
	SAFE_FREE(data.dptr);
	
	tdb_close (pwd_tdb);
	
	return tdbsam_getsampwnam (my_methods, user, name);
}

static NTSTATUS tdbsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_UNSUCCESSFUL;
	return tdbsam_getsampwrid(my_methods, user, rid);
}

/***************************************************************************
 Delete a SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_delete_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT *sam_pass)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb;
	TDB_DATA 	key;
	fstring 	keystr;
	uint32		rid;
	fstring		name;
	
	unix_strlower(pdb_get_username(sam_pass), -1, name, sizeof(name));
	
	/* open the TDB */
	if (!(pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDWR, 0600))) {
		DEBUG(0, ("Unable to open TDB passwd!"));
		return nt_status;
	}
  
  	/* set the search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	rid = pdb_get_user_rid(sam_pass);

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("Error deleting entry from tdb passwd database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return nt_status;
	}	

	/* delete also the RID key */

  	/* set the search key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* it's outaa here!  8^) */
	if (tdb_delete(pwd_tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("Error deleting entry from tdb rid database!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		tdb_close(pwd_tdb); 
		return nt_status;
	}
	
	tdb_close(pwd_tdb);
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Update the TDB SAM
****************************************************************************/

static BOOL tdb_update_sam(struct pdb_methods *my_methods, SAM_ACCOUNT* newpwd, int flag)
{
	struct tdbsam_privates *tdb_state = (struct tdbsam_privates *)my_methods->private_data;
	TDB_CONTEXT 	*pwd_tdb = NULL;
	TDB_DATA 	key, data;
	uint8		*buf = NULL;
	fstring 	keystr;
	fstring		name;
	BOOL		ret = True;
	uint32		user_rid;
	BOOL		tdb_ret;

	/* invalidate the existing TDB iterator if it is open */
	if (tdb_state->passwd_tdb) {
		tdb_close(tdb_state->passwd_tdb);
		tdb_state->passwd_tdb = NULL;
	}

 	/* open the account TDB passwd*/
	pwd_tdb = tdb_open_log(tdb_state->tdbsam_location, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600);
  	if (!pwd_tdb)
	{
		DEBUG(0, ("tdb_update_sam: Unable to open TDB passwd (%s)!\n", tdb_state->tdbsam_location));
		return False;
	}

	/* if flag == TDB_INSERT then make up a new RID else throw an error. */
	if (!(user_rid = pdb_get_user_rid(newpwd))) {
		if (flag & TDB_INSERT) {
			if (IS_SAM_UNIX_USER(newpwd)) {
				if (tdb_state->algorithmic_rids) {
					user_rid = fallback_pdb_uid_to_user_rid(pdb_get_uid(newpwd));
				} else {
					user_rid = BASE_RID;
					tdb_ret = tdb_change_uint32_atomic(pwd_tdb, "RID_COUNTER", &user_rid, RID_MULTIPLIER);
					if (!tdb_ret) {
						ret = False;
						goto done;
					}
				}
				pdb_set_user_sid_from_rid(newpwd, user_rid, PDB_CHANGED);
			} else {
				user_rid = tdb_state->low_nua_rid;
				tdb_ret = tdb_change_uint32_atomic(pwd_tdb, "NUA_RID_COUNTER", &user_rid, RID_MULTIPLIER);
				if (!tdb_ret) {
					ret = False;
					goto done;
				}
				if (user_rid > tdb_state->high_nua_rid) {
					DEBUG(0, ("tdbsam: no NUA rids available, cannot add user %s!\n", pdb_get_username(newpwd)));
					ret = False;
					goto done;
				}
				pdb_set_user_sid_from_rid(newpwd, user_rid, PDB_CHANGED);
			}
		} else {
			DEBUG (0,("tdb_update_sam: Failing to store a SAM_ACCOUNT for [%s] without a RID\n",pdb_get_username(newpwd)));
			ret = False;
			goto done;
		}
	}

	if (!pdb_get_group_rid(newpwd)) {
		if (flag & TDB_INSERT) {
			if (!tdb_state->permit_non_unix_accounts) {
				DEBUG (0,("tdb_update_sam: Failing to store a SAM_ACCOUNT for [%s] without a primary group RID\n",pdb_get_username(newpwd)));
				ret = False;
				goto done;
			} else {
				/* This seems like a good default choice for non-unix users */
				pdb_set_group_sid_from_rid(newpwd, DOMAIN_GROUP_RID_USERS, PDB_DEFAULT);
			}
		} else {
			DEBUG (0,("tdb_update_sam: Failing to store a SAM_ACCOUNT for [%s] without a primary group RID\n",pdb_get_username(newpwd)));
			ret = False;
			goto done;
		}
	}

	/* copy the SAM_ACCOUNT struct into a BYTE buffer for storage */
	if ((data.dsize=init_buffer_from_sam (tdb_state, &buf, newpwd)) == -1) {
		DEBUG(0,("tdb_update_sam: ERROR - Unable to copy SAM_ACCOUNT info BYTE buffer!\n"));
		ret = False;
		goto done;
	}
	data.dptr = buf;

	unix_strlower(pdb_get_username(newpwd), -1, name, sizeof(name));
	
	DEBUG(5, ("Storing %saccount %s with RID %d\n", flag == TDB_INSERT ? "(new) " : "", name, user_rid));

  	/* setup the USER index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%s", USERPREFIX, name);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;

	/* add the account */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify passwd TDB!"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		ret = False;
		goto done;
	}
	
	/* setup RID data */
	data.dsize = sizeof(fstring);
	data.dptr = name;

	/* setup the RID index key */
	slprintf(keystr, sizeof(keystr)-1, "%s%.8x", RIDPREFIX, user_rid);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* add the reference */
	if (tdb_store(pwd_tdb, key, data, flag) != TDB_SUCCESS) {
		DEBUG(0, ("Unable to modify TDB passwd !"));
		DEBUGADD(0, (" Error: %s\n", tdb_errorstr(pwd_tdb)));
		DEBUGADD(0, (" occured while storing the RID index (%s)\n", keystr));
		ret = False;
		goto done;
	}

done:	
	/* cleanup */
	tdb_close (pwd_tdb);
	SAFE_FREE(buf);
	
	return (ret);	
}

/***************************************************************************
 Modifies an existing SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_update_sam_account (struct pdb_methods *my_methods, SAM_ACCOUNT *newpwd)
{
	if (tdb_update_sam(my_methods, newpwd, TDB_MODIFY))
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

/***************************************************************************
 Adds an existing SAM_ACCOUNT
****************************************************************************/

static NTSTATUS tdbsam_add_sam_account (struct pdb_methods *my_methods, SAM_ACCOUNT *newpwd)
{
	if (tdb_update_sam(my_methods, newpwd, TDB_INSERT))
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				DOM_SID sid, BOOL with_priv)
{
	return get_group_map_from_sid(sid, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				gid_t gid, BOOL with_priv)
{
	return get_group_map_from_gid(gid, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				char *name, BOOL with_priv)
{
	return get_group_map_from_ntname(name, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_add_group_mapping_entry(struct pdb_methods *methods,
					       GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_INSERT) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_update_group_mapping_entry(struct pdb_methods *methods,
						  GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_REPLACE) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_delete_group_mapping_entry(struct pdb_methods *methods,
						  DOM_SID sid)
{
	return group_map_remove(sid) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS tdbsam_enum_group_mapping(struct pdb_methods *methods,
					  enum SID_NAME_USE sid_name_use,
					  GROUP_MAP **rmap, int *num_entries,
					  BOOL unix_only, BOOL with_priv)
{
	return enum_group_mapping(sid_name_use, rmap, num_entries, unix_only,
				  with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static void free_private_data(void **vp) 
{
	struct tdbsam_privates **tdb_state = (struct tdbsam_privates **)vp;
	close_tdb(*tdb_state);
	*tdb_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}


NTSTATUS pdb_init_tdbsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct tdbsam_privates *tdb_state;

#if 0 /* when made a module use this */
	tdbsam_debug_level = debug_add_class("tdbsam");
	if(tdbsam_debug_level == -1) {
		tdbsam_debug_level = DBGC_ALL;
		DEBUG(0, ("tdbsam: Couldn't register custom debugging class!\n"));
	}
#endif

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "tdbsam";

	(*pdb_method)->setsampwent = tdbsam_setsampwent;
	(*pdb_method)->endsampwent = tdbsam_endsampwent;
	(*pdb_method)->getsampwent = tdbsam_getsampwent;
	(*pdb_method)->getsampwnam = tdbsam_getsampwnam;
	(*pdb_method)->getsampwsid = tdbsam_getsampwsid;
	(*pdb_method)->add_sam_account = tdbsam_add_sam_account;
	(*pdb_method)->update_sam_account = tdbsam_update_sam_account;
	(*pdb_method)->delete_sam_account = tdbsam_delete_sam_account;
	(*pdb_method)->getgrsid = tdbsam_getgrsid;
	(*pdb_method)->getgrgid = tdbsam_getgrgid;
	(*pdb_method)->getgrnam = tdbsam_getgrnam;
	(*pdb_method)->add_group_mapping_entry = tdbsam_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = tdbsam_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = tdbsam_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = tdbsam_enum_group_mapping;

	tdb_state = talloc_zero(pdb_context->mem_ctx, sizeof(struct tdbsam_privates));

	if (!tdb_state) {
		DEBUG(0, ("talloc() failed for tdbsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		tdb_state->tdbsam_location = talloc_strdup(pdb_context->mem_ctx, location);
	} else {
		pstring tdbfile;
		get_private_directory(tdbfile);
		pstrcat(tdbfile, "/");
		pstrcat(tdbfile, PASSDB_FILE_NAME);
		tdb_state->tdbsam_location = talloc_strdup(pdb_context->mem_ctx, tdbfile);
	}

	tdb_state->algorithmic_rids = True;

	(*pdb_method)->private_data = tdb_state;

	(*pdb_method)->free_private_data = free_private_data;

	return NT_STATUS_OK;
}

NTSTATUS pdb_init_tdbsam_nua(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct tdbsam_privates *tdb_state;
	uint32 low_nua_uid, high_nua_uid;

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_tdbsam(pdb_context, pdb_method, location))) {
		return nt_status;
	}

	(*pdb_method)->name = "tdbsam_nua";

	tdb_state = (*pdb_method)->private_data;

	tdb_state->permit_non_unix_accounts = True;

	if (!lp_non_unix_account_range(&low_nua_uid, &high_nua_uid)) {
		DEBUG(0, ("cannot use tdbsam_nua without 'non unix account range' in smb.conf!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	tdb_state->low_nua_rid=fallback_pdb_uid_to_user_rid(low_nua_uid);

	tdb_state->high_nua_rid=fallback_pdb_uid_to_user_rid(high_nua_uid);

	return NT_STATUS_OK;
}


#else

NTSTATUS pdb_init_tdbsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("tdbsam not compiled in!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_init_tdbsam_nua(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("tdbsam_nua not compiled in!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


#endif
