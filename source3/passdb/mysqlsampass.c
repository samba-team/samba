/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  Samba MYSQL SAM Database, by Benjamin Kuit.
 *  Copyright (C) Benjamin Kuit                     1999,
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef WITH_MYSQLSAM

#include "includes.h"
#include <mysql.h>

extern int DEBUGLEVEL;

extern pstring samlogon_user;
extern BOOL sam_logon_in_ssb;

typedef void *(*mysql_fill_func)( MYSQL_ROW * );
#define FILL_SAM mysql_fill_sam_passwd

void *mysql_startpwent(BOOL update);
void mysql_endpwent(void *vp);
SMB_BIG_UINT mysql_getpwpos(void *vp);
BOOL mysql_setpwpos(void *vp, SMB_BIG_UINT pos);
void *mysql_fill_smb_passwd( MYSQL_ROW *row );
MYSQL_ROW *mysql_getpwent(void *vp);
void *mysql_fetch_passwd( mysql_fill_func filler, char *where );
void *mysql_getpwuid( mysql_fill_func filler, uid_t uid );
void *mysql_getpwnam( mysql_fill_func filler, char *field, const char *name );
int mysql_db_lock_connect( MYSQL *handle );
BOOL mysql_add_smb( MYSQL *handle, struct smb_passwd *smb );
BOOL mysql_mod_smb( MYSQL *handle, struct smb_passwd *smb, BOOL override );
BOOL mysql_del_smb( MYSQL *handle, char *unix_name );

void *mysql_fill_sam_passwd( MYSQL_ROW *row ) {
	static struct sam_passwd *user;

	static pstring full_name;
	static pstring home_dir;
	static pstring home_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring acct_desc;
	static pstring workstations;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	user = pwdb_smb_to_sam((struct smb_passwd *)mysql_fill_smb_passwd(row));

	if ( user == NULL ) {
		return NULL;
	}

	/* 'Researched' from sampass.c =) */

	pstrcpy(samlogon_user, user->unix_name);

	if (samlogon_user[strlen(samlogon_user)-1] == '$' && 
	    user->group_rid != DOMAIN_GROUP_RID_USERS)
	{
		DEBUG(0,("trust account %s should be in DOMAIN_GROUP_RID_USERS\n", samlogon_user));
	}

	/* XXXX hack to get standard_sub_basic() to use sam logon username */
	/* possibly a better way would be to do a become_user() call */
	sam_logon_in_ssb = True;

	pstrcpy(full_name    , "");
	pstrcpy(logon_script , lp_logon_script  ());
	pstrcpy(profile_path , lp_logon_path    ());
	pstrcpy(home_drive   , lp_logon_drive   ());
	pstrcpy(home_dir     , lp_logon_home    ());
	pstrcpy(acct_desc    , "");
	pstrcpy(workstations , "");

	sam_logon_in_ssb = False;

	user->full_name    = full_name;
	user->home_dir     = home_dir;
	user->dir_drive    = home_drive;
	user->logon_script = logon_script;
	user->profile_path = profile_path;
	user->acct_desc    = acct_desc;
	user->workstations = workstations;

	user->unknown_str = NULL; /* don't know, yet! */
	user->munged_dial = NULL; /* "munged" dial-back telephone number */

	user->unknown_3 = 0xffffff; /* don't know */
	user->logon_divs = 168; /* hours per week */
	user->hours_len = 21; /* 21 times 8 bits = 168 */
	memset(user->hours, 0xff, user->hours_len); /* available at all hours */
	user->unknown_5 = 0x00020000; /* don't know */
	user->unknown_6 = 0x000004ec; /* don't know */

	return (void*)user;
}

struct sam_passwd *mysql_getsampwent(void *vp) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return (struct sam_passwd*)mysql_fill_sam_passwd( mysql_getpwent(vp) );
}

struct sam_passwd *mysql_getsampwrid(uint32 rid) {
	fstring where;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	slprintf( where, sizeof(where), "user_rid=%lu", (long unsigned)rid);

	return (struct sam_passwd *)mysql_fetch_passwd( FILL_SAM, where );
}

struct sam_passwd *mysql_getsampwuid(uid_t uid) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return (struct sam_passwd *)mysql_getpwuid( FILL_SAM, uid );
}

struct sam_passwd *mysql_getsampwntnam(const char *nt_name) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return (struct sam_passwd *)mysql_getpwnam( FILL_SAM, "nt_name", nt_name);
}

struct sam_disp_info *mysql_getsamdispntnam(const char *nt_name) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return pwdb_sam_to_dispinfo(mysql_getsampwntnam(nt_name));
}

struct sam_disp_info *mysql_getsamdisprid(uint32 rid) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return pwdb_sam_to_dispinfo(mysql_getsampwrid(rid));
}

struct sam_disp_info *mysql_getsamdispent(void *vp) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return pwdb_sam_to_dispinfo(mysql_getsampwent(vp));
}

static BOOL mysql_mod_sam( MYSQL *handle, struct sam_passwd *sam, BOOL override ) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return True;
}

BOOL mysql_add_sampwd_entry(struct sam_passwd *sam) {
	MYSQL handle;
	struct smb_passwd *smb;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	smb = pwdb_sam_to_smb( sam );

	if ( smb == NULL ) {
		return False;
	}

	if ( mysql_db_lock_connect( &handle ) ) {
		return False;
	}

	if ( !mysql_add_smb( &handle, smb ) ) {
		mysql_close(&handle);
		return False;
	}

	if ( !mysql_mod_smb( &handle, smb, True ) ) {
		mysql_del_smb( &handle, smb->unix_name );
		mysql_close(&handle);
		return False;
	}

	if ( !mysql_mod_sam( &handle, sam, True ) ) {
		mysql_del_smb( &handle, smb->unix_name );
		mysql_close(&handle);
		return False;
	}

	mysql_close(&handle);
	return True;
}

BOOL mysql_mod_sampwd_entry(struct sam_passwd *sam, BOOL override) {
	MYSQL handle;
	struct smb_passwd *smb;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	smb = pwdb_sam_to_smb(sam);

	if ( smb == NULL ) {
		return False;
	}

	if ( mysql_db_lock_connect( &handle ) ) {
		return False;
	}

	if ( !mysql_mod_smb( &handle, smb, override ) ) {
		mysql_close(&handle);
		return False;
	}

	if ( !mysql_mod_sam( &handle, sam, override ) ) {
		mysql_close(&handle);
		return False;
	}

	mysql_close(&handle);
	return True;
}

static struct sam_passdb_ops sam_mysql_ops =
{
        mysql_startpwent,
        mysql_endpwent,
        mysql_getpwpos,
        mysql_setpwpos,
        mysql_getsampwntnam,
        mysql_getsampwuid,
        mysql_getsampwrid,
        mysql_getsampwent,
        mysql_add_sampwd_entry,
        mysql_mod_sampwd_entry,
        mysql_getsamdispntnam,
        mysql_getsamdisprid,
        mysql_getsamdispent
};

struct sam_passdb_ops *mysql_initialise_sam_password_db(void)
{
	return &sam_mysql_ops;
}

#else
	void mysql_dummy_sam_function(void) { }
#endif
