/* 
 *  Unix SMB/CIFS implementation.
 *  account policy storage
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Andrew Bartlett              2002
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

#include "includes.h"
static TDB_CONTEXT *tdb; 

#define DATABASE_VERSION 2

extern DOM_SID global_sid_World;
extern DOM_SID global_sid_Builtin_Administrators;
extern DOM_SID global_sid_Builtin_Account_Operators;
extern DOM_SID global_sid_Builtin_Server_Operators;
extern DOM_SID global_sid_Builtin_Print_Operators;
extern DOM_SID global_sid_Builtin_Backup_Operators;


/****************************************************************************
 Set default for a field if it is empty
****************************************************************************/

static void set_default_on_empty(int field, uint32 value)
{
	if (account_policy_get(field, NULL))
		return;
	account_policy_set(field, value);
	return;
}

/****************************************************************************
 Open the account policy tdb.
****************************************************************************/

BOOL init_account_policy(void)
{
	const char *vstring = "INFO/version";
	uint32 version;

	if (tdb)
		return True;
	tdb = tdb_open_log(lock_path("account_policy.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open account policy database\n"));
		return False;
	}

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring,0);
	if (!tdb_fetch_uint32(tdb, vstring, &version) || version != DATABASE_VERSION) {
		tdb_store_uint32(tdb, vstring, DATABASE_VERSION);
		
		set_default_on_empty(
			AP_MIN_PASSWORD_LEN, 
			MINPASSWDLENGTH);/* 5 chars minimum             */
		set_default_on_empty(
			AP_PASSWORD_HISTORY, 
			0);		/* don't keep any old password	*/
		set_default_on_empty(
			AP_USER_MUST_LOGON_TO_CHG_PASS, 
			0);		/* don't force user to logon	*/
		set_default_on_empty(
			AP_MAX_PASSWORD_AGE, 
			(uint32)-1);	/* don't expire			*/
		set_default_on_empty(
			AP_MIN_PASSWORD_AGE, 
			0);		/* 0 days                      */
		set_default_on_empty(
			AP_LOCK_ACCOUNT_DURATION, 
			30);		/* lockout for 30 minutes      */
		set_default_on_empty(
			AP_RESET_COUNT_TIME, 
			30);		/* reset after 30 minutes      */
		set_default_on_empty(
			AP_BAD_ATTEMPT_LOCKOUT, 
			0);		/* don't lockout               */
		set_default_on_empty(
			AP_TIME_TO_LOGOUT, 
			-1);		/* don't force logout          */
		set_default_on_empty(
			AP_REFUSE_MACHINE_PW_CHANGE, 
			0);		/* allow machine pw changes    */
	}
	tdb_unlock_bystring(tdb, vstring);

	/* These exist by default on NT4 in [HKLM\SECURITY\Policy\Accounts] */

	privilege_create_account( &global_sid_World );
	privilege_create_account( &global_sid_Builtin_Administrators );
	privilege_create_account( &global_sid_Builtin_Account_Operators );
	privilege_create_account( &global_sid_Builtin_Server_Operators );
	privilege_create_account( &global_sid_Builtin_Print_Operators );
	privilege_create_account( &global_sid_Builtin_Backup_Operators );
	
	return True;
}

static const struct {
	int field;
	const char *string;
} account_policy_names[] = {
	{AP_MIN_PASSWORD_LEN, "min password length"},
	{AP_PASSWORD_HISTORY, "password history"},
	{AP_USER_MUST_LOGON_TO_CHG_PASS, "user must logon to change password"},
	{AP_MAX_PASSWORD_AGE, "maximum password age"},
	{AP_MIN_PASSWORD_AGE,"minimum password age"},
	{AP_LOCK_ACCOUNT_DURATION, "lockout duration"},
	{AP_RESET_COUNT_TIME, "reset count minutes"},
	{AP_BAD_ATTEMPT_LOCKOUT, "bad lockout attempt"},
	{AP_TIME_TO_LOGOUT, "disconnect time"},
	{AP_REFUSE_MACHINE_PW_CHANGE, "refuse machine password change"},
	{0, NULL}
};

char *account_policy_names_list(void)
{
	char *nl, *p;
	int i;
	size_t len = 0;

	for (i=0; account_policy_names[i].string; i++) {
		len += strlen(account_policy_names[i].string) + 1;
	}
	len++;
	nl = SMB_MALLOC(len);
	if (!nl) {
		return NULL;
	}
	p = nl;
	for (i=0; account_policy_names[i].string; i++) {
		memcpy(p, account_policy_names[i].string, strlen(account_policy_names[i].string) + 1);
		p[strlen(account_policy_names[i].string)] = '\n';
		p += strlen(account_policy_names[i].string) + 1;
	}
	*p = '\0';
	return nl;
}

/****************************************************************************
Get the account policy name as a string from its #define'ed number
****************************************************************************/

static const char *decode_account_policy_name(int field)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (field == account_policy_names[i].field)
			return account_policy_names[i].string;
	}
	return NULL;

}

/****************************************************************************
Get the account policy name as a string from its #define'ed number
****************************************************************************/

int account_policy_name_to_fieldnum(const char *name)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (strcmp(name, account_policy_names[i].string) == 0)
			return account_policy_names[i].field;
	}
	return 0;

}

/****************************************************************************
****************************************************************************/

BOOL account_policy_get(int field, uint32 *value)
{
	fstring name;
	uint32 regval;

	if(!init_account_policy())return False;

	if (value)
		*value = 0;

	fstrcpy(name, decode_account_policy_name(field));
	if (!*name) {
		DEBUG(1, ("account_policy_get: Field %d is not a valid account policy type!  Cannot get, returning 0.\n", field));
		return False;
	}
	if (!tdb_fetch_uint32(tdb, name, &regval)) {
		DEBUG(1, ("account_policy_get: tdb_fetch_uint32 failed for field %d (%s), returning 0\n", field, name));
		return False;
	}
	if (value)
		*value = regval;

	DEBUG(10,("account_policy_get: %s:%d\n", name, regval));
	return True;
}


/****************************************************************************
****************************************************************************/
BOOL account_policy_set(int field, uint32 value)
{
	fstring name;

	if(!init_account_policy())return False;

	fstrcpy(name, decode_account_policy_name(field));
	if (!*name) {
		DEBUG(1, ("Field %d is not a valid account policy type!  Cannot set.\n", field));
		return False;
	}

	if (!tdb_store_uint32(tdb, name, value)) {
		DEBUG(1, ("tdb_store_uint32 failed for field %d (%s) on value %u", field, name, value));
		return False;
	}

	DEBUG(10,("account_policy_set: %s:%d\n", name, value));
	
	return True;
}

/****************************************************************************
****************************************************************************/

TDB_CONTEXT *get_account_pol_tdb( void )
{

	if ( !tdb ) {
		if ( !init_account_policy() )
			return NULL;
	}

	return tdb;
}

