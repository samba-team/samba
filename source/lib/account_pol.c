/* 
 *  Unix SMB/CIFS implementation.
 *  account policy storage
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Andrew Bartlett              2002
 *  Copyright (C) Guenther Deschner            2004-2005
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

/* cache all entries for 60 seconds for to save ldap-queries (cache is updated
 * after this period if admins do not use pdbedit or usermanager but manipulate
 * ldap directly) - gd */

#define DATABASE_VERSION 	3
#define AP_LASTSET 		"LAST_CACHE_UPDATE"
#define AP_MIGRATED 		"ACCOUNT POLICIES WERE MIGRATED TO PASSDB"
#define AP_TTL			60

extern DOM_SID global_sid_World;
extern DOM_SID global_sid_Builtin_Administrators;
extern DOM_SID global_sid_Builtin_Account_Operators;
extern DOM_SID global_sid_Builtin_Server_Operators;
extern DOM_SID global_sid_Builtin_Print_Operators;
extern DOM_SID global_sid_Builtin_Backup_Operators;


struct ap_table {
	int field;
	const char *string;
	uint32 default_val;
	const char *comment;
};

static const struct ap_table account_policy_names[] = {
	{AP_MIN_PASSWORD_LEN, "min password length", MINPASSWDLENGTH, 
		"Minimal password length (default: 5)"},
	{AP_PASSWORD_HISTORY, "password history", 0,
		"Length of Password History Entries (default: 0 => off)" },
	{AP_USER_MUST_LOGON_TO_CHG_PASS, "user must logon to change password", 0,
		"Force Users to logon for password change (default: 0 => off, 2 => on)"},
	{AP_MAX_PASSWORD_AGE, "maximum password age", (uint32)-1,
		"Maximum password age, in seconds (default: -1 => never expire passwords)"},
	{AP_MIN_PASSWORD_AGE,"minimum password age", 0,
		"Minimal password age, in seconds (default: 0 => allow immediate password change)"},
	{AP_LOCK_ACCOUNT_DURATION, "lockout duration", 30,
		"Lockout duration in minutes (default: 30, -1 => forever)"},
	{AP_RESET_COUNT_TIME, "reset count minutes", 30,
		"Reset time after lockout in minutes (default: 30)"},
	{AP_BAD_ATTEMPT_LOCKOUT, "bad lockout attempt", 0,
		"Lockout users after bad logon attempts (default: 0 => off)"},
	{AP_TIME_TO_LOGOUT, "disconnect time", -1,
		"Disconnect Users outside logon hours (default: -1 => off, 0 => on)"}, 
	{AP_REFUSE_MACHINE_PW_CHANGE, "refuse machine password change", 0,
		"Allow Machine Password changes (default: 0 => off)"},
	{0, NULL, 0, ""}
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

const char *decode_account_policy_name(int field)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (field == account_policy_names[i].field)
			return account_policy_names[i].string;
	}
	return NULL;

}

/****************************************************************************
Get the account policy comment as a string from its #define'ed number
****************************************************************************/

const char *account_policy_get_comment(int field)
{
	int i;
	for (i=0; account_policy_names[i].string; i++) {
		if (field == account_policy_names[i].field)
			return account_policy_names[i].comment;
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

/*****************************************************************************
Update LAST-Set counter inside the cache
*****************************************************************************/

static BOOL account_policy_cache_timestamp(uint32 *value, BOOL update)
{
	pstring key;
	uint32 val = 0;
	time_t now;

	slprintf(key, sizeof(key)-1, "%s", AP_LASTSET);

	if (!init_account_policy())
		return False;

	if (!tdb_fetch_uint32(tdb, key, &val) && !update) {
		DEBUG(10,("failed to get last set timestamp of cache\n"));
		return False;
	}

	*value = val;

	DEBUG(10, ("account policy cache lastset was: %s\n", http_timestring(val)));

	if (update) {

		now = time(NULL);

		if (!tdb_store_uint32(tdb, key, (uint32)now)) {
			DEBUG(1, ("tdb_store_uint32 failed for %s\n", key));
			return False;
		}
		DEBUG(10, ("account policy cache lastset now: %s\n", http_timestring(now)));
		*value = now;
	}

	return True;
}

/*****************************************************************************
Get default value for account policy
*****************************************************************************/

BOOL account_policy_get_default(int account_policy, uint32 *val)
{
	int i;
	for (i=0; account_policy_names[i].field; i++) {
		if (account_policy_names[i].field == account_policy) {
			*val = account_policy_names[i].default_val;
			return True;
		}
	}
	DEBUG(0,("no default for account_policy index %d found. This should never happen\n", 
		account_policy));
	return False;
}

/*****************************************************************************
 Set default for a field if it is empty
*****************************************************************************/

static BOOL account_policy_set_default_on_empty(int account_policy)
{

	uint32 value;

	if (!account_policy_get(account_policy, &value) && 
	    !account_policy_get_default(account_policy, &value)) {
		return False;
	}

	return account_policy_set(account_policy, value);
}

/*****************************************************************************
Check migration success, set marker if required
*****************************************************************************/

static BOOL already_migrated_account_policies(BOOL store_migration_success)
{
	pstring key;
	uint32 value;

	slprintf(key, sizeof(key)-1, "%s", AP_MIGRATED);

	if (tdb_fetch_uint32(tdb, key, &value)) {
		return True;
	}

	if (store_migration_success) {

		if (!tdb_store_uint32(tdb, key, 1)) {
			DEBUG(1, ("tdb_store_uint32 failed for %s\n", key));
			return False;
		}
		return True;
	}

	return False;
}

/*****************************************************************************
Migrate account policies to passdb
*****************************************************************************/

static BOOL migrate_account_policy_names_to_passdb(void)
{
	int i, tmp_val;
	BOOL got_pol;

	if (already_migrated_account_policies(False)) {
		return True;
	}

	DEBUG(1,("start migrating account policies into passdb\n"));

	for (i=1; decode_account_policy_name(i) != NULL; i++) {

		got_pol = False;

		if (pdb_get_account_policy(i, &tmp_val)) {
			DEBUG(10,("account policy already in passdb\n"));
			got_pol = True;
		}

		if (!got_pol && !account_policy_get(i, &tmp_val)) {
			DEBUG(0,("very weird: could not get value for account policy\n"));
			return False;
		}

		DEBUGADD(1,("\tmigrating account policy (#%d: %s with value: %d) to passdb\n", 
			i, decode_account_policy_name(i), tmp_val));

		/* set policy via new passdb api */
		if (!pdb_set_account_policy(i, tmp_val)) {
			DEBUG(0,("failed to set account_policy\n"));
			return False;
		}

	}

	if (!already_migrated_account_policies(True)) {
		DEBUG(0,("could not store marker for account policy migration in the tdb\n"));
		return False;
	}
		
	DEBUGADD(1,("succesfully migrated account policies into passdb\n"));

	return True;
}

/*****************************************************************************
 Open the account policy tdb.
***`*************************************************************************/

BOOL init_account_policy(void)
{

	const char *vstring = "INFO/version";
	uint32 version;
	int i;

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

		for (i=0; account_policy_names[i].field; i++) {

			if (!account_policy_set_default_on_empty(account_policy_names[i].field)) {
				DEBUG(0,("failed to set default value in account policy tdb\n"));
				return False;
			}
		}
	}

	if (!migrate_account_policy_names_to_passdb()) {
		DEBUG(0,("Could not migrate account policy tdb to passdb.\n"));
		return False;
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

/*****************************************************************************
Internal function
*****************************************************************************/

BOOL account_policy_get(int field, uint32 *value)
{
	fstring name;
	uint32 regval;

	if (!init_account_policy())
		return False;

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
Get an account policy from a (migrated tdb)
****************************************************************************/

BOOL account_policy_set(int field, uint32 value)
{
	fstring name;

	if (!init_account_policy())
		return False;

	fstrcpy(name, decode_account_policy_name(field));
	if (!*name) {
		DEBUG(1, ("Field %d is not a valid account policy type!  Cannot set.\n", field));
		return False;
	}

	if (!tdb_store_uint32(tdb, name, value)) {
		DEBUG(1, ("tdb_store_uint32 failed for field %d (%s) on value %u\n", field, name, value));
		return False;
	}

	DEBUG(10,("account_policy_set: %s:%d\n", name, value));
	
	return True;
}

/****************************************************************************
Set an account policy in the cache 
****************************************************************************/

BOOL cache_account_policy_set(int field, uint32 value)
{
	uint32 lastset, i;

	for (i=0; account_policy_names[i].field; i++) {

		if (account_policy_names[i].field == field) {

			DEBUG(10,("cache_account_policy_set: updating account pol cache\n"));

			if (!account_policy_set(field, value)) {
				return False;
			}

			if (!account_policy_cache_timestamp(&lastset, True)) {
				DEBUG(10,("cache_account_policy_set: failed to get lastest cache update timestamp\n"));
				return False;
			}

			DEBUG(10,("cache_account_policy_set: cache valid until: %s\n", http_timestring(lastset+AP_TTL)));
		}
	}

	return True;
}

/*****************************************************************************
Get an account policy from the cache 
*****************************************************************************/

BOOL cache_account_policy_get(int field, uint32 *value)
{
	uint32 lastset, i;

	if (!account_policy_cache_timestamp(&lastset, False)) {
		DEBUG(10,("cache_account_policy_get: failed to get latest cache update timestamp\n"));
		return False;
	}

	if ((lastset + AP_TTL) < (uint32)time(NULL) ) {
		DEBUG(10,("cache_account_policy_get: no valid cache entry (cache expired)\n"));
		return False;
	} 

	for (i=0; account_policy_names[i].field; i++) {
		if (account_policy_names[i].field == field) {
			return account_policy_get(field, value);
		}
	}

	return False;
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

