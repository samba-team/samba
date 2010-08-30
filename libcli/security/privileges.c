/*
   Unix SMB/CIFS implementation.
   Privileges handling functions
   Copyright (C) Jean François Micouleau	1998-2001
   Copyright (C) Simo Sorce			2002-2003
   Copyright (C) Gerald (Jerry) Carter          2005
   Copyright (C) Michael Adam			2007
   Copyright (C) Andrew Bartlett		2010
   Copyright (C) Andrew Tridgell                2004

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

/*
 * Basic privileges functions (mask-operations and conversion
 * functions between the different formats (se_priv, privset, luid)
 * moved here * from lib/privileges.c to minimize linker deps.
 *
 * generally SID- and LUID-related code is left in lib/privileges.c
 *
 * some extra functions to hide privs array from lib/privileges.c
 */

#include "includes.h"
#include "libcli/security/privileges.h"
#include "librpc/gen_ndr/security.h"

/* The use of strcasecmp here is safe, all the comparison strings are ASCII */
#undef strcasecmp

const uint64_t se_priv_all         = SE_ALL_PRIVS;

/* Define variables for all privileges so we can use the
   uint64_t* in the various se_priv_XXX() functions */

const uint64_t se_priv_none       = SE_NONE;
const uint64_t se_machine_account = SE_MACHINE_ACCOUNT;
const uint64_t se_print_operator  = SE_PRINT_OPERATOR;
const uint64_t se_add_users       = SE_ADD_USERS;
const uint64_t se_disk_operators  = SE_DISK_OPERATOR;
const uint64_t se_remote_shutdown = SE_REMOTE_SHUTDOWN;
const uint64_t se_restore         = SE_RESTORE;
const uint64_t se_take_ownership  = SE_TAKE_OWNERSHIP;

#define NUM_SHORT_LIST_PRIVS 8

static const struct {
	enum sec_privilege luid;
	uint64_t privilege_mask;
	const char *name;
	const char *description;
} privs[] = {

	{SEC_PRIV_MACHINE_ACCOUNT, SE_MACHINE_ACCOUNT,   "SeMachineAccountPrivilege",	"Add machines to domain"},
	{SEC_PRIV_TAKE_OWNERSHIP,  SE_TAKE_OWNERSHIP,    "SeTakeOwnershipPrivilege",    "Take ownership of files or other objects"},
        {SEC_PRIV_BACKUP,          SE_BACKUP,            "SeBackupPrivilege",           "Back up files and directories"},
        {SEC_PRIV_RESTORE,         SE_RESTORE,           "SeRestorePrivilege",          "Restore files and directories"},
	{SEC_PRIV_REMOTE_SHUTDOWN, SE_REMOTE_SHUTDOWN,   "SeRemoteShutdownPrivilege",	"Force shutdown from a remote system"},

	{SEC_PRIV_PRINT_OPERATOR,  SE_PRINT_OPERATOR,	 "SePrintOperatorPrivilege",	"Manage printers"},
	{SEC_PRIV_ADD_USERS,       SE_ADD_USERS,	 "SeAddUsersPrivilege",		"Add users and groups to the domain"},
	{SEC_PRIV_DISK_OPERATOR,   SE_DISK_OPERATOR,	 "SeDiskOperatorPrivilege",	"Manage disk shares"},

	/* The list from here on was not displayed in the code from
	 * source3/ with the comment that usrmgr will display these
	 * next 2 twice if you include them.  The source4/ code has
	 * always included them, but they do not appear in Windows
	 * 2008 R2.

	   Finally, the parameter 'short_list' determines if the short
	   or full list (including many other privileges) is used */

	{SEC_PRIV_SECURITY,
	 SE_SECURITY,
	 "SeSecurityPrivilege",
	"System security"},

	{SEC_PRIV_SYSTEMTIME,
	 SE_SYSTEMTIME,
	 "SeSystemtimePrivilege",
	"Set the system clock"},

	{SEC_PRIV_SHUTDOWN,
	 SE_SHUTDOWN,
	 "SeShutdownPrivilege",
	"Shutdown the system"},

	{SEC_PRIV_DEBUG,
	 SE_DEBUG,
	 "SeDebugPrivilege",
	"Debug processes"},

	{SEC_PRIV_SYSTEM_ENVIRONMENT,
	 SE_SYSTEM_ENVIRONMENT,
	 "SeSystemEnvironmentPrivilege",
	"Modify system environment"},

	{SEC_PRIV_SYSTEM_PROFILE,
	 SE_SYSTEM_PROFILE,
	 "SeSystemProfilePrivilege",
	"Profile the system"},

	{SEC_PRIV_PROFILE_SINGLE_PROCESS,
	 SE_PROFILE_SINGLE_PROCESS,
	 "SeProfileSingleProcessPrivilege",
	"Profile one process"},

	{SEC_PRIV_INCREASE_BASE_PRIORITY,
	 SE_INCREASE_BASE_PRIORITY,
	 "SeIncreaseBasePriorityPrivilege",
	 "Increase base priority"},

	{SEC_PRIV_LOAD_DRIVER,
	 SE_LOAD_DRIVER,
	 "SeLoadDriverPrivilege",
	"Load drivers"},

	{SEC_PRIV_CREATE_PAGEFILE,
	 SE_CREATE_PAGEFILE,
	 "SeCreatePagefilePrivilege",
	"Create page files"},

	{SEC_PRIV_INCREASE_QUOTA,
	 SE_INCREASE_QUOTA,
	 "SeIncreaseQuotaPrivilege",
	"Increase quota"},

	{SEC_PRIV_CHANGE_NOTIFY,
	 SE_CHANGE_NOTIFY,
	 "SeChangeNotifyPrivilege",
	"Register for change notify"},

	{SEC_PRIV_UNDOCK,
	 SE_UNDOCK,
	 "SeUndockPrivilege",
	"Undock devices"},

	{SEC_PRIV_MANAGE_VOLUME,
	 SE_MANAGE_VOLUME,
	 "SeManageVolumePrivilege",
	"Manage system volumes"},

	{SEC_PRIV_IMPERSONATE,
	 SE_IMPERSONATE,
	 "SeImpersonatePrivilege",
	"Impersonate users"},

	{SEC_PRIV_CREATE_GLOBAL,
	 SE_CREATE_GLOBAL,
	 "SeCreateGlobalPrivilege",
	"Create global"},

	{SEC_PRIV_ENABLE_DELEGATION,
	 SE_ENABLE_DELEGATION,
	 "SeEnableDelegationPrivilege",
	"Enable Delegation"},

	{SEC_PRIV_INTERACTIVE_LOGON,
	 SE_INTERACTIVE_LOGON,
	 "SeInteractiveLogonRight",
	"Interactive logon"},

	{SEC_PRIV_NETWORK_LOGON,
	 SE_NETWORK_LOGON,
	 "SeNetworkLogonRight",
	"Network logon"},

	{SEC_PRIV_REMOTE_INTERACTIVE_LOGON,
	 SE_REMOTE_INTERACTIVE_LOGON,
	 "SeRemoteInteractiveLogonRight",
	"Remote Interactive logon"}
};

/***************************************************************************
 copy an uint64_t privilege bitmap
****************************************************************************/

bool se_priv_copy( uint64_t *dst, const uint64_t *src )
{
	if ( !dst || !src )
		return false;

	*dst = *src;

	return true;
}

/***************************************************************************
 put all valid privileges into a mask
****************************************************************************/

bool se_priv_put_all_privileges(uint64_t *privilege_mask)
{
	int i;
	uint32_t num_privs = ARRAY_SIZE(privs);

	if (!se_priv_copy(privilege_mask, &se_priv_none)) {
		return false;
	}
	for ( i=0; i<num_privs; i++ ) {
		se_priv_add(privilege_mask, &privs[i].privilege_mask);
	}
	return true;
}

/***************************************************************************
 combine 2 uint64_t privilege bitmaps and store the resulting set in new_mask
****************************************************************************/

void se_priv_add( uint64_t *privilege_mask, const uint64_t *addpriv )
{
	*privilege_mask |= *addpriv;
}

/***************************************************************************
 remove one uint64_t privileges bitmap from another and store the resulting set
 in privilege_mask
****************************************************************************/

void se_priv_remove( uint64_t *privilege_mask, const uint64_t *removepriv )
{
	*privilege_mask &= ~*removepriv;
}

/***************************************************************************
 invert a given uint64_t and store the set in new_mask
****************************************************************************/

static void se_priv_invert( uint64_t *new_mask, const uint64_t *privilege_mask )
{
	uint64_t allprivs;

	se_priv_copy( &allprivs, &se_priv_all );
	se_priv_remove( &allprivs, privilege_mask );
	se_priv_copy( new_mask, &allprivs );
}

/***************************************************************************
 check if 2 privilege bitmaps (as uint64_t) are equal
****************************************************************************/

bool se_priv_equal( const uint64_t *privilege_mask1, const uint64_t *privilege_mask2 )
{
	return *privilege_mask1 == *privilege_mask2;
}

/***************************************************************************
 check if a uint64_t has any assigned privileges
****************************************************************************/

static bool se_priv_empty( const uint64_t *privilege_mask )
{
	uint64_t p1;

	se_priv_copy( &p1, privilege_mask );

	p1 &= se_priv_all;

	return se_priv_equal( &p1, &se_priv_none );
}

/*********************************************************************
 Lookup the uint64_t bitmask value for a privilege name
*********************************************************************/

bool se_priv_from_name( const char *name, uint64_t *privilege_mask )
{
	int i;

	uint32_t num_privs = ARRAY_SIZE(privs);

	for ( i=0; i<num_privs; i++ ) {
		if ( strequal( privs[i].name, name ) ) {
			se_priv_copy( privilege_mask, &privs[i].privilege_mask );
			return true;
		}
	}

	return false;
}

/****************************************************************************
 check if the privilege (by bitmask) is in the privilege list
****************************************************************************/

bool is_privilege_assigned(const uint64_t *privileges,
			   const uint64_t *check)
{
	uint64_t p1, p2;

	if ( !privileges || !check )
		return false;

	/* everyone has privileges if you aren't checking for any */

	if ( se_priv_empty( check ) ) {
		DEBUG(1,("is_privilege_assigned: no privileges in check_mask!\n"));
		return true;
	}

	se_priv_copy( &p1, check );

	/* invert the uint64_t we want to check for and remove that from the
	   original set.  If we are left with the uint64_t we are checking
	   for then return true */

	se_priv_invert( &p1, check );
	se_priv_copy( &p2, privileges );
	se_priv_remove( &p2, &p1 );

	return se_priv_equal( &p2, check );
}

/****************************************************************************
 check if the any of the privileges (by bitmask) is in the privilege list
****************************************************************************/

static bool is_any_privilege_assigned( uint64_t *privileges, const uint64_t *check )
{
	uint64_t p1, p2;

	if ( !privileges || !check )
		return false;

	/* everyone has privileges if you aren't checking for any */

	if ( se_priv_empty( check ) ) {
		DEBUG(1,("is_any_privilege_assigned: no privileges in check_mask!\n"));
		return true;
	}

	se_priv_copy( &p1, check );

	/* invert the uint64_t we want to check for and remove that from the
	   original set.  If we are left with the uint64_t we are checking
	   for then return true */

	se_priv_invert( &p1, check );
	se_priv_copy( &p2, privileges );
	se_priv_remove( &p2, &p1 );

	/* see if we have any bits left */

	return !se_priv_empty( &p2 );
}

/*********************************************************************
 Generate the struct lsa_LUIDAttribute structure based on a bitmask
*********************************************************************/

const char* get_privilege_dispname( const char *name )
{
	int i;

	uint32_t num_privs = ARRAY_SIZE(privs);

	if (!name) {
		return NULL;
	}

	for ( i=0; i<num_privs; i++ ) {
		if ( strequal( privs[i].name, name ) ) {
			return privs[i].description;
		}
	}

	return NULL;
}

/****************************************************************************
 initialise a privilege list and set the talloc context
 ****************************************************************************/

/****************************************************************************
 Does the user have the specified privilege ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

bool user_has_privileges(const struct security_token *token, const uint64_t *privilege_bit)
{
	if ( !token )
		return false;

	return is_privilege_assigned( &token->privilege_mask, privilege_bit );
}

/****************************************************************************
 Does the user have any of the specified privileges ?  We only deal with one privilege
 at a time here.
*****************************************************************************/

bool user_has_any_privilege(struct security_token *token, const uint64_t *privilege_mask)
{
	if ( !token )
		return false;

	return is_any_privilege_assigned( &token->privilege_mask, privilege_mask );
}

/*******************************************************************
 return the number of elements in the 'short' privlege array (traditional source3 behaviour)
*******************************************************************/

int num_privileges_in_short_list( void )
{
	return NUM_SHORT_LIST_PRIVS;
}

/****************************************************************************
 Convert a LUID to a named string
****************************************************************************/

const char *luid_to_privilege_name(const struct lsa_LUID *set)
{
	int i;

	uint32_t num_privs = ARRAY_SIZE(privs);

	if (set->high != 0)
		return NULL;

	for ( i=0; i<num_privs; i++ ) {
		if ( set->low == privs[i].luid ) {
			return privs[i].name;
		}
	}

	return NULL;
}


/****************************************************************************
 add a privilege to a privilege array
 ****************************************************************************/

static bool privilege_set_add(PRIVILEGE_SET *priv_set, struct lsa_LUIDAttribute set)
{
	struct lsa_LUIDAttribute *new_set;

	/* we can allocate memory to add the new privilege */

	new_set = talloc_realloc(priv_set->mem_ctx, priv_set->set, struct lsa_LUIDAttribute, priv_set->count + 1);
	if ( !new_set ) {
		DEBUG(0,("privilege_set_add: failed to allocate memory!\n"));
		return false;
	}

	new_set[priv_set->count].luid.high = set.luid.high;
	new_set[priv_set->count].luid.low = set.luid.low;
	new_set[priv_set->count].attribute = set.attribute;

	priv_set->count++;
	priv_set->set = new_set;

	return true;
}

/*******************************************************************
*******************************************************************/

bool se_priv_to_privilege_set( PRIVILEGE_SET *set, uint64_t privilege_mask )
{
	int i;
	uint32_t num_privs = ARRAY_SIZE(privs);
	struct lsa_LUIDAttribute luid;

	luid.attribute = 0;
	luid.luid.high = 0;

	for ( i=0; i<num_privs; i++ ) {
		if ((privilege_mask & privs[i].privilege_mask) == 0)
			continue;

		luid.luid.high = 0;
		luid.luid.low = privs[i].luid;

		if ( !privilege_set_add( set, luid ) )
			return false;
	}

	return true;
}

/*******************************************************************
*******************************************************************/

static bool luid_to_se_priv( struct lsa_LUID *luid, uint64_t *privilege_mask )
{
	int i;
	uint32_t num_privs = ARRAY_SIZE(privs);

	for ( i=0; i<num_privs; i++ ) {
		if ( luid->low == privs[i].luid ) {
			se_priv_copy( privilege_mask, &privs[i].privilege_mask );
			return true;
		}
	}

	return false;
}

/*******************************************************************
*******************************************************************/

bool privilege_set_to_se_priv( uint64_t *privilege_mask, struct lsa_PrivilegeSet *privset )
{
	int i;

	ZERO_STRUCTP( privilege_mask );

	for ( i=0; i<privset->count; i++ ) {
		uint64_t r;

		/* sanity check for invalid privilege.  we really
		   only care about the low 32 bits */

		if ( privset->set[i].luid.high != 0 )
			return false;

		if ( luid_to_se_priv( &privset->set[i].luid, &r ) )
			se_priv_add( privilege_mask, &r );
	}

	return true;
}

/*
  map a privilege id to the wire string constant
*/
const char *sec_privilege_name(enum sec_privilege privilege)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privs);i++) {
		if (privs[i].luid == privilege) {
			return privs[i].name;
		}
	}
	return NULL;
}

/*
  map a privilege id to a privilege display name. Return NULL if not found

  TODO: this should use language mappings
*/
const char *sec_privilege_display_name(enum sec_privilege privilege, uint16_t *language)
{
	int i;
	if (privilege < 1 || privilege > 64) {
		return NULL;
	}
	for (i=0;i<ARRAY_SIZE(privs);i++) {
		if (privs[i].luid == privilege) {
			return privs[i].description;
		}
	}
	return NULL;
}

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_id(const char *name)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privs);i++) {
		if (strcasecmp(privs[i].name, name) == 0) {
			return privs[i].luid;
		}
	}
	return -1;
}

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_from_mask(uint64_t mask)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privs);i++) {
		if (privs[i].privilege_mask == mask) {
			return privs[i].luid;
		}
	}
	return -1;
}

/*
  assist in walking the table of privileges - return the LUID (low 32 bits) by index
*/
enum sec_privilege sec_privilege_from_index(int idx)
{
	if (idx >= 0 && idx<ARRAY_SIZE(privs)) {
		return privs[idx].luid;
	}
	return -1;
}

/*
  assist in walking the table of privileges - return the string constant by index
*/
const char *sec_privilege_name_from_index(int idx)
{
	if (idx >= 0 && idx<ARRAY_SIZE(privs)) {
		return privs[idx].name;
	}
	return NULL;
}


/*
  return a privilege mask given a privilege id
*/
static uint64_t sec_privilege_mask(enum sec_privilege privilege)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privs);i++) {
		if (privs[i].luid == privilege) {
			return privs[i].privilege_mask;
		}
	}

	return 0;
}


/*
  return true if a security_token has a particular privilege bit set
*/
bool security_token_has_privilege(const struct security_token *token, enum sec_privilege privilege)
{
	uint64_t mask;

	mask = sec_privilege_mask(privilege);
	if (mask == 0) {
		return false;
	}

	if (token->privilege_mask & mask) {
		return true;
	}
	return false;
}

/*
  set a bit in the privilege mask
*/
void security_token_set_privilege(struct security_token *token, enum sec_privilege privilege)
{
	/* Relies on the fact that an invalid privilage will return 0, so won't change this */
	token->privilege_mask |= sec_privilege_mask(privilege);
}

void security_token_debug_privileges(int dbg_lev, const struct security_token *token)
{
	DEBUGADD(dbg_lev, (" Privileges (0x%16llX):\n",
			    (unsigned long long) token->privilege_mask));

	if (token->privilege_mask) {
		int idx = 0;
		int i = 0;
		for (idx = 0; idx<ARRAY_SIZE(privs); idx++) {
			if (token->privilege_mask & privs[idx].privilege_mask) {
				DEBUGADD(dbg_lev, ("  Privilege[%3lu]: %s\n", (unsigned long)i++,
						   privs[idx].name));
			}
		}
	}
}
