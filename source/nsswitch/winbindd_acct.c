/* 
   Unix SMB/CIFS implementation.

   Winbind account management functions

   Copyright (C) by Gerald (Jerry) Carter       2003
   
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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define WBKEY_PASSWD	"WBA_PASSWD"
#define WBKEY_GROUP	"WBA_GROUP"

#define NUM_PW_FIELDS	7
#define NUM_GRP_FIELDS	4

/* Globals */

static TDB_CONTEXT *account_tdb;

extern userdom_struct current_user_info;

struct _check_primary_grp {
	gid_t	gid;
	BOOL	found;
};

/**********************************************************************
**********************************************************************/

static void free_winbindd_gr( WINBINDD_GR *grp )
{
	int i;

	if ( !grp )
		return;
		
	for ( i=0; i<grp->num_gr_mem; i++ )
		SAFE_FREE( grp->gr_mem[i] );

	SAFE_FREE( grp->gr_mem );
	
	return;
}

/*****************************************************************************
 Initialise auto-account database. 
*****************************************************************************/

static BOOL winbindd_accountdb_init(void)
{
	/* see if we've already opened the tdb */
	
	if ( account_tdb )
		return True;

	/* winbindd_idmap.tdb should always be opened by the idmap_init()
	   code first */

	if ( !(account_tdb = idmap_tdb_handle()) ) {
		DEBUG(0, ("winbindd_accountdb_init: Unable to retreive handle for database\n"));
		return False;
	}
	
	/* yeah! */
	
	return True;   
}

/**********************************************************************
 Convert a string in /etc/passwd format to a struct passwd* entry
**********************************************************************/

static WINBINDD_PW* string2passwd( char *string )
{
	static WINBINDD_PW pw;
	char *p, *str;
	char *fields[NUM_PW_FIELDS];
	int i;
	
	if ( !string )
		return NULL;
	
	ZERO_STRUCTP( &pw );
	
	DEBUG(10,("string2passwd: converting \"%s\"\n", string));
	
	ZERO_STRUCT( fields );
	
	for ( i=0, str=string; i<NUM_PW_FIELDS-1; i++ ) {
		if ( !(p = strchr( str, ':' )) ) {
			DEBUG(0,("string2passwd: parsing failure\n"));
			return NULL;
		}
		*p = '\0';
		if ( str )
			fields[i] = str;
		str = p + 1;
	}
	if ( str ) 
		fields[i] = str;
	
	/* copy fields */
	
	fstrcpy( pw.pw_name,   fields[0] );
	fstrcpy( pw.pw_passwd, fields[1] );
	pw.pw_uid = atoi(      fields[2] );
	pw.pw_gid = atoi(      fields[3] );
	fstrcpy( pw.pw_gecos,  fields[4] );
	fstrcpy( pw.pw_dir,    fields[5] );
	fstrcpy( pw.pw_shell,  fields[6] );
	
	
	/* last minute sanity checks */
	
	if ( pw.pw_uid==0 || pw.pw_gid==0 ) {
		DEBUG(0,("string2passwd: Failure! uid==%lu, gid==%lu\n",
			(unsigned long)pw.pw_uid, (unsigned long)pw.pw_gid));
		return NULL;
	}
	
	DEBUG(10,("string2passwd: Success\n"));

	return &pw;
}

/**********************************************************************
 Convert a struct passwd* to a string formatted for /etc/passwd
**********************************************************************/

static char* passwd2string( const WINBINDD_PW *pw )
{
	static pstring string;
	int ret;
	
	if ( !pw || !pw->pw_name )
		return NULL;
	
	DEBUG(10,("passwd2string: converting passwd struct for %s\n", 
		pw->pw_name));

	ret = pstr_sprintf( string, "%s:%s:%lu:%lu:%s:%s:%s",
		pw->pw_name, 
		pw->pw_passwd ? pw->pw_passwd : "x",
		(unsigned long)pw->pw_uid,
		(unsigned long)pw->pw_gid,
		pw->pw_gecos,
		pw->pw_dir,
		pw->pw_shell );
		
	if ( ret < 0 ) {
		DEBUG(0,("passwd2string: pstr_sprintf() failed!\n"));
		return NULL;
	}
		
	return string;	
}

/**********************************************************************
 Convert a string in /etc/group format to a struct group* entry
**********************************************************************/

static WINBINDD_GR* string2group( char *string )
{
	static WINBINDD_GR grp;
	char *p, *str;
	char *fields[NUM_GRP_FIELDS];
	int i;
	char **gr_members = NULL;
	int num_gr_members = 0;
	
	if ( !string )
		return NULL;
		
	ZERO_STRUCTP( &grp );
	
	DEBUG(10,("string2group: converting \"%s\"\n", string));
	
	ZERO_STRUCT( fields );
	
	for ( i=0, str=string; i<NUM_GRP_FIELDS-1; i++ ) {
		if ( !(p = strchr( str, ':' )) ) {
			DEBUG(0,("string2group: parsing failure\n"));
			return NULL;
		}
		*p = '\0';
		if ( str )
			fields[i] = str;
		str = p + 1;
	}
	
	/* group members */
	
	if ( *str ) {
		/* we already know we have a non-empty string */

		num_gr_members = count_chars(str, ',') + 1;
		
		/* if there was at least one comma, then there 
		   are n+1 members */
		if ( num_gr_members ) {
			fstring buffer;
			
			gr_members = (char**)smb_xmalloc(sizeof(char*)*(num_gr_members+1));
			
			i = 0;
			while ( next_token(&str, buffer, ",", sizeof(buffer)) && i<num_gr_members ) {
				gr_members[i++] = smb_xstrdup(buffer);
			}

			gr_members[i]   = NULL;
		}
	}

	
	/* copy fields */
	
	fstrcpy( grp.gr_name,   fields[0] );
	fstrcpy( grp.gr_passwd, fields[1] );
	grp.gr_gid = atoi(      fields[2] );
	
	grp.num_gr_mem = num_gr_members;
	grp.gr_mem     = gr_members;
	
	/* last minute sanity checks */
	
	if ( grp.gr_gid == 0 ) {
		DEBUG(0,("string2group: Failure! gid==%lu\n", (unsigned long)grp.gr_gid));
		SAFE_FREE( gr_members );
		return NULL;
	}
	
	DEBUG(10,("string2group: Success\n"));

	return &grp;
}

/**********************************************************************
 Convert a struct group* to a string formatted for /etc/group
**********************************************************************/

static char* group2string( const WINBINDD_GR *grp )
{
	static pstring string;
	int ret;
	char *member, *gr_mem_str;
	int num_members;
	int i, size;
	
	if ( !grp || !grp->gr_name )
		return NULL;
	
	DEBUG(10,("group2string: converting passwd struct for %s\n", 
		grp->gr_name));
	
	if ( grp->num_gr_mem ) {
		int idx = 0;

		member = grp->gr_mem[0];
		size = 0;
		num_members = 0;

		while ( member ) {
			size += strlen(member) + 1;
			num_members++;
			member = grp->gr_mem[num_members];
		}
		
		gr_mem_str = smb_xmalloc(size);
	
		for ( i=0; i<num_members; i++ ) {
			snprintf( &gr_mem_str[idx], size-idx, "%s,", grp->gr_mem[i] );
			idx += strlen(grp->gr_mem[i]) + 1;
		}
		/* add trailing NULL (also removes trailing ',' */
		gr_mem_str[size-1] = '\0';
	}
	else {
		/* no members */
		gr_mem_str = smb_xmalloc(sizeof(fstring));
		fstrcpy( gr_mem_str, "" );
	}

	ret = pstr_sprintf( string, "%s:%s:%lu:%s",
		grp->gr_name, 
		grp->gr_passwd ? grp->gr_passwd : "*",
		(unsigned long)grp->gr_gid,
		gr_mem_str );
		
	SAFE_FREE( gr_mem_str );
		
	if ( ret < 0 ) {
		DEBUG(0,("group2string: pstr_sprintf() failed!\n"));
		return NULL;
	}
		
	return string;	
}

/**********************************************************************
**********************************************************************/

static char* acct_userkey_byname( const char *name )
{
	static fstring key;
	
	fstr_sprintf( key, "%s/NAME/%s", WBKEY_PASSWD, name );
	
	return key;		
}

/**********************************************************************
**********************************************************************/

static char* acct_userkey_byuid( uid_t uid )
{
	static fstring key;
	
	fstr_sprintf( key, "%s/UID/%lu", WBKEY_PASSWD, (unsigned long)uid );
	
	return key;		
}

/**********************************************************************
**********************************************************************/

static char* acct_groupkey_byname( const char *name )
{
	static fstring key;
	
	fstr_sprintf( key, "%s/NAME/%s", WBKEY_GROUP, name );
	
	return key;		
}

/**********************************************************************
**********************************************************************/

static char* acct_groupkey_bygid( gid_t gid )
{
	static fstring key;
	
	fstr_sprintf( key, "%s/GID/%lu", WBKEY_GROUP, (unsigned long)gid );
	
	return key;		
}

/**********************************************************************
**********************************************************************/

WINBINDD_PW* wb_getpwnam( const char * name )
{
	char *keystr;
	TDB_DATA data;
	static WINBINDD_PW *pw;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_getpwnam: Failed to open winbindd account db\n"));
		return NULL;
	}
		
	
	keystr = acct_userkey_byname( name );
	
	data = tdb_fetch_bystring( account_tdb, keystr );
	
	pw = NULL;
	
	if ( data.dptr ) {
		pw = string2passwd( data.dptr );
		SAFE_FREE( data.dptr );
	}
		
	DEBUG(5,("wb_getpwnam: %s user (%s)\n", 
		(pw ? "Found" : "Did not find"), name ));
	
	return pw;
}

/**********************************************************************
**********************************************************************/

WINBINDD_PW* wb_getpwuid( const uid_t uid )
{
	char *keystr;
	TDB_DATA data;
	static WINBINDD_PW *pw;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_getpwuid: Failed to open winbindd account db\n"));
		return NULL;
	}
	
	data = tdb_fetch_bystring( account_tdb, acct_userkey_byuid(uid) );
	if ( !data.dptr ) {
		DEBUG(4,("wb_getpwuid: failed to locate uid == %lu\n", (unsigned long)uid));
		return NULL;
	}
	keystr = acct_userkey_byname( data.dptr );

	SAFE_FREE( data.dptr );
	
	data = tdb_fetch_bystring( account_tdb, keystr );
	
	pw = NULL;
	
	if ( data.dptr ) {
		pw = string2passwd( data.dptr );
		SAFE_FREE( data.dptr );
	}

	DEBUG(5,("wb_getpwuid: %s user (uid == %lu)\n", 
		(pw ? "Found" : "Did not find"), (unsigned long)uid ));
	
	return pw;
}

/**********************************************************************
**********************************************************************/

static BOOL wb_storepwnam( const WINBINDD_PW *pw )
{
	char *namekey, *uidkey;
	TDB_DATA data;
	char *str;
	int ret = 0;
	fstring username;

	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_storepwnam: Failed to open winbindd account db\n"));
		return False;
	}

	namekey = acct_userkey_byname( pw->pw_name );
	
	/* lock the main entry first */
	
	if ( tdb_lock_bystring(account_tdb, namekey, 0) == -1 ) {
		DEBUG(0,("wb_storepwnam: Failed to lock %s\n", namekey));
		return False;
	}
	
	str = passwd2string( pw );

	data.dptr = str;
	data.dsize = strlen(str) + 1;	

	if ( (tdb_store_bystring(account_tdb, namekey, data, TDB_REPLACE)) == -1 ) {
		DEBUG(0,("wb_storepwnam: Failed to store \"%s\"\n", str));
		ret = -1;
		goto done;
	}
	
	/* store the uid index */
	
	uidkey = acct_userkey_byuid(pw->pw_uid);
	
	fstrcpy( username, pw->pw_name );
	data.dptr = username;
	data.dsize = strlen(username) + 1;
	
	if ( (tdb_store_bystring(account_tdb, uidkey, data, TDB_REPLACE)) == -1 ) {
		DEBUG(0,("wb_storepwnam: Failed to store uid key \"%s\"\n", str));
		tdb_delete_bystring(account_tdb, namekey);
		ret = -1;
		goto done;
	}		
	
	DEBUG(10,("wb_storepwnam: Success -> \"%s\"\n", str));

done:	
	tdb_unlock_bystring( account_tdb, namekey );
	
	return ( ret == 0 );
}

/**********************************************************************
**********************************************************************/

WINBINDD_GR* wb_getgrnam( const char * name )
{
	char *keystr;
	TDB_DATA data;
	static WINBINDD_GR *grp;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_getgrnam: Failed to open winbindd account db\n"));
		return NULL;
	}
		
	
	keystr = acct_groupkey_byname( name );
	
	data = tdb_fetch_bystring( account_tdb, keystr );
	
	grp = NULL;
	
	if ( data.dptr ) {
		grp = string2group( data.dptr );
		SAFE_FREE( data.dptr );
	}
		
	DEBUG(5,("wb_getgrnam: %s group (%s)\n", 
		(grp ? "Found" : "Did not find"), name ));
	
	return grp;
}

/**********************************************************************
**********************************************************************/

WINBINDD_GR* wb_getgrgid( gid_t gid )
{
	char *keystr;
	TDB_DATA data;
	static WINBINDD_GR *grp;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_getgrgid: Failed to open winbindd account db\n"));
		return NULL;
	}
	
	data = tdb_fetch_bystring( account_tdb, acct_groupkey_bygid(gid) );
	if ( !data.dptr ) {
		DEBUG(4,("wb_getgrgid: failed to locate gid == %lu\n", 
			 (unsigned long)gid));
		return NULL;
	}
	keystr = acct_groupkey_byname( data.dptr );

	SAFE_FREE( data.dptr );
	
	data = tdb_fetch_bystring( account_tdb, keystr );
	
	grp = NULL;
	
	if ( data.dptr ) {
		grp = string2group( data.dptr );
		SAFE_FREE( data.dptr );
	}

	DEBUG(5,("wb_getgrgid: %s group (gid == %lu)\n", 
		(grp ? "Found" : "Did not find"), (unsigned long)gid ));
	
	return grp;
}

/**********************************************************************
**********************************************************************/

static BOOL wb_storegrnam( const WINBINDD_GR *grp )
{
	char *namekey, *gidkey;
	TDB_DATA data;
	char *str;
	int ret = 0;
	fstring groupname;

	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_storepwnam: Failed to open winbindd account db\n"));
		return False;
	}

	namekey = acct_groupkey_byname( grp->gr_name );
	
	/* lock the main entry first */
	
	if ( tdb_lock_bystring(account_tdb, namekey, 0) == -1 ) {
		DEBUG(0,("wb_storegrnam: Failed to lock %s\n", namekey));
		return False;
	}
	
	str = group2string( grp );

	data.dptr = str;
	data.dsize = strlen(str) + 1;	

	if ( (tdb_store_bystring(account_tdb, namekey, data, TDB_REPLACE)) == -1 ) {
		DEBUG(0,("wb_storegrnam: Failed to store \"%s\"\n", str));
		ret = -1;
		goto done;
	}
	
	/* store the gid index */
	
	gidkey = acct_groupkey_bygid(grp->gr_gid);
	
	fstrcpy( groupname, grp->gr_name );
	data.dptr = groupname;
	data.dsize = strlen(groupname) + 1;
	
	if ( (tdb_store_bystring(account_tdb, gidkey, data, TDB_REPLACE)) == -1 ) {
		DEBUG(0,("wb_storegrnam: Failed to store gid key \"%s\"\n", str));
		tdb_delete_bystring(account_tdb, namekey);
		ret = -1;
		goto done;
	}
	
	DEBUG(10,("wb_storegrnam: Success -> \"%s\"\n", str));

done:	
	tdb_unlock_bystring( account_tdb, namekey );
	
	return ( ret == 0 );
}

/**********************************************************************
**********************************************************************/

static BOOL wb_addgrpmember( WINBINDD_GR *grp, const char *user )
{
	int i;
	char **members;
	
	if ( !grp || !user )
		return False;
	
	for ( i=0; i<grp->num_gr_mem; i++ ) {
		if ( StrCaseCmp( grp->gr_mem[i], user ) == 0 )
			return True;
	}
	
	/* add one new slot and keep an extra for the terminating NULL */
	members = Realloc( grp->gr_mem, (grp->num_gr_mem+2)*sizeof(char*) );
	if ( !members )
		return False;
		
	grp->gr_mem = members;
	grp->gr_mem[grp->num_gr_mem++] = smb_xstrdup(user);
	grp->gr_mem[grp->num_gr_mem]   = NULL;
		
	return True;
}

/**********************************************************************
**********************************************************************/

static BOOL wb_delgrpmember( WINBINDD_GR *grp, const char *user )
{
	int i;
	BOOL found = False;
	
	if ( !grp || !user )
		return False;
	
	for ( i=0; i<grp->num_gr_mem; i++ ) {
		if ( StrCaseCmp( grp->gr_mem[i], user ) == 0 ) {
			found = True;
			break;
		}
	}
	
	if ( !found ) 
		return False;

	/* still some remaining members */

	if ( grp->num_gr_mem > 1 ) {
		SAFE_FREE(grp->gr_mem[i]);
		grp->num_gr_mem--;
		grp->gr_mem[i] = grp->gr_mem[grp->num_gr_mem];
		grp->gr_mem[grp->num_gr_mem] = NULL;
	}
	else {	/* last one */
		free_winbindd_gr( grp );
		grp->gr_mem = NULL;
		grp->num_gr_mem = 0;
	}
				
	return True;
}

/**********************************************************************
**********************************************************************/

static int cleangroups_traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, 
		       void *state)
{
	int len;
	fstring key;
	char *name = (char*)state;
	
	fstr_sprintf( key, "%s/NAME", WBKEY_GROUP );
	len = strlen(key);
	
	/* if this is a group entry then, check the members */
	
	if ( (strncmp(kbuf.dptr, key, len) == 0) && dbuf.dptr ) {
		WINBINDD_GR *grp;
		
		if ( !(grp = string2group( dbuf.dptr )) ) {
			DEBUG(0,("cleangroups_traverse_fn: Failure to parse [%s]\n",
				dbuf.dptr));
			return 0;
		}
		
		/* just try to delete the user and rely on wb_delgrpmember()
		   to tell you whether or not the group changed.  This is more 
		   effecient than testing group membership first since the 
		   checks for deleting a user from a group is essentially the 
		   same as checking if he/she is a member */
		   
		if ( wb_delgrpmember( grp, name ) ) {
			DEBUG(10,("cleanupgroups_traverse_fn: Removed user (%s) from group (%s)\n",
				name, grp->gr_name));
			wb_storegrnam( grp );
		}
		
		free_winbindd_gr( grp );
	}

	return 0;
}

/**********************************************************************
**********************************************************************/

static BOOL wb_delete_user( WINBINDD_PW *pw)
{
	char *namekey;
	char *uidkey;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_delete_user: Failed to open winbindd account db\n"));
		return False;
	}

	namekey = acct_userkey_byname( pw->pw_name );
	
	/* lock the main entry first */
	
	if ( tdb_lock_bystring(account_tdb, namekey, 0) == -1 ) {
		DEBUG(0,("wb_delete_user: Failed to lock %s\n", namekey));
		return False;
	}
	
	/* remove user from all groups */
	
	tdb_traverse(account_tdb, cleangroups_traverse_fn, (void *)pw->pw_name);
	
	/* remove the user */
	uidkey = acct_userkey_byuid( pw->pw_uid );
	
	tdb_delete_bystring( account_tdb, namekey );
	tdb_delete_bystring( account_tdb, uidkey );
	
	tdb_unlock_bystring( account_tdb, namekey );
	
	return True;
}

/**********************************************************************
**********************************************************************/

static int isprimarygroup_traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, 
                                      TDB_DATA dbuf, void *params)
{
	int len;
	fstring key;
	struct _check_primary_grp *check = (struct _check_primary_grp*)params;
	
	fstr_sprintf( key, "%s/NAME", WBKEY_PASSWD );
	len = strlen(key);
	
	/* if this is a group entry then, check the members */
	
	if ( (strncmp(kbuf.dptr, key, len) == 0) && dbuf.dptr ) {
		WINBINDD_PW *pw;;
		
		if ( !(pw = string2passwd( dbuf.dptr )) ) {
			DEBUG(0,("isprimarygroup_traverse_fn: Failure to parse [%s]\n",
				dbuf.dptr));
			return 0;
		}
		
		if ( check->gid == pw->pw_gid ) {
			check->found = True;
			return 1;
		}
	}

	return 0;
}


/**********************************************************************
**********************************************************************/

static BOOL wb_delete_group( WINBINDD_GR *grp )
{
	struct _check_primary_grp check;
	char *namekey;
	char *gidkey;
	
	if ( !account_tdb && !winbindd_accountdb_init() ) {
		DEBUG(0,("wb_delete_group: Failed to open winbindd account db\n"));
		return False;
	}
	
	/* lock the main entry first */
	
	namekey = acct_groupkey_byname( grp->gr_name );	
	if ( tdb_lock_bystring(account_tdb, namekey, 0) == -1 ) {
		DEBUG(0,("wb_delete_group: Failed to lock %s\n", namekey));
		return False;
	}
	
	/* is this group the primary group for any user?  If 
	   so deny delete */
	   
	check.found = False;	
	tdb_traverse(account_tdb, isprimarygroup_traverse_fn, (void *)&check);
	
	if ( check.found ) {
		DEBUG(4,("wb_delete_group: Cannot delete group (%s) since it "
			"is the primary group for some users\n", grp->gr_name));
		return False;
	}
	
	/* We're clear.  Delete the group */
	
	DEBUG(5,("wb_delete_group: Removing group (%s)\n", grp->gr_name));
	
	gidkey = acct_groupkey_bygid( grp->gr_gid );
	
	tdb_delete_bystring( account_tdb, namekey );
	tdb_delete_bystring( account_tdb, gidkey );
	
	tdb_unlock_bystring( account_tdb, namekey );
	
	return True;
}

/**********************************************************************
 Create a new "UNIX" user for the system given a username
**********************************************************************/

enum winbindd_result winbindd_create_user(struct winbindd_cli_state *state)
{
	char *user, *group;
	unid_t id;
	WINBINDD_PW pw, *pw_check;
	WINBINDD_GR *wb_grp;
	struct group *unix_grp;
	gid_t primary_gid;
	uint32 flags = state->request.flags;
	uint32 rid;
	
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_create_user: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.username)-1]='\0';
	state->request.data.acct_mgt.groupname[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';
	
	user  = state->request.data.acct_mgt.username;
	group = state->request.data.acct_mgt.groupname;
	
	DEBUG(3, ("[%5lu]: create_user: user=>(%s), group=>(%s)\n", 
		(unsigned long)state->pid, user, group));

	if ( (pw_check=wb_getpwnam(user)) != NULL ) {
		DEBUG(0,("winbindd_create_user: Refusing to create user that already exists (%s)\n", 
			user));
		return WINBINDD_ERROR;
	}

		
	if ( !*group )
		group = lp_template_primary_group();
		
	/* validate the primary group
	   1) lookup in local tdb first
	   2) call getgrnam() as a last resort */
	   
	if ( (wb_grp=wb_getgrnam(group)) != NULL ) {
		primary_gid = wb_grp->gr_gid;
		free_winbindd_gr( wb_grp );
	}
	else if ( (unix_grp=sys_getgrnam(group)) != NULL ) {
		primary_gid = unix_grp->gr_gid;	
	}
	else {
		DEBUG(2,("winbindd_create_user: Cannot validate gid for group (%s)\n", group));
		return WINBINDD_ERROR;
	}

	/* get a new uid */
	
	if ( !NT_STATUS_IS_OK(idmap_allocate_id( &id, ID_USERID)) ) {
		DEBUG(0,("winbindd_create_user: idmap_allocate_id() failed!\n"));
		return WINBINDD_ERROR;
	}
	
	/* The substitution of %U and %D in the 'template homedir' is done
	   by lp_string() calling standard_sub_basic(). */

	fstrcpy( current_user_info.smb_name, user );
	sub_set_smb_name( user );
	fstrcpy( current_user_info.domain, get_global_sam_name() );
	
	/* fill in the passwd struct */
		
	fstrcpy( pw.pw_name,   user );
	fstrcpy( pw.pw_passwd, "x" );
	fstrcpy( pw.pw_gecos,  user);
	fstrcpy( pw.pw_dir,    lp_template_homedir() );
	fstrcpy( pw.pw_shell,  lp_template_shell() );
	
	pw.pw_uid = id.uid;
	pw.pw_gid = primary_gid;
	
	/* store the new entry */
	
	if ( !wb_storepwnam(&pw) )
		return WINBINDD_ERROR;
		
	/* do we need a new RID? */
	
	if ( flags & WBFLAG_ALLOCATE_RID ) {
		if ( !NT_STATUS_IS_OK(idmap_allocate_rid(&rid, USER_RID_TYPE)) ) {
			DEBUG(0,("winbindd_create_user: RID allocation failure!  Cannot create user (%s)\n",
				user));
			wb_delete_user( &pw );
			
			return WINBINDD_ERROR;
		}
		
		state->response.data.rid = rid;
	}

	return WINBINDD_OK;
}

/**********************************************************************
 Create a new "UNIX" group for the system given a username
**********************************************************************/

enum winbindd_result winbindd_create_group(struct winbindd_cli_state *state)
{
	char *group;
	unid_t id;
	WINBINDD_GR grp, *grp_check;
	uint32 flags = state->request.flags;
	uint32 rid;
	
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_create_group: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.groupname[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';	
	group = state->request.data.acct_mgt.groupname;
	
	DEBUG(3, ("[%5lu]: create_group: (%s)\n", (unsigned long)state->pid, group));
	
	if ( (grp_check=wb_getgrnam(group)) != NULL ) {
		DEBUG(0,("winbindd_create_group: Refusing to create group that already exists (%s)\n", 
			group));
		return WINBINDD_ERROR;
	}
	
	/* get a new gid */
	
	if ( !NT_STATUS_IS_OK(idmap_allocate_id( &id, ID_GROUPID)) ) {
		DEBUG(0,("winbindd_create_group: idmap_allocate_id() failed!\n"));
		return WINBINDD_ERROR;
	}
	
	/* fill in the group struct */
		
	fstrcpy( grp.gr_name,   group );
	fstrcpy( grp.gr_passwd, "*" );
	
	grp.gr_gid      = id.gid;
	grp.gr_mem      = NULL;	/* start with no members */
	grp.num_gr_mem  = 0;
	
	if ( !wb_storegrnam(&grp) )
		return WINBINDD_ERROR;
		
	/* do we need a new RID? */
	
	if ( flags & WBFLAG_ALLOCATE_RID ) {
		if ( !NT_STATUS_IS_OK(idmap_allocate_rid(&rid, GROUP_RID_TYPE)) ) {
			DEBUG(0,("winbindd_create_group: RID allocation failure!  Cannot create group (%s)\n",
				group));
			wb_delete_group( &grp );
			
			return WINBINDD_ERROR;
		}
		
		state->response.data.rid = rid;
	}

	return WINBINDD_OK;
}

/**********************************************************************
 Add a user to the membership for a group.
**********************************************************************/

enum winbindd_result winbindd_add_user_to_group(struct winbindd_cli_state *state)
{
	WINBINDD_PW *pw;
	WINBINDD_GR *grp;
	char *user, *group;
	BOOL ret;
	
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_add_user_to_group: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.groupname[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';	
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.username)-1]='\0';	
	group = state->request.data.acct_mgt.groupname;
	user = state->request.data.acct_mgt.username;
	
	DEBUG(3, ("[%5lu]:  add_user_to_group: add %s to %s\n", (unsigned long)state->pid, 
		user, group));
	
	/* make sure it is a valid user */
	
	if ( !(pw = wb_getpwnam( user )) ) {
		DEBUG(4,("winbindd_add_user_to_group: Cannot add a non-existent user\n"));
		return WINBINDD_ERROR;
	}
	
	/* make sure it is a valid group */
	
	if ( !(grp = wb_getgrnam( group )) ) {
		DEBUG(4,("winbindd_add_user_to_group: Cannot add a user to a non-extistent group\n"));
		return WINBINDD_ERROR;	
	}
	
	if ( !wb_addgrpmember( grp, user ) )
		return WINBINDD_ERROR;
		
	ret = wb_storegrnam(grp);
	
	free_winbindd_gr( grp );
	
	return ( ret ? WINBINDD_OK : WINBINDD_ERROR );
}

/**********************************************************************
 Remove a user from the membership of a group
**********************************************************************/

enum winbindd_result winbindd_remove_user_from_group(struct winbindd_cli_state *state)
{
	WINBINDD_GR *grp;
	char *user, *group;
	BOOL ret;

	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_remove_user_from_group: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.groupname[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';	
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.username)-1]='\0';	
	group = state->request.data.acct_mgt.groupname;
	user = state->request.data.acct_mgt.username;
	
	DEBUG(3, ("[%5lu]:  remove_user_from_group: delete %s from %s\n", (unsigned long)state->pid, 
		user, group));
	
	/* don't worry about checking the username since we're removing it anyways */
	
	/* make sure it is a valid group */
	
	if ( !(grp = wb_getgrnam( group )) ) {
		DEBUG(4,("winbindd_remove_user_from_group: Cannot remove a user from a non-extistent group\n"));
		return WINBINDD_ERROR;	
	}
	
	if ( !wb_delgrpmember( grp, user ) )
		return WINBINDD_ERROR;
		
	ret = wb_storegrnam(grp);
	
	free_winbindd_gr( grp );
	
	return ( ret ? WINBINDD_OK : WINBINDD_ERROR );
}

/**********************************************************************
 Set the primary group membership of a user
**********************************************************************/

enum winbindd_result winbindd_set_user_primary_group(struct winbindd_cli_state *state)
{
	WINBINDD_PW *pw;
	WINBINDD_GR *grp;
	char *user, *group;

	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_set_user_primary_group: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.groupname[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';	
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.username)-1]='\0';	
	group = state->request.data.acct_mgt.groupname;
	user = state->request.data.acct_mgt.username;
	
	DEBUG(3, ("[%5lu]:  set_user_primary_group: group %s for user %s\n", 
		  (unsigned long)state->pid, group, user));
	
	/* make sure it is a valid user */
	
	if ( !(pw = wb_getpwnam( user )) ) {
		DEBUG(4,("winbindd_add_user_to_group: Cannot add a non-existent user\n"));
		return WINBINDD_ERROR;
	}
	
	/* make sure it is a valid group */
	
	if ( !(grp = wb_getgrnam( group )) ) {
		DEBUG(4,("winbindd_add_user_to_group: Cannot add a user to a non-extistent group\n"));
		return WINBINDD_ERROR;	
	}
	
	pw->pw_gid = grp->gr_gid;

	free_winbindd_gr( grp );
		
	return ( wb_storepwnam(pw) ? WINBINDD_OK : WINBINDD_ERROR );
}

/**********************************************************************
 Delete a user from the winbindd account tdb.
**********************************************************************/

enum winbindd_result winbindd_delete_user(struct winbindd_cli_state *state)
{
	WINBINDD_PW *pw;
	char *user;

	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_delete_user: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.username)-1]='\0';	
	user = state->request.data.acct_mgt.username;
	
	DEBUG(3, ("[%5lu]:  delete_user: %s\n", (unsigned long)state->pid, user));
	
	/* make sure it is a valid user */
	
	if ( !(pw = wb_getpwnam( user )) ) {
		DEBUG(4,("winbindd_delete_user: Cannot delete a non-existent user\n"));
		return WINBINDD_ERROR;
	}
	
	return ( wb_delete_user(pw) ? WINBINDD_OK : WINBINDD_ERROR );
}

/**********************************************************************
 Delete a group from winbindd's account tdb. 
**********************************************************************/

enum winbindd_result winbindd_delete_group(struct winbindd_cli_state *state)
{
	WINBINDD_GR *grp;
	char *group;
	BOOL ret;

	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_delete_group: non-privileged access denied!\n"));
		return WINBINDD_ERROR;
	}
	
	/* Ensure null termination */
	state->request.data.acct_mgt.username[sizeof(state->request.data.acct_mgt.groupname)-1]='\0';	
	group = state->request.data.acct_mgt.groupname;
	
	DEBUG(3, ("[%5lu]:  delete_group: %s\n", (unsigned long)state->pid, group));
	
	/* make sure it is a valid group */
	
	if ( !(grp = wb_getgrnam( group )) ) {
		DEBUG(4,("winbindd_delete_group: Cannot delete a non-existent group\n"));
		return WINBINDD_ERROR;
	}
	
	ret = wb_delete_group(grp);
	
	free_winbindd_gr( grp );
	
	return ( ret ? WINBINDD_OK : WINBINDD_ERROR );
}



