/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Hewlett-Packard Company           1999.
 *  Copyright (C) Jeremy Allison		    2001.
 *  Copyright (C) Gerald Carter                     2002.
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

/* Implementation of registry functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define KEY_HKLM	"HKLM"
#define KEY_HKU		"HKU"

#define OUR_HANDLE(hnd) (((hnd)==NULL)?"NULL":(IVAL((hnd)->data5,4)==(uint32)sys_getpid()?"OURS":"OTHER")), \
((unsigned int)IVAL((hnd)->data5,4)),((unsigned int)sys_getpid())

/* structure to store the registry handles */

typedef struct _RegistryKey {
	struct _RegistryKey *prev, *next;

	fstring name; /* name of registry key */
	POLICY_HND	hnd;
	
} Registry_Key;

static Registry_Key *regkeys_list;
static TDB_CONTEXT *tdb_reg;

/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings
 ***********************************************************************/
 
static BOOL store_reg_keys( TDB_CONTEXT *tdb, char *keyname, char **subkeys, uint32 num_subkeys  )
{
	TDB_DATA kbuf, dbuf;
	void *buffer, *tmpbuf;
	int i = 0;
	uint32 len, buflen;
	BOOL ret = True;
	
	if ( !keyname )
		return False;
	
	/* allocate some initial memory */
		
	buffer = malloc(sizeof(pstring));
	buflen = sizeof(pstring);
	len = 0;
	
	/* store the number of subkeys */
	
	len += tdb_pack(buffer+len, buflen-len, "d", num_subkeys);
	
	/* pack all the strings */
	
	for (i=0; i<num_subkeys; i++) {
		len += tdb_pack(buffer+len, buflen-len, "f", subkeys[i]);
		if ( len > buflen ) {
			/* allocate some extra space */
			if ((tmpbuf = Realloc( buffer, len*2 )) == NULL) {
				DEBUG(0,("store_reg_keys: Failed to realloc memory of size [%d]\n", len*2));
				ret = False;
				goto done;
			}
			buffer = tmpbuf;
			buflen = len*2;
					
			len = tdb_pack(buffer+len, buflen-len, "f", subkeys[i]);
		}		
	}
	
	/* finally write out the data */
	
	kbuf.dptr = keyname;
	kbuf.dsize = strlen(keyname)+1;
	dbuf.dptr = buffer;
	dbuf.dsize = len;
	if ( tdb_store( tdb, kbuf, dbuf, TDB_REPLACE ) == -1) {
		ret = False;
		goto done;
	}

done:		
	SAFE_FREE( buffer );
	return ret;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be 
 released by the caller.  The subkeys are stored in a catenated string
 of null terminated character strings
 ***********************************************************************/

static int fetch_reg_keys( TDB_CONTEXT *tdb,  char* key, char **subkeys )
{
	pstring path;
	uint32 num_items;
	TDB_DATA dbuf;
	void *buf;
	uint32 buflen, len;
	int i;
	char *s;

	
	pstrcpy( path, key );
	
	/* convert to key format */
	pstring_sub( path, "\\", "/" );
	
	dbuf = tdb_fetch_by_string( tdb, path );
	
	buf = dbuf.dptr;
	buflen = dbuf.dsize;
	
	if ( !buf ) {
		DEBUG(5,("fetch_reg_keys: Failed to fetch any subkeys for [%s]\n", key));
		return -1;
	}
	
	len = tdb_unpack( buf, buflen, "d", &num_items);
	if (num_items) {
		if ( (*subkeys = (char*)malloc(sizeof(fstring)*num_items)) == NULL ) {
			DEBUG(0,("fetch_reg_keys: Failed to malloc memory for subkey array containing [%d] items!\n",
				num_items));
			num_items = -1;
			goto done;
		}
	}
	
	s = *subkeys;
	for (i=0; i<num_items; i++) {
		len += tdb_unpack( buf+len, buflen-len, "f", s );
		s += strlen(s) + 1;
	}

done:	
	SAFE_FREE(dbuf.dptr);
	return num_items;
}

/***********************************************************************
 count the number of subkeys dtored in the registry
 ***********************************************************************/

static int fetch_reg_keys_count( TDB_CONTEXT *tdb,  char* key )
{
	pstring path;
	uint32 num_items;
	TDB_DATA dbuf;
	void *buf;
	uint32 buflen, len;
	
	
	pstrcpy( path, key );
	
	/* convert to key format */
	pstring_sub( path, "\\", "/" );
	
	dbuf = tdb_fetch_by_string( tdb, path );
	
	buf = dbuf.dptr;
	buflen = dbuf.dsize;
	
	if ( !buf ) {
		DEBUG(5,("fetch_reg_keys: Failed to fetch any subkeys for [%s]\n", key));
		return -1;
	}
	
	len = tdb_unpack( buf, buflen, "d", &num_items);
	
	SAFE_FREE( buf );
	
	return num_items;
}

/***********************************************************************
 retreive a specific subkey specified by index.  The subkey parameter
 is assumed to be an fstring.
 ***********************************************************************/

static BOOL fetch_reg_keys_specific( TDB_CONTEXT *tdb,  char* key, char* subkey, uint32 index )
{
	int num_subkeys, i;
	char *subkeys = NULL;
	char *s;
	
	num_subkeys = fetch_reg_keys( tdb_reg, key, &subkeys );
	if ( num_subkeys == -1 )
		return False;

	s = subkeys;
	for ( i=0; i<num_subkeys; i++ ) {
		/* copy the key if the index matches */
		if ( i == index ) {
			fstrcpy( subkey, s );
			break;
		}
		
		/* go onto the next string */
		s += strlen(s) + 1;
	}
	
	SAFE_FREE(subkeys);
	
	return True;
}


/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
static BOOL init_registry_data( TDB_CONTEXT* tdb_reg )
{
	pstring keyname;
	char *subkeys[3];

	/* HKEY_LOCAL_MACHINE */
	
	pstrcpy( keyname, KEY_HKLM );
	subkeys[0] = "SYSTEM";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM" );
	subkeys[0] = "CurrentControlSet";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet" );
	subkeys[0] = "Control";
	subkeys[1] = "services";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 2 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control" );
	subkeys[0] = "Print";
	subkeys[1] = "ProduceOptions";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 2 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control/Print" );
	subkeys[0] = "Environments";
	subkeys[1] = "Forms";
	subkeys[2] = "Printers";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 3 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/Control/ProductOptions" );
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 0 ))
		return False;

	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services" );
	subkeys[0] = "Netlogon";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services/Netlogon" );
	subkeys[0] = "parameters";
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 1 ))
		return False;
		
	pstrcpy( keyname, KEY_HKLM );
	pstrcat( keyname, "/SYSTEM/CurrentControlSet/services/Netlogon/parameters" );
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 0 ))
		return False;

	
	/* HKEY_USER */
		
	pstrcpy( keyname, KEY_HKU );
	if ( !store_reg_keys( tdb_reg, keyname, subkeys, 0 ) )
		return False;
		
	return True;
}
  
/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
BOOL init_registry( void )
{
	static pid_t local_pid;
	
	
	if (tdb_reg && local_pid == sys_getpid())
		return True;

	/* 
	 * try to open first without creating so we can determine
	 * if we need to init the data in the registry
	 */
	
	tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR, 0600);
	if ( !tdb_reg ) 
	{
		tdb_reg = tdb_open_log(lock_path("registry.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if ( !tdb_reg ) {
			DEBUG(0,("init_registry: Failed to open registry %s (%s)\n",
				lock_path("registry.tdb"), strerror(errno) ));
			return False;
		}
		
		DEBUG(10,("init_registry: Successfully created registry tdb\n"));
		
		/* create the registry here */
		if ( !init_registry_data( tdb_reg ) ) {
			DEBUG(0,("init_registry: Failed to initiailize data in registry!\n"));
			return False;
		}
	}

	local_pid = sys_getpid();
	
	return True;
}

/******************************************************************
 Find a registry key handle and return a Registry_Key
 *****************************************************************/

static Registry_Key *find_regkey_index_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	Registry_Key *regkey = NULL;

	if(!find_policy_by_hnd(p,hnd,(void **)&regkey)) {
		DEBUG(2,("find_regkey_index_by_hnd: Registry Key not found: "));
		return NULL;
	}

	return regkey;
}


/******************************************************************
 free() function for Registry_Key
 *****************************************************************/
 
static void free_reg_info(void *ptr)
{
	Registry_Key *info = (Registry_Key*)ptr;
	
	DLIST_REMOVE(regkeys_list, info);

	SAFE_FREE(info);
}

/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 *******************************************************************/
 
static BOOL open_registry_key(pipes_struct *p, POLICY_HND *hnd, char *name, 
				uint32 access_granted)
{
	Registry_Key *regkey = NULL;

	DEBUG(7,("open_registry_key: name = [%s]\n", name));

	/* All registry keys **must** have a name of non-zero length */
	
	if (!name || !*name )
		return False;
			
	if ((regkey=(Registry_Key*)malloc(sizeof(Registry_Key))) == NULL)
		return False;
		
	ZERO_STRUCTP( regkey );
	
	DLIST_ADD( regkeys_list, regkey );

	/* copy the name and obtain a handle */
	
	fstrcpy( regkey->name, name );
	
	DEBUG(7,("open_registry_key: exit\n"));
	
	return create_policy_hnd( p, hnd, free_reg_info, regkey );
}

/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 *******************************************************************/

static BOOL close_registry_key(pipes_struct *p, POLICY_HND *hnd)
{
	Registry_Key *regkey = find_regkey_index_by_hnd(p, hnd);
	
	if ( !regkey ) {
		DEBUG(2,("close_registry_key: Invalid handle (%s:%u:%u)\n", OUR_HANDLE(hnd)));
		return False;
	}
	
	close_policy_hnd(p, hnd);
	
	return True;
}

/********************************************************************
 retrieve information about the subkeys
 *******************************************************************/
 
static BOOL get_subkey_information( Registry_Key *key, uint32 *maxnum, uint32 *maxlen )
{
	int num_subkeys, i;
	uint32 max_len;
	char *subkeys = NULL;
	uint32 len;
	char *s;
	
	if ( !key )
		return False;
	
	num_subkeys = fetch_reg_keys( tdb_reg, key->name, &subkeys );
	if ( num_subkeys == -1 )
		return False;

	/* find the longest string */
	
	max_len = 0;
	s = subkeys;
	for ( i=0; i<num_subkeys; i++ ) {
		len = strlen(s);
		max_len = MAX(max_len, len);
		s += len + 1;
	}

	*maxnum = num_subkeys;
	*maxlen = max_len*2;
	
	SAFE_FREE(subkeys);
	
	return True;
}

/********************************************************************
 retrieve information about the values.  We don't store values 
 here.  The registry tdb is intended to be a frontend to oether 
 Samba tdb's (such as ntdrivers.tdb).
 *******************************************************************/
 
static BOOL get_value_information( Registry_Key *key, uint32 *maxnum, 
                                    uint32 *maxlen, uint32 *maxsize )
{
	if ( !key )
		return False;

	/* Hard coded key names first */
	
	if ( !strcmp(key->name, KEY_HKLM) || !strcmp(key->name, KEY_HKU) )
	{
		*maxnum   = 0;
		*maxlen   = 0;
		*maxsize  = 0;
		return True;
	}
	
	/* 
	 * FIXME!!! Need to add routines to look up values in other
	 * databases   --jerry
	 */

	return False;
}

/********************************************************************
 reg_close
 ********************************************************************/

NTSTATUS _reg_close(pipes_struct *p, REG_Q_CLOSE *q_u, REG_R_CLOSE *r_u)
{
	/* set up the REG unknown_1 response */
	ZERO_STRUCT(r_u->pol);

	/* close the policy handle */
	if (!close_registry_key(p, &q_u->pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*******************************************************************
 reg_reply_open
 ********************************************************************/

NTSTATUS _reg_open_hklm(pipes_struct *p, REG_Q_OPEN_HKLM *q_u, REG_R_OPEN_HKLM *r_u)
{
	if (!open_registry_key(p, &r_u->pol, KEY_HKLM, 0x0))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*******************************************************************
 reg_reply_open
 ********************************************************************/

NTSTATUS _reg_open_hku(pipes_struct *p, REG_Q_OPEN_HKU *q_u, REG_R_OPEN_HKU *r_u)
{
	if (!open_registry_key(p, &r_u->pol, KEY_HKU, 0x0))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/

NTSTATUS _reg_open_entry(pipes_struct *p, REG_Q_OPEN_ENTRY *q_u, REG_R_OPEN_ENTRY *r_u)
{
	POLICY_HND pol;
	fstring name;
	pstring path;
	int num_subkeys;
	Registry_Key *key = find_regkey_index_by_hnd(p, &q_u->pol);

	DEBUG(5,("reg_open_entry: Enter\n"));

	if ( !key )
		return NT_STATUS_INVALID_HANDLE;

	rpcstr_pull(name,q_u->uni_name.buffer,sizeof(name),q_u->uni_name.uni_str_len*2,0);

	/* store the full path in the regkey_list */
	
	pstrcpy( path, key->name );
	pstrcat( path, "\\" );
	pstrcat( path, name );

	DEBUG(5,("reg_open_entry: %s\n", path));

	/* do a check on the name, here */
	
	if ( (num_subkeys=fetch_reg_keys_count( tdb_reg, path )) == -1 )
		return NT_STATUS_ACCESS_DENIED;

	if (!open_registry_key(p, &pol, path, 0x0))
		return NT_STATUS_TOO_MANY_SECRETS; 

	init_reg_r_open_entry(r_u, &pol, NT_STATUS_OK);

	DEBUG(5,("reg_open_entry: Exitn"));

	return r_u->status;
}

/*******************************************************************
 reg_reply_info
 ********************************************************************/

NTSTATUS _reg_info(pipes_struct *p, REG_Q_INFO *q_u, REG_R_INFO *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	char *value = NULL;
	uint32 type = 0x1; /* key type: REG_SZ */
	UNISTR2 *uni_key = NULL;
	BUFFER2 *buf = NULL;
	fstring name;
	Registry_Key *key = find_regkey_index_by_hnd( p, &q_u->pol );

	DEBUG(5,("_reg_info: Enter\n"));

	if ( !key )
		return NT_STATUS_INVALID_HANDLE;
		
	DEBUG(7,("_reg_info: policy key name = [%s]\n", key->name));

	rpcstr_pull(name, q_u->uni_type.buffer, sizeof(name), q_u->uni_type.uni_str_len*2, 0);

	DEBUG(5,("reg_info: checking subkey: %s\n", name));

	uni_key = (UNISTR2 *)talloc_zero(p->mem_ctx, sizeof(UNISTR2));
	buf = (BUFFER2 *)talloc_zero(p->mem_ctx, sizeof(BUFFER2));

	if (!uni_key || !buf)
		return NT_STATUS_NO_MEMORY;

	if ( strequal(name, "RefusePasswordChange") ) {
		type=0xF770;
		status = NT_STATUS_NO_SUCH_FILE;
		init_unistr2(uni_key, "", 0);
		init_buffer2(buf, (uint8*) uni_key->buffer, uni_key->uni_str_len*2);
		
		buf->buf_max_len=4;

		goto out;
	}

	switch (lp_server_role()) {
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			value = "LanmanNT";
			break;
		case ROLE_STANDALONE:
			value = "ServerNT";
			break;
		case ROLE_DOMAIN_MEMBER:
			value = "WinNT";
			break;
	}

	/* This makes the server look like a member server to clients */
	/* which tells clients that we have our own local user and    */
	/* group databases and helps with ACL support.                */

	init_unistr2(uni_key, value, strlen(value)+1);
	init_buffer2(buf, (uint8*)uni_key->buffer, uni_key->uni_str_len*2);
  
 out:
	init_reg_r_info(q_u->ptr_buf, r_u, buf, type, status);

	DEBUG(5,("reg_open_entry: Exit\n"));

	return status;
}


/*****************************************************************************
 Implementation of REG_QUERY_KEY
 ****************************************************************************/
 
NTSTATUS _reg_query_key(pipes_struct *p, REG_Q_QUERY_KEY *q_u, REG_R_QUERY_KEY *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	Registry_Key	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	
	DEBUG(5,("_reg_query_key: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	
	
	if ( !get_subkey_information( regkey, &r_u->num_subkeys, &r_u->max_subkeylen ) )
		return NT_STATUS_ACCESS_DENIED;
		
	if ( !get_value_information( regkey, &r_u->num_values, &r_u->max_valnamelen, &r_u->max_valbufsize ) )
		return NT_STATUS_ACCESS_DENIED;	
		
	r_u->sec_desc = 0x0;	/* size for key's sec_desc */
	
	/* Win9x set this to 0x0 since it does not keep timestamps.
	   Doing the same here for simplicity   --jerry */
	   
	ZERO_STRUCT(r_u->mod_time);	

	DEBUG(5,("_reg_query_key: Exit\n"));
	
	return status;
}


/*****************************************************************************
 Implementation of REG_UNKNOWN_1A
 ****************************************************************************/
 
NTSTATUS _reg_unknown_1a(pipes_struct *p, REG_Q_UNKNOWN_1A *q_u, REG_R_UNKNOWN_1A *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	Registry_Key	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	
	DEBUG(5,("_reg_unknown_1a: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	
	
	r_u->unknown = 0x00000005;	/* seems to be consistent...no idea what it means */
	
	DEBUG(5,("_reg_unknown_1a: Exit\n"));
	
	return status;
}


/*****************************************************************************
 Implementation of REG_ENUM_KEY
 ****************************************************************************/
 
NTSTATUS _reg_enum_key(pipes_struct *p, REG_Q_ENUM_KEY *q_u, REG_R_ENUM_KEY *r_u)
{
	NTSTATUS 	status = NT_STATUS_OK;
	Registry_Key	*regkey = find_regkey_index_by_hnd( p, &q_u->pol );
	fstring		subkey;
	
	
	DEBUG(5,("_reg_enum_key: Enter\n"));
	
	if ( !regkey )
		return NT_STATUS_INVALID_HANDLE;	

	DEBUG(8,("_reg_enum_key: enumerating key [%s]\n", regkey->name));
	
	if ( !fetch_reg_keys_specific( tdb_reg, regkey->name, subkey, q_u->key_index ) )
	{
		status = werror_to_ntstatus( WERR_NO_MORE_ITEMS );
		goto done;
	}
	
	DEBUG(10,("_reg_enum_key: retrieved subkey named [%s]\n", subkey));
	
	/* subkey has the string name now */
	
	init_reg_r_enum_key( r_u, subkey, q_u->unknown_1, q_u->unknown_2 );
	
	DEBUG(5,("_reg_enum_key: Exit\n"));
	
done:	
	return status;
}


/*******************************************************************
 reg_shutdwon
 ********************************************************************/

#define SHUTDOWN_R_STRING "-r"
#define SHUTDOWN_F_STRING "-f"


NTSTATUS _reg_shutdown(pipes_struct *p, REG_Q_SHUTDOWN *q_u, REG_R_SHUTDOWN *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	pstring shutdown_script;
	UNISTR2 unimsg = q_u->uni_msg;
	pstring message;
	pstring chkmsg;
	fstring timeout;
	fstring r;
	fstring f;
	
	/* message */
	rpcstr_pull (message, unimsg.buffer, sizeof(message), unimsg.uni_str_len*2,0);
		/* security check */
	alpha_strcpy (chkmsg, message, NULL, sizeof(message));
	/* timeout */
	snprintf(timeout, sizeof(timeout), "%d", q_u->timeout);
	/* reboot */
	snprintf(r, sizeof(r), (q_u->flags & REG_REBOOT_ON_SHUTDOWN)?SHUTDOWN_R_STRING:"");
	/* force */
	snprintf(f, sizeof(f), (q_u->flags & REG_FORCE_SHUTDOWN)?SHUTDOWN_F_STRING:"");

	pstrcpy(shutdown_script, lp_shutdown_script());

	if(*shutdown_script) {
		int shutdown_ret;
		all_string_sub(shutdown_script, "%m", chkmsg, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%t", timeout, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%r", r, sizeof(shutdown_script));
		all_string_sub(shutdown_script, "%f", f, sizeof(shutdown_script));
		shutdown_ret = smbrun(shutdown_script,NULL);
		DEBUG(3,("_reg_shutdown: Running the command `%s' gave %d\n",shutdown_script,shutdown_ret));
	}

	return status;
}

/*******************************************************************
 reg_abort_shutdwon
 ********************************************************************/

NTSTATUS _reg_abort_shutdown(pipes_struct *p, REG_Q_ABORT_SHUTDOWN *q_u, REG_R_ABORT_SHUTDOWN *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	pstring abort_shutdown_script;

	pstrcpy(abort_shutdown_script, lp_abort_shutdown_script());

	if(*abort_shutdown_script) {
		int abort_shutdown_ret;
		abort_shutdown_ret = smbrun(abort_shutdown_script,NULL);
		DEBUG(3,("_reg_abort_shutdown: Running the command `%s' gave %d\n",abort_shutdown_script,abort_shutdown_ret));
	}

	return status;
}


