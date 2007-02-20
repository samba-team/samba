/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 * 
 *  Copyright (C) Gerald Carter                 2002-2006.
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
#include "regfio.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct generic_mapping reg_generic_map = 
	{ REG_KEY_READ, REG_KEY_WRITE, REG_KEY_EXECUTE, REG_KEY_ALL };

/******************************************************************
 free() function for struct regkey_info
 *****************************************************************/
 
static void free_regkey(void *ptr)
{
	struct registry_key *key = (struct registry_key *)ptr;
	TALLOC_FREE(key);
}

/******************************************************************
 Find a registry key handle and return a REGISTRY_KEY
 *****************************************************************/

static struct registry_key *find_regkey_by_hnd(pipes_struct *p,
					       POLICY_HND *hnd)
{
	struct registry_key *regkey = NULL;

	if(!find_policy_by_hnd(p,hnd,(void **)(void *)&regkey)) {
		DEBUG(2,("find_regkey_index_by_hnd: Registry Key not found: "));
		return NULL;
	}

	return regkey;
}

/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 
 When we open a key, we store the full path to the key as 
 HK[LM|U]\<key>\<key>\...
 *******************************************************************/
 
static WERROR open_registry_key( pipes_struct *p, POLICY_HND *hnd, 
				 struct registry_key *parent,
				 const char *subkeyname,
				 uint32 access_desired  )
{
	WERROR result = WERR_OK;
	struct registry_key *key;

	/* now do the internal open */

	if (parent == NULL) {
		result = reg_openhive(NULL, subkeyname, access_desired,
				      p->pipe_user.nt_user_token, &key);
	}
	else {
		result = reg_openkey(NULL, parent, subkeyname, access_desired,
				     &key);
	}

	if ( !W_ERROR_IS_OK(result) ) {
		return result;
	}
	
	if ( !create_policy_hnd( p, hnd, free_regkey, key ) ) {
		return WERR_BADFILE; 
	}
	
	return WERR_OK;;
}

/*******************************************************************
 Function for open a new registry handle and creating a handle 
 Note that P should be valid & hnd should already have space
 *******************************************************************/

static BOOL close_registry_key(pipes_struct *p, POLICY_HND *hnd)
{
	struct registry_key *regkey = find_regkey_by_hnd(p, hnd);
	
	if ( !regkey ) {
		DEBUG(2,("close_registry_key: Invalid handle (%s:%u:%u)\n",
			 OUR_HANDLE(hnd)));
		return False;
	}
	
	close_policy_hnd(p, hnd);
	
	return True;
}

/********************************************************************
 reg_close
 ********************************************************************/

WERROR _winreg_CloseKey(pipes_struct *p, struct winreg_CloseKey *r)
{
	/* close the policy handle */

	if (!close_registry_key(p, r->in.handle))
		return WERR_BADFID; 

	ZERO_STRUCTP(r->out.handle);

	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKLM(pipes_struct *p, struct winreg_OpenHKLM *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKLM, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKPD(pipes_struct *p, struct winreg_OpenHKPD *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKPD, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKPT(pipes_struct *p, struct winreg_OpenHKPT *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKPT, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKCR(pipes_struct *p, struct winreg_OpenHKCR *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKCR, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKU(pipes_struct *p, struct winreg_OpenHKU *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKU, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKCU(pipes_struct *p, struct winreg_OpenHKCU *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKCU, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKCC(pipes_struct *p, struct winreg_OpenHKCC *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKCC, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKDD(pipes_struct *p, struct winreg_OpenHKDD *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKDD, r->in.access_mask);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_OpenHKPN(pipes_struct *p, struct winreg_OpenHKPN *r)
{
	return open_registry_key(p, r->out.handle, NULL, KEY_HKPN, r->in.access_mask);
}

/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/

WERROR _winreg_OpenKey(pipes_struct *p, struct winreg_OpenKey *r)
{
	struct registry_key *parent = find_regkey_by_hnd(p, r->in.parent_handle );

	if ( !parent )
		return WERR_BADFID;

	return open_registry_key(p, r->out.handle, parent, r->in.keyname.name, r->in.access_mask);
}

/*******************************************************************
 reg_reply_info
 ********************************************************************/

WERROR _winreg_QueryValue(pipes_struct *p, struct winreg_QueryValue *r)
{
	WERROR        status = WERR_BADFILE;
	struct registry_key *regkey = find_regkey_by_hnd( p, r->in.handle );
	prs_struct    prs_hkpd;

	uint8_t *outbuf;
	uint32_t outbuf_size;

	DATA_BLOB val_blob;
	BOOL free_buf = False;
	BOOL free_prs = False;

	if ( !regkey )
		return WERR_BADFID;

	*r->out.value_length = *r->out.type = 0;
	
	DEBUG(7,("_reg_info: policy key name = [%s]\n", regkey->key->name));
	DEBUG(7,("_reg_info: policy key type = [%08x]\n", regkey->key->type));
	
	/* Handle QueryValue calls on HKEY_PERFORMANCE_DATA */
	if(regkey->key->type == REG_KEY_HKPD) 
	{
		if(strequal(r->in.value_name.name, "Global"))	{
			prs_init(&prs_hkpd, *r->in.data_size, p->mem_ctx, MARSHALL);
			status = reg_perfcount_get_hkpd(
				&prs_hkpd, *r->in.data_size, &outbuf_size, NULL);
			outbuf = (uint8_t *)prs_hkpd.data_p;
			free_prs = True;
		}
		else if(strequal(r->in.value_name.name, "Counter 009")) {
			outbuf_size = reg_perfcount_get_counter_names(
				reg_perfcount_get_base_index(),
				(char **)(void *)&outbuf);
			free_buf = True;
		}
		else if(strequal(r->in.value_name.name, "Explain 009")) {
			outbuf_size = reg_perfcount_get_counter_help(
				reg_perfcount_get_base_index(),
				(char **)(void *)&outbuf);
			free_buf = True;
		}
		else if(isdigit(r->in.value_name.name[0])) {
			/* we probably have a request for a specific object
			 * here */
			prs_init(&prs_hkpd, *r->in.data_size, p->mem_ctx, MARSHALL);
			status = reg_perfcount_get_hkpd(
				&prs_hkpd, *r->in.data_size, &outbuf_size,
				r->in.value_name.name);
			outbuf = (uint8_t *)prs_hkpd.data_p;
			free_prs = True;
		}
		else {
			DEBUG(3,("Unsupported key name [%s] for HKPD.\n",
				 r->in.value_name.name));
			return WERR_BADFILE;
		}

		*r->out.type = REG_BINARY;
	}
	else {
		struct registry_value *val;

		status = reg_queryvalue(p->mem_ctx, regkey, r->in.value_name.name,
					&val);
		if (!W_ERROR_IS_OK(status)) {
			if (r->out.data_size) {
				*r->out.data_size = 0;
			}
			if (r->out.value_length) {
				*r->out.value_length = 0;
			}
			return status;
		}

		status = registry_push_value(p->mem_ctx, val, &val_blob);
		if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		outbuf = val_blob.data;
		outbuf_size = val_blob.length;
		*r->out.type = val->type;
	}

	*r->out.value_length = outbuf_size;

	if ( *r->in.data_size == 0 || !r->out.data ) {
		status = WERR_OK;
	} else if ( *r->out.value_length > *r->in.data_size ) {
		status = WERR_MORE_DATA;
	} else {
		memcpy( r->out.data, outbuf, *r->out.value_length );
		status = WERR_OK;
	}

	*r->out.data_size = *r->out.value_length;

	if (free_prs) prs_mem_free(&prs_hkpd);
	if (free_buf) SAFE_FREE(outbuf);

	return status;
}

/*****************************************************************************
 Implementation of REG_QUERY_KEY
 ****************************************************************************/

WERROR _winreg_QueryInfoKey(pipes_struct *p, struct winreg_QueryInfoKey *r)
{
	WERROR 	status = WERR_OK;
	struct registry_key *regkey = find_regkey_by_hnd( p, r->in.handle );
	
	if ( !regkey )
		return WERR_BADFID;

	r->out.classname->name = NULL;

	status = reg_queryinfokey(regkey, r->out.num_subkeys, r->out.max_subkeylen,
				  r->out.max_classlen, r->out.num_values, r->out.max_valnamelen,
				  r->out.max_valbufsize, r->out.secdescsize,
				  r->out.last_changed_time);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	/*
	 * These calculations account for the registry buffers being
	 * UTF-16. They are inexact at best, but so far they worked.
	 */

	*r->out.max_subkeylen *= 2;

	*r->out.max_valnamelen += 1;
	*r->out.max_valnamelen *= 2;
	
	return WERR_OK;
}


/*****************************************************************************
 Implementation of REG_GETVERSION
 ****************************************************************************/
 
WERROR _winreg_GetVersion(pipes_struct *p, struct winreg_GetVersion *r)
{
	struct registry_key *regkey = find_regkey_by_hnd( p, r->in.handle );
	
	if ( !regkey )
		return WERR_BADFID;
	
	*r->out.version = 0x00000005;	/* Windows 2000 registry API version */
	
	return WERR_OK;
}


/*****************************************************************************
 Implementation of REG_ENUM_KEY
 ****************************************************************************/
 
WERROR _winreg_EnumKey(pipes_struct *p, struct winreg_EnumKey *r)
{
	WERROR err;
	struct registry_key *key = find_regkey_by_hnd( p, r->in.handle );
	
	if ( !key )
		return WERR_BADFID; 

	if ( !r->in.name || !r->in.keyclass )
		return WERR_INVALID_PARAM;

	DEBUG(8,("_reg_enum_key: enumerating key [%s]\n", key->key->name));

	err = reg_enumkey(p->mem_ctx, key, r->in.enum_index, (char **)&r->out.name->name,
			  r->out.last_changed_time);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}
	r->out.keyclass->name = "";
	return WERR_OK;
}

/*****************************************************************************
 Implementation of REG_ENUM_VALUE
 ****************************************************************************/

WERROR _winreg_EnumValue(pipes_struct *p, struct winreg_EnumValue *r)
{
	WERROR err;
	struct registry_key *key = find_regkey_by_hnd( p, r->in.handle );
	char *valname;
	struct registry_value *val;
	DATA_BLOB value_blob;
	
	if ( !key )
		return WERR_BADFID;

	if ( !r->in.name )
		return WERR_INVALID_PARAM;

	DEBUG(8,("_winreg_EnumValue: enumerating values for key [%s]\n",
		 key->key->name));

	err = reg_enumvalue(p->mem_ctx, key, r->in.enum_index, &valname, &val);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	err = registry_push_value(p->mem_ctx, val, &value_blob);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	if (r->out.name != NULL) {
		r->out.name->name = valname;
	}

	if (r->out.type != NULL) {
		*r->out.type = val->type;
	}

	if (r->out.value != NULL) {
		if ((r->out.size == NULL) || (r->out.length == NULL)) {
			return WERR_INVALID_PARAM;
		}

		if (value_blob.length > *r->out.size) {
			return WERR_MORE_DATA;
		}

		memcpy( r->out.value, value_blob.data, value_blob.length );
	}

	if (r->out.length != NULL) {
		*r->out.length = value_blob.length;
	}
	if (r->out.size != NULL) {
		*r->out.size = value_blob.length;
	}

	return WERR_OK;
}

/*******************************************************************
 reg_shutdwon
 ********************************************************************/

WERROR _winreg_InitiateSystemShutdown(pipes_struct *p, struct winreg_InitiateSystemShutdown *r)
{
	struct winreg_InitiateSystemShutdownEx s;

	s.in.hostname = r->in.hostname;
	s.in.message = r->in.message;
	s.in.timeout = r->in.timeout;
	s.in.force_apps = r->in.force_apps;
	s.in.reboot = r->in.reboot;
	s.in.reason = 0;

	/* thunk down to _winreg_InitiateSystemShutdownEx() 
	   (just returns a status) */
	
	return _winreg_InitiateSystemShutdownEx( p, &s );
}

/*******************************************************************
 reg_shutdown_ex
 ********************************************************************/

#define SHUTDOWN_R_STRING "-r"
#define SHUTDOWN_F_STRING "-f"


WERROR _winreg_InitiateSystemShutdownEx(pipes_struct *p, struct winreg_InitiateSystemShutdownEx *r)
{
	pstring shutdown_script;
	char *msg = NULL;
	pstring chkmsg;
	fstring str_timeout;
	fstring str_reason;
	fstring reboot;
	fstring f;
	int ret;
	BOOL can_shutdown;
	

 	pstrcpy(shutdown_script, lp_shutdown_script());
	
	if ( !*shutdown_script )
		return WERR_ACCESS_DENIED;

	/* pull the message string and perform necessary sanity checks on it */

	chkmsg[0] = '\0';

	if ( r->in.message && r->in.message->name && r->in.message->name->name ) {
		if ( (msg = talloc_strdup(p->mem_ctx, r->in.message->name->name )) == NULL ) {
			return WERR_NOMEM;
		}
		alpha_strcpy (chkmsg, msg, NULL, sizeof(chkmsg));
	} 
		
	fstr_sprintf(str_timeout, "%d", r->in.timeout);
	fstr_sprintf(reboot, r->in.reboot ? SHUTDOWN_R_STRING : "");
	fstr_sprintf(f, r->in.force_apps ? SHUTDOWN_F_STRING : "");
	fstr_sprintf(str_reason, "%d", r->in.reason );

	all_string_sub( shutdown_script, "%z", chkmsg, sizeof(shutdown_script) );
	all_string_sub( shutdown_script, "%t", str_timeout, sizeof(shutdown_script) );
	all_string_sub( shutdown_script, "%r", reboot, sizeof(shutdown_script) );
	all_string_sub( shutdown_script, "%f", f, sizeof(shutdown_script) );
	all_string_sub( shutdown_script, "%x", str_reason, sizeof(shutdown_script) );

	can_shutdown = user_has_privileges( p->pipe_user.nt_user_token, &se_remote_shutdown );
		
	/* IF someone has privs, run the shutdown script as root. OTHERWISE run it as not root
	   Take the error return from the script and provide it as the Windows return code. */
	   
	/********** BEGIN SeRemoteShutdownPrivilege BLOCK **********/
	
	if ( can_shutdown ) 
		become_root();

	ret = smbrun( shutdown_script, NULL );
		
	if ( can_shutdown )
		unbecome_root();

	/********** END SeRemoteShutdownPrivilege BLOCK **********/
	
	DEBUG(3,("_reg_shutdown_ex: Running the command `%s' gave %d\n",
		shutdown_script, ret));
		

	return (ret == 0) ? WERR_OK : WERR_ACCESS_DENIED;
}




/*******************************************************************
 reg_abort_shutdwon
 ********************************************************************/

WERROR _winreg_AbortSystemShutdown(pipes_struct *p, struct winreg_AbortSystemShutdown *r)
{
	pstring abort_shutdown_script;
	int ret;
	BOOL can_shutdown;

	pstrcpy(abort_shutdown_script, lp_abort_shutdown_script());

	if ( !*abort_shutdown_script )
		return WERR_ACCESS_DENIED;
		
	can_shutdown = user_has_privileges( p->pipe_user.nt_user_token, &se_remote_shutdown );
		
	/********** BEGIN SeRemoteShutdownPrivilege BLOCK **********/
	
	if ( can_shutdown )
		become_root();
		
	ret = smbrun( abort_shutdown_script, NULL );
	
	if ( can_shutdown )
		unbecome_root();
		
	/********** END SeRemoteShutdownPrivilege BLOCK **********/

	DEBUG(3,("_reg_abort_shutdown: Running the command `%s' gave %d\n",
		abort_shutdown_script, ret));
		

	return (ret == 0) ? WERR_OK : WERR_ACCESS_DENIED;
}

/*******************************************************************
 ********************************************************************/

static int validate_reg_filename( pstring fname )
{
	char *p;
	int num_services = lp_numservices();
	int snum;
	pstring share_path;
	pstring unix_fname;
	
	/* convert to a unix path, stripping the C:\ along the way */
	
	if ( !(p = valid_share_pathname( fname ) ))
		return -1;

	/* has to exist within a valid file share */
			
	for ( snum=0; snum<num_services; snum++ ) {
	
		if ( !lp_snum_ok(snum) || lp_print_ok(snum) )
			continue;
		
		pstrcpy( share_path, lp_pathname(snum) );

		/* make sure we have a path (e.g. [homes] ) */

		if ( strlen( share_path ) == 0 )
			continue;

		if ( strncmp( share_path, p, strlen( share_path )) == 0 )
			break;
	}
	
	/* p and fname are overlapping memory so copy out and back in again */
	
	pstrcpy( unix_fname, p );
	pstrcpy( fname, unix_fname );
	
	return (snum < num_services) ? snum : -1;
}

/*******************************************************************
 Note: topkeypat is the *full* path that this *key will be 
 loaded into (including the name of the key)
 ********************************************************************/

static WERROR reg_load_tree( REGF_FILE *regfile, const char *topkeypath,
                             REGF_NK_REC *key )
{
	REGF_NK_REC *subkey;
	REGISTRY_KEY registry_key;
	REGVAL_CTR *values;
	REGSUBKEY_CTR *subkeys;
	int i;
	pstring path;
	WERROR result = WERR_OK;
	
	/* initialize the REGISTRY_KEY structure */
	
	if ( !(registry_key.hook = reghook_cache_find(topkeypath)) ) {
		DEBUG(0,("reg_load_tree: Failed to assigned a REGISTRY_HOOK to [%s]\n",
			topkeypath ));
		return WERR_BADFILE;
	}
	pstrcpy( registry_key.name, topkeypath );
	
	/* now start parsing the values and subkeys */

	if ( !(subkeys = TALLOC_ZERO_P( regfile->mem_ctx, REGSUBKEY_CTR )) )
		return WERR_NOMEM;
	
	if ( !(values = TALLOC_ZERO_P( subkeys, REGVAL_CTR )) )
		return WERR_NOMEM;

	/* copy values into the REGVAL_CTR */
	
	for ( i=0; i<key->num_values; i++ ) {
		regval_ctr_addvalue( values, key->values[i].valuename, key->values[i].type,
			(char*)key->values[i].data, (key->values[i].data_size & ~VK_DATA_IN_OFFSET) );
	}

	/* copy subkeys into the REGSUBKEY_CTR */
	
	key->subkey_index = 0;
	while ( (subkey = regfio_fetch_subkey( regfile, key )) ) {
		regsubkey_ctr_addkey( subkeys, subkey->keyname );
	}
	
	/* write this key and values out */
	
	if ( !store_reg_values( &registry_key, values ) 
		|| !store_reg_keys( &registry_key, subkeys ) )
	{
		DEBUG(0,("reg_load_tree: Failed to load %s!\n", topkeypath));
		result = WERR_REG_IO_FAILURE;
	}
	
	TALLOC_FREE( subkeys );
	
	if ( !W_ERROR_IS_OK(result) )
		return result;
	
	/* now continue to load each subkey registry tree */

	key->subkey_index = 0;
	while ( (subkey = regfio_fetch_subkey( regfile, key )) ) {
		pstr_sprintf( path, "%s%s%s", topkeypath, "\\", subkey->keyname );
		result = reg_load_tree( regfile, path, subkey );
		if ( !W_ERROR_IS_OK(result) )
			break;
	}

	return result;
}

/*******************************************************************
 ********************************************************************/

static WERROR restore_registry_key ( REGISTRY_KEY *krecord, const char *fname )
{
	REGF_FILE *regfile;
	REGF_NK_REC *rootkey;
	WERROR result;
		
	/* open the registry file....fail if the file already exists */
	
	if ( !(regfile = regfio_open( fname, (O_RDONLY), 0 )) ) {
                DEBUG(0,("restore_registry_key: failed to open \"%s\" (%s)\n", 
			fname, strerror(errno) ));
		return ( ntstatus_to_werror(map_nt_error_from_unix( errno )) );
        }
	
	/* get the rootkey from the regf file and then load the tree
	   via recursive calls */
	   
	if ( !(rootkey = regfio_rootkey( regfile )) ) {
		regfio_close( regfile );
		return WERR_REG_FILE_INVALID;
	}
	
	result = reg_load_tree( regfile, krecord->name, rootkey );
		
	/* cleanup */
	
	regfio_close( regfile );
	
	return result;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_RestoreKey(pipes_struct *p, struct winreg_RestoreKey *r)
{
	struct registry_key *regkey = find_regkey_by_hnd( p, r->in.handle );
	pstring         fname;
	int             snum;
	
	if ( !regkey )
		return WERR_BADFID; 

	if ( !r->in.filename || !r->in.filename->name )
		return WERR_INVALID_PARAM;

	pstrcpy( fname, r->in.filename->name );

	DEBUG(8,("_winreg_RestoreKey: verifying restore of key [%s] from "
		 "\"%s\"\n", regkey->key->name, fname));

	if ( (snum = validate_reg_filename( fname )) == -1 )
		return WERR_OBJECT_PATH_INVALID;
		
	/* user must posses SeRestorePrivilege for this this proceed */
	
	if ( !user_has_privileges( p->pipe_user.nt_user_token, &se_restore ) )
		return WERR_ACCESS_DENIED;
		
	DEBUG(2,("_winreg_RestoreKey: Restoring [%s] from %s in share %s\n",
		 regkey->key->name, fname, lp_servicename(snum) ));

	return restore_registry_key( regkey->key, fname );
}

/********************************************************************
********************************************************************/

static WERROR reg_write_tree( REGF_FILE *regfile, const char *keypath,
                              REGF_NK_REC *parent, SEC_DESC *sec_desc )
{
	REGF_NK_REC *key;
	REGVAL_CTR *values;
	REGSUBKEY_CTR *subkeys;
	int i, num_subkeys;
	pstring key_tmp;
	char *keyname, *parentpath;
	pstring subkeypath;
	char *subkeyname;
	REGISTRY_KEY registry_key;
	WERROR result = WERR_OK;
	
	if ( !regfile )
		return WERR_GENERAL_FAILURE;
		
	if ( !keypath )
		return WERR_OBJECT_PATH_INVALID;
		
	/* split up the registry key path */
	
	pstrcpy( key_tmp, keypath );
	if ( !reg_split_key( key_tmp, &parentpath, &keyname ) )
		return WERR_OBJECT_PATH_INVALID;

	if ( !keyname )
		keyname = parentpath;

	/* we need a REGISTRY_KEY object here to enumerate subkeys and values */
	
	ZERO_STRUCT( registry_key );

	if ( (registry_key.name = talloc_strdup(regfile->mem_ctx, keypath)) == NULL )
		return WERR_NOMEM;

	if ( (registry_key.hook = reghook_cache_find( registry_key.name )) == NULL )
		return WERR_BADFILE;

	/* lookup the values and subkeys */
	
	if ( !(subkeys = TALLOC_ZERO_P( regfile->mem_ctx, REGSUBKEY_CTR )) ) 
		return WERR_NOMEM;

	if ( !(values = TALLOC_ZERO_P( subkeys, REGVAL_CTR )) )
		return WERR_NOMEM;

	fetch_reg_keys( &registry_key, subkeys );
	fetch_reg_values( &registry_key, values );

	/* write out this key */
		
	if ( !(key = regfio_write_key( regfile, keyname, values, subkeys, sec_desc, parent )) ) {
		result = WERR_CAN_NOT_COMPLETE;
		goto done;
	}

	/* write each one of the subkeys out */

	num_subkeys = regsubkey_ctr_numkeys( subkeys );
	for ( i=0; i<num_subkeys; i++ ) {
		subkeyname = regsubkey_ctr_specific_key( subkeys, i );
		pstr_sprintf( subkeypath, "%s\\%s", keypath, subkeyname );
		result = reg_write_tree( regfile, subkeypath, key, sec_desc );
		if ( !W_ERROR_IS_OK(result) )
			goto done;
	}

	DEBUG(6,("reg_write_tree: wrote key [%s]\n", keypath ));

done:
	TALLOC_FREE( subkeys );
	TALLOC_FREE( registry_key.name );

	return result;
}

/*******************************************************************
 ********************************************************************/

static WERROR make_default_reg_sd( TALLOC_CTX *ctx, SEC_DESC **psd )
{
	DOM_SID adm_sid, owner_sid;
	SEC_ACE ace[2];         /* at most 2 entries */
	SEC_ACCESS mask;
	SEC_ACL *psa = NULL;
	size_t sd_size;

	/* set the owner to BUILTIN\Administrator */

	sid_copy(&owner_sid, &global_sid_Builtin);
	sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN );
	

	/* basic access for Everyone */

	init_sec_access(&mask, reg_generic_map.generic_execute | reg_generic_map.generic_read );
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/* add Full Access 'BUILTIN\Administrators' */

	init_sec_access(&mask, reg_generic_map.generic_all);
	sid_copy(&adm_sid, &global_sid_Builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);
	init_sec_ace(&ace[1], &adm_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

        /* create the security descriptor */

        if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 2, ace)) == NULL)
                return WERR_NOMEM;

        if ((*psd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, &owner_sid, NULL, NULL, psa, &sd_size)) == NULL)
                return WERR_NOMEM;

	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

static WERROR backup_registry_key ( REGISTRY_KEY *krecord, const char *fname )
{
	REGF_FILE *regfile;
	WERROR result;
	SEC_DESC *sd = NULL;
	
	/* open the registry file....fail if the file already exists */
	
	if ( !(regfile = regfio_open( fname, (O_RDWR|O_CREAT|O_EXCL), (S_IREAD|S_IWRITE) )) ) {
                DEBUG(0,("backup_registry_key: failed to open \"%s\" (%s)\n", 
			fname, strerror(errno) ));
		return ( ntstatus_to_werror(map_nt_error_from_unix( errno )) );
        }
	
	if ( !W_ERROR_IS_OK(result = make_default_reg_sd( regfile->mem_ctx, &sd )) ) {
		regfio_close( regfile );
		return result;
	}
		
	/* write the registry tree to the file  */
	
	result = reg_write_tree( regfile, krecord->name, NULL, sd );
		
	/* cleanup */
	
	regfio_close( regfile );
	
	return result;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_SaveKey(pipes_struct *p, struct winreg_SaveKey *r)
{
	struct registry_key *regkey = find_regkey_by_hnd( p, r->in.handle );
	pstring         fname;
	int             snum;
	
	if ( !regkey )
		return WERR_BADFID; 

	if ( !r->in.filename || !r->in.filename->name )
		return WERR_INVALID_PARAM;

	pstrcpy( fname, r->in.filename->name );

	DEBUG(8,("_winreg_SaveKey: verifying backup of key [%s] to \"%s\"\n",
		 regkey->key->name, fname));
	
	if ( (snum = validate_reg_filename( fname )) == -1 )
		return WERR_OBJECT_PATH_INVALID;
		
	DEBUG(2,("_winreg_SaveKey: Saving [%s] to %s in share %s\n",
		 regkey->key->name, fname, lp_servicename(snum) ));
		
	return backup_registry_key( regkey->key, fname );
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_SaveKeyEx(pipes_struct *p, struct winreg_SaveKeyEx *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_CreateKey( pipes_struct *p, struct winreg_CreateKey *r)
{
	struct registry_key *parent = find_regkey_by_hnd(p, r->in.handle);
	struct registry_key *new_key;
	WERROR result;

	if ( !parent )
		return WERR_BADFID;

	result = reg_createkey(NULL, parent, r->in.name.name, r->in.access_mask,
			       &new_key, r->out.action_taken);
	if (!W_ERROR_IS_OK(result)) {
		return result;
	}

	if (!create_policy_hnd(p, r->out.new_handle, free_regkey, new_key)) {
		TALLOC_FREE(new_key);
		return WERR_BADFILE;
	}

	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_SetValue(pipes_struct *p, struct winreg_SetValue *r)
{
	struct registry_key *key = find_regkey_by_hnd(p, r->in.handle);
	struct registry_value *val;
	WERROR status;

	if ( !key )
		return WERR_BADFID;

	DEBUG(8,("_reg_set_value: Setting value for [%s:%s]\n", 
			 key->key->name, r->in.name.name));

	status = registry_pull_value(p->mem_ctx, &val, r->in.type, r->in.data, 
								 r->in.size, r->in.size);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	return reg_setvalue(key, r->in.name.name, val);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_DeleteKey(pipes_struct *p, struct winreg_DeleteKey *r)
{
	struct registry_key *parent = find_regkey_by_hnd(p, r->in.handle);

	if ( !parent )
		return WERR_BADFID;

	return reg_deletekey(parent, r->in.key.name);
}


/*******************************************************************
 ********************************************************************/

WERROR _winreg_DeleteValue(pipes_struct *p, struct winreg_DeleteValue *r)
{
	struct registry_key *key = find_regkey_by_hnd(p, r->in.handle);
	
	if ( !key )
		return WERR_BADFID;

	return reg_deletevalue(key, r->in.value.name);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_GetKeySecurity(pipes_struct *p, struct winreg_GetKeySecurity *r)
{
	struct registry_key *key = find_regkey_by_hnd(p, r->in.handle);
	WERROR err;
	struct security_descriptor *secdesc;
	uint8 *data;
	size_t len;

	if ( !key )
		return WERR_BADFID;
		
	/* access checks first */
	
	if ( !(key->key->access_granted & STD_RIGHT_READ_CONTROL_ACCESS) )
		return WERR_ACCESS_DENIED;

	err = regkey_get_secdesc(p->mem_ctx, key->key, &secdesc);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	err = ntstatus_to_werror(marshall_sec_desc(p->mem_ctx, secdesc,
						   &data, &len));
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	if (len > r->out.sd->size) {
		r->out.sd->size = len;
		return WERR_INSUFFICIENT_BUFFER;
	}

	r->out.sd->size = len;
	r->out.sd->len = len;
	r->out.sd->data = data;
		
	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_SetKeySecurity(pipes_struct *p, struct winreg_SetKeySecurity *r)
{
	struct registry_key *key = find_regkey_by_hnd(p, r->in.handle);
	struct security_descriptor *secdesc;
	WERROR err;

	if ( !key )
		return WERR_BADFID;
		
	/* access checks first */
	
	if ( !(key->key->access_granted & STD_RIGHT_WRITE_DAC_ACCESS) )
		return WERR_ACCESS_DENIED;

	err = ntstatus_to_werror(unmarshall_sec_desc(p->mem_ctx, r->in.sd->data,
						     r->in.sd->len, &secdesc));
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	return regkey_set_secdesc(key->key, secdesc);
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_FlushKey(pipes_struct *p, struct winreg_FlushKey *r)
{
	/* I'm just replying OK because there's not a lot 
	   here I see to do i  --jerry */
	
	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_UnLoadKey(pipes_struct *p, struct winreg_UnLoadKey *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_ReplaceKey(pipes_struct *p, struct winreg_ReplaceKey *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_LoadKey(pipes_struct *p, struct winreg_LoadKey *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_NotifyChangeKeyValue(pipes_struct *p, struct winreg_NotifyChangeKeyValue *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_QueryMultipleValues(pipes_struct *p, struct winreg_QueryMultipleValues *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/*******************************************************************
 ********************************************************************/

WERROR _winreg_QueryMultipleValues2(pipes_struct *p, struct winreg_QueryMultipleValues2 *r)
{
	/* fill in your code here if you think this call should
	   do anything */

	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

