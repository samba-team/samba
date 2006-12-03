/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
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

/* Implementation of registry frontend view functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

extern REGISTRY_OPS printing_ops;
extern REGISTRY_OPS eventlog_ops;
extern REGISTRY_OPS shares_reg_ops;
extern REGISTRY_OPS smbconf_reg_ops;
extern REGISTRY_OPS regdb_ops;		/* these are the default */

/* array of REGISTRY_HOOK's which are read into a tree for easy access */
/* #define REG_TDB_ONLY		1 */

REGISTRY_HOOK reg_hooks[] = {
#ifndef REG_TDB_ONLY 
  { KEY_PRINTING,    		&printing_ops },
  { KEY_PRINTING_2K, 		&printing_ops },
  { KEY_PRINTING_PORTS, 	&printing_ops },
  { KEY_SHARES,      		&shares_reg_ops },
  { KEY_SMBCONF,      		&smbconf_reg_ops },
#endif
  { NULL, NULL }
};


static struct generic_mapping reg_generic_map = 
	{ REG_KEY_READ, REG_KEY_WRITE, REG_KEY_EXECUTE, REG_KEY_ALL };

/********************************************************************
********************************************************************/

static SEC_DESC* construct_registry_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[2];	
	SEC_ACCESS mask;
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *acl;
	size_t sd_size;

	/* basic access for Everyone */
	
	init_sec_access(&mask, REG_KEY_READ );
	init_sec_ace(&ace[i++], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	/* Full Access 'BUILTIN\Administrators' */
	
	init_sec_access(&mask, REG_KEY_ALL );
	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	
	/* create the security descriptor */
	
	if ( !(acl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) )
		return NULL;

	if ( !(sd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, acl, &sd_size)) )
		return NULL;

	return sd;
}


/***********************************************************************
 Open the registry database and initialize the REGISTRY_HOOK cache
 ***********************************************************************/
 
BOOL init_registry( void )
{
	int i;
	
	
	/* build the cache tree of registry hooks */
	
	reghook_cache_init();
	
	if ( !regdb_init() ) {
		DEBUG(0,("init_registry: failed to initialize the registry "
			 "tdb!\n"));
		return False;
	}

	for ( i=0; reg_hooks[i].keyname; i++ ) {
		if ( !reghook_cache_add(&reg_hooks[i]) )
			return False;
	}

	if ( DEBUGLEVEL >= 20 )
		reghook_dump_cache(20);

	/* add any keys for other services */

	svcctl_init_keys();
	eventlog_init_keys();
	perfcount_init_keys();

	/* close and let each smbd open up as necessary */

	regdb_close();

	return True;
}

/***********************************************************************
 High level wrapper function for storing registry subkeys
 ***********************************************************************/
 
BOOL store_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkeys )
{
	if ( key->hook && key->hook->ops && key->hook->ops->store_subkeys )
		return key->hook->ops->store_subkeys( key->name, subkeys );
		
	return False;

}

/***********************************************************************
 High level wrapper function for storing registry values
 ***********************************************************************/
 
BOOL store_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	if ( check_dynamic_reg_values( key ) )
		return False;

	if ( key->hook && key->hook->ops && key->hook->ops->store_values )
		return key->hook->ops->store_values( key->name, val );

	return False;
}


/***********************************************************************
 High level wrapper function for enumerating registry subkeys
 Initialize the TALLOC_CTX if necessary
 ***********************************************************************/

int fetch_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkey_ctr )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->fetch_subkeys )
		result = key->hook->ops->fetch_subkeys( key->name, subkey_ctr );

	return result;
}

/***********************************************************************
 High level wrapper function for enumerating registry values
 ***********************************************************************/

int fetch_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->fetch_values )
		result = key->hook->ops->fetch_values( key->name, val );
	
	/* if the backend lookup returned no data, try the dynamic overlay */
	
	if ( result == 0 ) {
		result = fetch_dynamic_reg_values( key, val );

		return ( result != -1 ) ? result : 0;
	}
	
	return result;
}

WERROR registry_fetch_values(TALLOC_CTX *mem_ctx, REGISTRY_KEY *key,
			     uint32 *pnum_values, char ***pnames,
			     struct registry_value ***pvalues)
{
	REGVAL_CTR *ctr;
	char **names;
	struct registry_value **values;
	uint32 i;

	if (!(ctr = TALLOC_ZERO_P(mem_ctx, REGVAL_CTR))) {
		return WERR_NOMEM;
	}

	if (fetch_reg_values(key, ctr) == -1) {
		TALLOC_FREE(ctr);
		return WERR_INVALID_PARAM;
	}

	if (ctr->num_values == 0) {
		*pnum_values = 0;
		TALLOC_FREE(ctr);
		return WERR_OK;
	}

	if ((!(names = TALLOC_ARRAY(ctr, char *, ctr->num_values))) ||
	    (!(values = TALLOC_ARRAY(ctr, struct registry_value *,
				     ctr->num_values)))) {
		TALLOC_FREE(ctr);
		return WERR_NOMEM;
	}

	for (i=0; i<ctr->num_values; i++) {
		REGISTRY_VALUE *val = ctr->values[i];
		WERROR err;

		if (!(names[i] = talloc_strdup(names, val->valuename))) {
			TALLOC_FREE(ctr);
			return WERR_NOMEM;
		}

		err = registry_pull_value(values, &values[i],
					  val->type, val->data_p,
					  val->size, val->size);
		if (!W_ERROR_IS_OK(err)) {
			TALLOC_FREE(ctr);
			return err;
		}
	}

	*pnum_values = ctr->num_values;
	*pnames = talloc_move(mem_ctx, &names);
	*pvalues = talloc_move(mem_ctx, &values);

	TALLOC_FREE(ctr);
	return WERR_OK;
}

/***********************************************************************
 High level access check for passing the required access mask to the 
 underlying registry backend
 ***********************************************************************/

BOOL regkey_access_check( REGISTRY_KEY *key, uint32 requested, uint32 *granted,
			  const struct nt_user_token *token )
{
	SEC_DESC *sec_desc;
	NTSTATUS status;
	WERROR err;
	TALLOC_CTX *mem_ctx;

	/* use the default security check if the backend has not defined its
	 * own */

	if (key->hook && key->hook->ops && key->hook->ops->reg_access_check) {
		return key->hook->ops->reg_access_check( key->name, requested,
							 granted, token );
	}

	/*
	 * The secdesc routines can't yet cope with a NULL talloc ctx sanely.
	 */

	if (!(mem_ctx = talloc_init("regkey_access_check"))) {
		return False;
	}

	err = regkey_get_secdesc(mem_ctx, key, &sec_desc);

	if (!W_ERROR_IS_OK(err)) {
		TALLOC_FREE(mem_ctx);
		return False;
	}

	se_map_generic( &requested, &reg_generic_map );

	if (!se_access_check(sec_desc, token, requested, granted, &status)) {
		TALLOC_FREE(mem_ctx);
		return False;
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_IS_OK(status);
}

/***********************************************************************
***********************************************************************/

static int regkey_destructor(REGISTRY_KEY *key)
{
	return regdb_close();
}

WERROR regkey_open_onelevel( TALLOC_CTX *mem_ctx, REGISTRY_KEY *parent,
			     REGISTRY_KEY **regkey, const char *name,
                             const struct nt_user_token *token,
			     uint32 access_desired )
{
	WERROR     	result = WERR_OK;
	REGISTRY_KEY    *key;
	REGSUBKEY_CTR	*subkeys = NULL;

	DEBUG(7,("regkey_open_onelevel: name = [%s]\n", name));

	if ((parent != NULL) &&
	    ((parent->access_granted & SEC_RIGHTS_ENUM_SUBKEYS) == 0)) {
		return WERR_ACCESS_DENIED;
	}

	if ( !(key = TALLOC_ZERO_P(mem_ctx, REGISTRY_KEY)) ) {
		return WERR_NOMEM;
	}

	if ( !(W_ERROR_IS_OK(result = regdb_open()) ) ) {
		TALLOC_FREE(key);
		return result;
	}

	talloc_set_destructor(key, regkey_destructor);
		
	/* initialization */
	
	key->type = REG_KEY_GENERIC;

	if (name[0] == '\0') {
		/*
		 * Open a copy of the parent key
		 */
		if (!parent) {
			result = WERR_BADFILE;
			goto done;
		}
		key->name = talloc_strdup(key, parent->name);
	}
	else {
		/*
		 * Normal open, concat parent and new keynames
		 */
		key->name = talloc_asprintf(key, "%s%s%s",
					    parent ? parent->name : "",
					    parent ? "\\": "",
					    name);
	}

	if (key->name == NULL) {
		result = WERR_NOMEM;
		goto done;
	}

	/* Tag this as a Performance Counter Key */

	if( StrnCaseCmp(key->name, KEY_HKPD, strlen(KEY_HKPD)) == 0 )
		key->type = REG_KEY_HKPD;
	
	/* Look up the table of registry I/O operations */

	if ( !(key->hook = reghook_cache_find( key->name )) ) {
		DEBUG(0,("reg_open_onelevel: Failed to assigned a "
			 "REGISTRY_HOOK to [%s]\n", key->name ));
		result = WERR_BADFILE;
		goto done;
	}
	
	/* check if the path really exists; failed is indicated by -1 */
	/* if the subkey count failed, bail out */

	if ( !(subkeys = TALLOC_ZERO_P( key, REGSUBKEY_CTR )) ) {
		result = WERR_NOMEM;
		goto done;
	}

	if ( fetch_reg_keys( key, subkeys ) == -1 )  {
		result = WERR_BADFILE;
		goto done;
	}
	
	TALLOC_FREE( subkeys );

	if ( !regkey_access_check( key, access_desired, &key->access_granted,
				   token ) ) {
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	*regkey = key;
	result = WERR_OK;
	
done:
	if ( !W_ERROR_IS_OK(result) ) {
		TALLOC_FREE(key);
	}

	return result;
}

WERROR regkey_open_internal( TALLOC_CTX *ctx, REGISTRY_KEY **regkey,
			     const char *path,
                             const struct nt_user_token *token,
			     uint32 access_desired )
{
	TALLOC_CTX *mem_ctx;
	const char *p;
	REGISTRY_KEY *parent = NULL;
	WERROR err;
	size_t len;

	if (!(mem_ctx = talloc_new(ctx))) {
		return WERR_NOMEM;
	}

	len = strlen(path);
	if ((len > 0) && (path[len-1] == '\\')) {
		if (!(path = talloc_strndup(mem_ctx, path, len-1))) {
			TALLOC_FREE(mem_ctx);
			return WERR_NOMEM;
		}
	}

	while ((p = strchr(path, '\\')) != NULL) {
		char *name_component;
		REGISTRY_KEY *intermediate;

		if (!(name_component = talloc_strndup(
			      mem_ctx, path, (p - path)))) {
			TALLOC_FREE(mem_ctx);
			return WERR_NOMEM;
		}

		err = regkey_open_onelevel(mem_ctx, parent, &intermediate,
					   name_component, token,
					   SEC_RIGHTS_ENUM_SUBKEYS);
		TALLOC_FREE(name_component);

		if (!W_ERROR_IS_OK(err)) {
			TALLOC_FREE(mem_ctx);
			return WERR_NOMEM;
		}

		TALLOC_FREE(parent);
		parent = intermediate;
		path = p+1;
	}

	err = regkey_open_onelevel(ctx, parent, regkey, path, token,
				   access_desired);
	TALLOC_FREE(mem_ctx);
	return err;
}

WERROR regkey_get_secdesc(TALLOC_CTX *mem_ctx, REGISTRY_KEY *key,
			  struct security_descriptor **psecdesc)
{
	struct security_descriptor *secdesc;

	if (key->hook && key->hook->ops && key->hook->ops->get_secdesc) {
		WERROR err;

		err = key->hook->ops->get_secdesc(mem_ctx, key->name,
						  psecdesc);
		if (W_ERROR_IS_OK(err)) {
			return WERR_OK;
		}
	}

	if (!(secdesc = construct_registry_sd(mem_ctx))) {
		return WERR_NOMEM;
	}

	*psecdesc = secdesc;
	return WERR_OK;
}

WERROR regkey_set_secdesc(REGISTRY_KEY *key,
			  struct security_descriptor *psecdesc)
{
	if (key->hook && key->hook->ops && key->hook->ops->set_secdesc) {
		return key->hook->ops->set_secdesc(key->name, psecdesc);
	}

	return WERR_ACCESS_DENIED;
}


/*
 * Utility function to open a complete registry path including the hive
 * prefix. This should become the replacement function for
 * regkey_open_internal.
 */

WERROR reg_open_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		     uint32 desired_access, const struct nt_user_token *token,
		     struct registry_key **pkey)
{
	struct registry_key *hive, *key;
	char *path, *p;
	WERROR err;

	if (!(path = SMB_STRDUP(orig_path))) {
		return WERR_NOMEM;
	}

	p = strchr(path, '\\');

	if ((p == NULL) || (p[1] == '\0')) {
		/*
		 * No key behind the hive, just return the hive
		 */

		err = reg_openhive(mem_ctx, path, desired_access, token,
				   &hive);
		if (!W_ERROR_IS_OK(err)) {
			SAFE_FREE(path);
			return err;
		}
		SAFE_FREE(path);
		*pkey = hive;
		return WERR_OK;
	}

	*p = '\0';

	err = reg_openhive(mem_ctx, path, SEC_RIGHTS_ENUM_SUBKEYS, token,
			   &hive);
	if (!W_ERROR_IS_OK(err)) {
		SAFE_FREE(path);
		return err;
	}

	err = reg_openkey(mem_ctx, hive, p+1, desired_access, &key);

	TALLOC_FREE(hive);
	SAFE_FREE(path);

	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	*pkey = key;
	return WERR_OK;
}

/*
 * Utility function to create a registry key without opening the hive
 * before. Assumes the hive already exists.
 */

WERROR reg_create_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		       uint32 desired_access,
		       const struct nt_user_token *token,
		       enum winreg_CreateAction *paction,
		       struct registry_key **pkey)
{
	struct registry_key *hive;
	char *path, *p;
	WERROR err;

	if (!(path = SMB_STRDUP(orig_path))) {
		return WERR_NOMEM;
	}

	p = strchr(path, '\\');

	if ((p == NULL) || (p[1] == '\0')) {
		/*
		 * No key behind the hive, just return the hive
		 */

		err = reg_openhive(mem_ctx, path, desired_access, token,
				   &hive);
		if (!W_ERROR_IS_OK(err)) {
			SAFE_FREE(path);
			return err;
		}
		SAFE_FREE(path);
		*pkey = hive;
		*paction = REG_OPENED_EXISTING_KEY;
		return WERR_OK;
	}

	*p = '\0';

	err = reg_openhive(mem_ctx, path,
			   (strchr(p+1, '\\') != NULL) ?
			   SEC_RIGHTS_ENUM_SUBKEYS : SEC_RIGHTS_CREATE_SUBKEY,
			   token, &hive);
	if (!W_ERROR_IS_OK(err)) {
		SAFE_FREE(path);
		return err;
	}

	err = reg_createkey(mem_ctx, hive, p+1, desired_access, pkey, paction);
	SAFE_FREE(path);
	TALLOC_FREE(hive);
	return err;
}

/*
 * Utility function to create a registry key without opening the hive
 * before. Will not delete a hive.
 */

WERROR reg_delete_path(const struct nt_user_token *token,
		       const char *orig_path)
{
	struct registry_key *hive;
	char *path, *p;
	WERROR err;

	if (!(path = SMB_STRDUP(orig_path))) {
		return WERR_NOMEM;
	}

	p = strchr(path, '\\');

	if ((p == NULL) || (p[1] == '\0')) {
		return WERR_INVALID_PARAM;
	}

	*p = '\0';

	err = reg_openhive(NULL, path,
			   (strchr(p+1, '\\') != NULL) ?
			   SEC_RIGHTS_ENUM_SUBKEYS : SEC_RIGHTS_CREATE_SUBKEY,
			   token, &hive);
	if (!W_ERROR_IS_OK(err)) {
		SAFE_FREE(path);
		return err;
	}

	err = reg_deletekey(hive, p+1);
	SAFE_FREE(path);
	TALLOC_FREE(hive);
	return err;
}

WERROR reg_set_dword(struct registry_key *key, const char *valuename,
		     uint32 value)
{
	struct registry_value val;
	ZERO_STRUCT(val);
	val.type = REG_DWORD;
	val.v.dword = value;
	return reg_setvalue(key, valuename, &val);
}

WERROR reg_set_sz(struct registry_key *key, const char *valuename,
		  const char *value)
{
	struct registry_value val;
	ZERO_STRUCT(val);
	val.type = REG_SZ;
	val.v.sz.str = CONST_DISCARD(char *, value);
	val.v.sz.len = strlen(value)+1;
	return reg_setvalue(key, valuename, &val);
}
