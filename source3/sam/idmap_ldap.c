/* 
   Unix SMB/CIFS implementation.

   idmap LDAP backend

   Copyright (C) Tim Potter 		2000
   Copyright (C) Anthony Liguori 	2003
   Copyright (C) Simo Sorce 		2003
   Copyright (C) Gerald Carter 		2003
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP


#include <lber.h>
#include <ldap.h>

#include "smbldap.h"

#define IDMAP_GROUP_SUFFIX	"ou=idmap group"
#define IDMAP_USER_SUFFIX	"ou=idmap people"


struct ldap_idmap_state {
	struct smbldap_state *smbldap_state;
	TALLOC_CTX *mem_ctx;

	/* struct ldap_idmap_state *prev, *next; */
};

#define LDAP_MAX_ALLOC_ID 128              /* number tries while allocating
					      new id */

static struct ldap_idmap_state ldap_state;

static NTSTATUS ldap_set_mapping(const DOM_SID *sid, unid_t id, int id_type);
static NTSTATUS ldap_set_mapping_internals(const DOM_SID *sid, unid_t id, int id_type, 
					   const char *ldap_dn, LDAPMessage *entry);
static NTSTATUS ldap_idmap_close(void);


/*****************************************************************************
 Allocate a new uid or gid
*****************************************************************************/

static NTSTATUS ldap_allocate_id(unid_t *id, int id_type)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	int rc = LDAP_SERVER_DOWN;
	int count = 0;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	pstring id_str, new_id_str;
	LDAPMod **mods = NULL;
	const char *type;
	char *dn;
	char **attr_list;
	pstring filter;
	uid_t	luid, huid;
	gid_t	lgid, hgid;


	type = (id_type & ID_USERID) ?
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER ) : 
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );

	snprintf(filter, sizeof(filter)-1, "(objectClass=%s)", LDAP_OBJ_IDPOOL);

	attr_list = get_attr_list( idpool_attr_list );
	
	rc = smbldap_search(ldap_state.smbldap_state, lp_ldap_idmap_suffix(),
			       LDAP_SCOPE_SUBTREE, filter,
			       attr_list, 0, &result);
	free_attr_list( attr_list );
	 
	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_allocate_id: %s object not found\n", LDAP_OBJ_IDPOOL));
		goto out;
	}
	
	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	if (count != 1) {
		DEBUG(0,("ldap_allocate_id: single %s object not found\n", LDAP_OBJ_IDPOOL));
		goto out;
	}

	dn = ldap_get_dn(ldap_state.smbldap_state->ldap_struct, result);
	entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);

	if (!smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, type, id_str)) {
		DEBUG(0,("ldap_allocate_id: %s attribute not found\n",
			 type));
		goto out;
	}

	/* this must succeed or else we wouldn't have initialized */
		
	lp_idmap_uid( &luid, &huid);
	lp_idmap_gid( &lgid, &hgid);
	
	/* make sure we still have room to grow */
	
	if (id_type & ID_USERID) {
		id->uid = strtoul(id_str, NULL, 10);
		if (id->uid > huid ) {
			DEBUG(0,("ldap_allocate_id: Cannot allocate uid above %d!\n", huid));
			goto out;
		}
	}
	else { 
		id->gid = strtoul(id_str, NULL, 10);
		if (id->gid > hgid ) {
			DEBUG(0,("ldap_allocate_id: Cannot allocate gid above %d!\n", hgid));
			goto out;
		}
	}
	
	snprintf(new_id_str, sizeof(new_id_str), "%u", 
		 ((id_type & ID_USERID) ? id->uid : id->gid) + 1);
		 
	smbldap_set_mod( &mods, LDAP_MOD_DELETE, type, id_str );		 
	smbldap_set_mod( &mods, LDAP_MOD_ADD, type, new_id_str );
	
	rc = ldap_modify_s(ldap_state.smbldap_state->ldap_struct, dn, mods);

	ldap_memfree(dn);
	ldap_mods_free( mods, True );
	
	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_allocate_id: Failed to allocate new %s.  ldap_modify() failed.\n",
			type));
		goto out;
	}
	
	ret = NT_STATUS_OK;
out:
	return ret;
}

/*****************************************************************************
 get a sid from an id
*****************************************************************************/

static NTSTATUS ldap_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type)
{
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	fstring id_str;
	pstring sid_str;
	pstring filter;
	pstring suffix;
	const char *type;
	const char *obj_class;
	int rc;
	int count;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	char **attr_list;

	/* first we try for a samba user or group mapping */
	
	if ( id_type & ID_USERID ) {
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER );
		obj_class = LDAP_OBJ_SAMBASAMACCOUNT;
		snprintf(id_str, sizeof(id_str), "%u", id.uid );	
		pstrcpy( suffix, lp_ldap_suffix());
	}
	else {
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );
		obj_class = LDAP_OBJ_GROUPMAP;
		snprintf(id_str, sizeof(id_str), "%u", id.gid );	
		pstrcpy( suffix, lp_ldap_group_suffix() );
	}
		 
	attr_list = get_attr_list( sidmap_attr_list );
	snprintf(filter, sizeof(filter), "(&(|(objectClass=%s)(objectClass=%s))(%s=%s))", 
		 LDAP_OBJ_IDMAP_ENTRY, obj_class, type, id_str);

	rc = smbldap_search(ldap_state.smbldap_state, suffix, LDAP_SCOPE_SUBTREE, 
			    filter, attr_list, 0, &result);
	
	if (rc != LDAP_SUCCESS) 
		goto out;
	   
	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);

	/* fall back to looking up an idmap entry if we didn't find and 
	   actual user or group */
	
	if (count == 0) {
		ldap_msgfree(result);
		result = NULL;
		
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%u))",
			LDAP_OBJ_IDMAP_ENTRY, type,  ((id_type & ID_USERID) ? id.uid : id.gid));

		pstrcpy( suffix, lp_ldap_idmap_suffix() );

		rc = smbldap_search(ldap_state.smbldap_state, suffix, LDAP_SCOPE_SUBTREE, 
			filter, attr_list, 0, &result);

		if (rc != LDAP_SUCCESS)
			   goto out;
			   
		count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	}
	
	if (count != 1) {
		DEBUG(0,("ldap_get_sid_from_id: mapping not found for %s: %u\n", 
			type, ((id_type & ID_USERID) ? id.uid : id.gid)));
		goto out;
	}
	
	entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);
	
	if ( !smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, LDAP_ATTRIBUTE_SID, sid_str) )
		goto out;
	   
	if (!string_to_sid(sid, sid_str)) 
		goto out;

	ret = NT_STATUS_OK;
out:
	free_attr_list( attr_list );	 

	if (result)
		ldap_msgfree(result);

	return ret;
}

/***********************************************************************
 Get an id from a sid 
***********************************************************************/

static NTSTATUS ldap_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid)
{
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	pstring sid_str;
	pstring filter;
	pstring id_str;
	const char *suffix;	
	const char *type;
	const char *obj_class;
	const char *posix_obj_class;
	int rc;
	int count;
	char **attr_list;
	char *dn = NULL;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	/* first try getting the mapping from a samba user or group */
	
	sid_to_string(sid_str, sid);
	if ( *id_type & ID_USERID ) {
		type = get_attr_key2string( sidmap_attr_list, LDAP_ATTR_UIDNUMBER );
		obj_class = LDAP_OBJ_SAMBASAMACCOUNT;
		posix_obj_class = LDAP_OBJ_POSIXACCOUNT;
		suffix = lp_ldap_suffix();
		snprintf(filter, sizeof(filter), 
			 "(&(|(&(objectClass=%s)(objectClass=%s))(objectClass=%s))(%s=%s))", 
			 obj_class, posix_obj_class, LDAP_OBJ_IDMAP_ENTRY, 
			 get_attr_key2string( sidmap_attr_list, LDAP_ATTR_SID ), 
			 sid_str);
	}
	else {
		type = get_attr_key2string( sidmap_attr_list, LDAP_ATTR_GIDNUMBER );
		obj_class = LDAP_OBJ_GROUPMAP;
		posix_obj_class = LDAP_OBJ_POSIXGROUP;
		suffix = lp_ldap_group_suffix();
		snprintf(filter, sizeof(filter), 
			 "(&(|(objectClass=%s)(objectClass=%s))(%s=%s))", 
			 obj_class, LDAP_OBJ_IDMAP_ENTRY, 
			 get_attr_key2string( sidmap_attr_list, LDAP_ATTR_SID ), 
			 sid_str);
	}
	   
	attr_list = get_attr_list( sidmap_attr_list );
	rc = smbldap_search(ldap_state.smbldap_state, suffix, LDAP_SCOPE_SUBTREE, 
		filter, attr_list, 0, &result);
		
	if (rc != LDAP_SUCCESS)
		goto out;

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	
	/* fall back to looking up an idmap entry if we didn't find anything under the idmap
	   user or group suffix */

	if (count == 0) {
		ldap_msgfree(result);
		
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%s))", 
			LDAP_OBJ_IDMAP_ENTRY, LDAP_ATTRIBUTE_SID, sid_str);

		suffix = lp_ldap_idmap_suffix();

		rc = smbldap_search(ldap_state.smbldap_state, suffix, LDAP_SCOPE_SUBTREE, 
			filter, attr_list, 0, &result);
			
		if (rc != LDAP_SUCCESS)
			goto out;
			
		count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	}
	   
	if ( count > 1 ) {
		DEBUG(0, ("ldap_get_id_from_sid: search %s returned more than on entry!\n",
			filter));
		goto out;
	}

	/* we might have an existing entry to work with so pull out the requested information */
	
	if ( count ) {
		entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);
	
		dn = ldap_get_dn(ldap_state.smbldap_state->ldap_struct, result);
		DEBUG(10, ("Found mapping entry at dn=%s, looking for %s\n", dn, type));
		
		if ( smbldap_get_single_attribute(ldap_state.smbldap_state->ldap_struct, entry, type, id_str) ) 
		{
			if ( (*id_type & ID_USERID) )
				id->uid = strtoul(id_str, NULL, 10);
			else
				id->gid = strtoul(id_str, NULL, 10);
			
			ret = NT_STATUS_OK;
			goto out;
		}
	}
	
	if (!(*id_type & ID_QUERY_ONLY)) {
		/* if entry == NULL, and we are asked to - allocate a new id */
		int i;
		
		for (i = 0; i < LDAP_MAX_ALLOC_ID; i++) 
		{
			ret = ldap_allocate_id(id, *id_type);
			if ( NT_STATUS_IS_OK(ret) )
				break;
		}
		
		if ( !NT_STATUS_IS_OK(ret) ) {
			DEBUG(0,("ldap_allocate_id: cannot acquire id lock!\n"));
			goto out;
		}
		
		ret = ldap_set_mapping(sid, *id, *id_type);
	} else {
		/* no match, and not adding one */
		ret = NT_STATUS_UNSUCCESSFUL;
	}

out:
	free_attr_list( attr_list );
	if (result)
		ldap_msgfree(result);
	if (dn)
		ldap_memfree(dn);
	
	return ret;
}

/***********************************************************************
 This function cannot be called to modify a mapping, only set a new one 

 This takes a possible pointer to the existing entry for the UID or SID
 involved.
***********************************************************************/

static NTSTATUS ldap_set_mapping_internals(const DOM_SID *sid, unid_t id, 
					   int id_type, const char *ldap_dn, 
					   LDAPMessage *entry)
{
	char *dn = NULL;
	pstring id_str;
	fstring type;
	LDAPMod **mods = NULL;
	int rc = -1;
	int ldap_op;
	fstring sid_string;
	char **values = NULL;
	int i;

	sid_to_string( sid_string, sid );

	if (ldap_dn) {
		DEBUG(10, ("Adding new IDMAP mapping on DN: %s", ldap_dn));
		ldap_op = LDAP_MOD_REPLACE;
		dn = strdup(ldap_dn);
	} else {
		ldap_op = LDAP_MOD_ADD;
		asprintf(&dn, "%s=%s,%s", get_attr_key2string( sidmap_attr_list, LDAP_ATTR_SID), 
			 sid_string, lp_ldap_idmap_suffix());
	}
	
	if (!dn) {
		DEBUG(0, ("ldap_set_mapping_internals: out of memory allocating DN!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if ( id_type & ID_USERID ) 
		fstrcpy( type, get_attr_key2string( sidmap_attr_list, LDAP_ATTR_UIDNUMBER ) );
	else
		fstrcpy( type, get_attr_key2string( sidmap_attr_list, LDAP_ATTR_GIDNUMBER ) );

	snprintf(id_str, sizeof(id_str), "%u", ((id_type & ID_USERID) ? id.uid : id.gid));	
	
	if (entry) 
		values = ldap_get_values(ldap_state.smbldap_state->ldap_struct, entry, "objectClass");

	if (values) {
		BOOL found_idmap = False;
		for (i=0; values[i]; i++) {
			if (StrCaseCmp(values[i], LDAP_OBJ_IDMAP_ENTRY) == 0) {
				found_idmap = True;
				break;
			}
		}
		if (!found_idmap)
			smbldap_set_mod( &mods, LDAP_MOD_ADD, 
					 "objectClass", LDAP_OBJ_IDMAP_ENTRY );
	} else {
		smbldap_set_mod( &mods, LDAP_MOD_ADD, 
				 "objectClass", LDAP_OBJ_IDMAP_ENTRY );
	}

	smbldap_make_mod( ldap_state.smbldap_state->ldap_struct, 
			  entry, &mods, type, id_str );

	smbldap_make_mod( ldap_state.smbldap_state->ldap_struct, 
			  entry, &mods,  
			  get_attr_key2string(sidmap_attr_list, LDAP_ATTR_SID), 
			  sid_string );

	/* There may well be nothing at all to do */
	if (mods) {
		switch(ldap_op)
		{
		case LDAP_MOD_ADD: 
			smbldap_set_mod( &mods, LDAP_MOD_ADD, 
					 "objectClass", LDAP_OBJ_SID_ENTRY );
			rc = smbldap_add(ldap_state.smbldap_state, dn, mods);
			break;
		case LDAP_MOD_REPLACE: 
			rc = smbldap_modify(ldap_state.smbldap_state, dn, mods);
			break;
		}
		
		ldap_mods_free( mods, True );	
	} else {
		rc = LDAP_SUCCESS;
	}

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state.smbldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,("ldap_set_mapping_internals: Failed to %s mapping from %s to %u [%s]\n",
			 (ldap_op == LDAP_MOD_ADD) ? "add" : "replace",
			 sid_string, (unsigned int)((id_type & ID_USERID) ? id.uid : id.gid), type));
		DEBUG(0, ("ldap_set_mapping_internals: Error was: %s (%s)\n", ld_error ? ld_error : "(NULL)", ldap_err2string (rc)));
		return NT_STATUS_UNSUCCESSFUL;
	}
		
	DEBUG(10,("ldap_set_mapping: Successfully created mapping from %s to %d [%s]\n",
		sid_string, ((id_type & ID_USERID) ? id.uid : id.gid), type));

	return NT_STATUS_OK;
}

/***********************************************************************
 This function cannot be called to modify a mapping, only set a new one 
***********************************************************************/

static NTSTATUS ldap_set_mapping(const DOM_SID *sid, unid_t id, int id_type) 
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	char *dn = NULL;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	const char *type;
	const char *obj_class;
	const char *posix_obj_class;
	const char *suffix;
	fstring sid_str;
	fstring id_str;
	pstring filter;
	char **attr_list;
	int rc;
	int count;

	/* try for a samba user or group mapping (looking for an entry with a SID) */
	if ( id_type & ID_USERID ) {
		obj_class = LDAP_OBJ_SAMBASAMACCOUNT;
		suffix = lp_ldap_suffix();
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER );
		posix_obj_class = LDAP_OBJ_POSIXACCOUNT;
		snprintf(id_str, sizeof(id_str), "%u", id.uid );	
	}
	else {
		obj_class = LDAP_OBJ_GROUPMAP;
		suffix = lp_ldap_group_suffix();
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );
		posix_obj_class = LDAP_OBJ_POSIXGROUP;
		snprintf(id_str, sizeof(id_str), "%u", id.gid );	
	}
	
	sid_to_string(sid_str, sid);
	snprintf(filter, sizeof(filter), 
		 "(|"
		 "(&(|(objectClass=%s)(|(objectClass=%s)(objectClass=%s)))(%s=%s))"
		 "(&(objectClass=%s)(%s=%s))"
		 ")", 
		 /* objectClasses that might contain a SID */
		 LDAP_OBJ_SID_ENTRY, LDAP_OBJ_IDMAP_ENTRY, obj_class, 
		 get_attr_key2string( sidmap_attr_list, LDAP_ATTR_SID ), 
		 sid_str, 

		 /* objectClasses that might contain a Unix UID/GID */
		 posix_obj_class, 
		 /* Unix UID/GID specifier*/
		 type, 
		 /* actual ID */
		 id_str);

	attr_list = get_attr_list( sidmap_attr_list );
	rc = smbldap_search(ldap_state.smbldap_state, suffix, LDAP_SCOPE_SUBTREE, 
			    filter, attr_list, 0, &result);
	free_attr_list( attr_list );
	
	if (rc != LDAP_SUCCESS)
		goto out;

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);
	
	/* fall back to looking up an idmap entry if we didn't find anything under the idmap
	   user or group suffix */

	if (count == 1) {
		entry = ldap_first_entry(ldap_state.smbldap_state->ldap_struct, result);
	
		dn = ldap_get_dn(ldap_state.smbldap_state->ldap_struct, result);
		DEBUG(10, ("Found partial mapping entry at dn=%s, looking for %s\n", dn, type));

		ret = ldap_set_mapping_internals(sid, id, id_type, dn, entry);

		goto out;
	} else if (count > 1) {
		DEBUG(0, ("Too many entries trying to find DN to attach ldap \n"));
		goto out;
	}

	ret = ldap_set_mapping_internals(sid, id, id_type, NULL, NULL);

out:
	if (result)
		ldap_msgfree(result);
	if (dn)
		ldap_memfree(dn);
	
	return ret;
}
/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static NTSTATUS ldap_idmap_init( char *params )
{
	fstring filter;
	int rc;
	char **attr_list;
	LDAPMessage *result = NULL;
	LDAPMod **mods = NULL;
	int count;
	NTSTATUS nt_status;

	ldap_state.mem_ctx = talloc_init("idmap_ldap");
	if (!ldap_state.mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* assume location is the only parameter */
	if (!NT_STATUS_IS_OK(nt_status = 
			     smbldap_init(ldap_state.mem_ctx, params, 
					  &ldap_state.smbldap_state))) {
		talloc_destroy(ldap_state.mem_ctx);
		return nt_status;
	}

	/* see if the idmap suffix and sub entries exists */
	
	snprintf( filter, sizeof(filter), "(objectclass=%s)", LDAP_OBJ_IDPOOL );
	
	attr_list = get_attr_list( idpool_attr_list );
	rc = smbldap_search(ldap_state.smbldap_state, lp_ldap_idmap_suffix(), 
		LDAP_SCOPE_SUBTREE, filter, attr_list, 0, &result);
	free_attr_list ( attr_list );

	if (rc != LDAP_SUCCESS)
		return NT_STATUS_UNSUCCESSFUL;

	count = ldap_count_entries(ldap_state.smbldap_state->ldap_struct, result);

	if ( count > 1 ) {
		DEBUG(0,("ldap_idmap_init: multiple entries returned from %s (base == %s)\n",
			filter, lp_ldap_idmap_suffix() ));
		return NT_STATUS_UNSUCCESSFUL;
	}
	else if (count == 0) {
		uid_t	luid, huid;
		gid_t	lgid, hgid;
		fstring uid_str, gid_str;
		
		if ( !lp_idmap_uid(&luid, &huid) || !lp_idmap_gid( &lgid, &hgid ) ) {
			DEBUG(0,("ldap_idmap_init: idmap uid/gid parameters not specified\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		snprintf( uid_str, sizeof(uid_str), "%d", luid );
		snprintf( gid_str, sizeof(gid_str), "%d", lgid );

		smbldap_set_mod( &mods, LDAP_MOD_ADD, "objectClass", LDAP_OBJ_IDPOOL );
		smbldap_set_mod( &mods, LDAP_MOD_ADD, 
			get_attr_key2string(idpool_attr_list, LDAP_ATTR_UIDNUMBER), uid_str );
		smbldap_set_mod( &mods, LDAP_MOD_ADD,
			get_attr_key2string(idpool_attr_list, LDAP_ATTR_GIDNUMBER), gid_str );
		
		rc = smbldap_modify(ldap_state.smbldap_state, lp_ldap_idmap_suffix(), mods);
	}
	
	return NT_STATUS_OK;
}

/*****************************************************************************
 End the LDAP session
*****************************************************************************/

static NTSTATUS ldap_idmap_close(void)
{

	smbldap_free_struct(&(ldap_state).smbldap_state);
	talloc_destroy(ldap_state.mem_ctx);
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	return NT_STATUS_OK;
}


/* This function doesn't make as much sense in an LDAP world since the calling
   node doesn't really control the ID ranges */
static void ldap_idmap_status(void)
{
	DEBUG(0, ("LDAP IDMAP Status not available\n"));
}

static struct idmap_methods ldap_methods = {
	ldap_idmap_init,
	ldap_allocate_id,
	ldap_get_sid_from_id,
	ldap_get_id_from_sid,
	ldap_set_mapping,
	ldap_idmap_close,
	ldap_idmap_status

};

NTSTATUS idmap_ldap_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "ldap", &ldap_methods);
}
