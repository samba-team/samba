/*
   Unix SMB/CIFS implementation.

   idmap LDAP backend

   Copyright (C) Tim Potter 		2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com>	2003
   Copyright (C) Gerald Carter 		2003
   Copyright (C) Simo Sorce 		2003-2007
   Copyright (C) Michael Adam		2010

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

#include "includes.h"
#include "winbindd.h"
#include "secrets.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "../libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

#include <lber.h>
#include <ldap.h>

#include "smbldap.h"
#include "passdb/pdb_ldap_schema.h"

struct idmap_ldap_context {
	struct smbldap_state *smbldap_state;
	char *url;
	char *suffix;
	char *user_dn;
	bool anon;
	struct idmap_rw_ops *rw_ops;
};

#define CHECK_ALLOC_DONE(mem) do { \
	if (!mem) { \
		DEBUG(0, ("Out of memory!\n")); \
		ret = NT_STATUS_NO_MEMORY; \
		goto done; \
	} } while (0)

/**********************************************************************
 IDMAP ALLOC TDB BACKEND
**********************************************************************/

/*********************************************************************
 ********************************************************************/

static NTSTATUS get_credentials( TALLOC_CTX *mem_ctx,
				 struct smbldap_state *ldap_state,
				 struct idmap_domain *dom,
				 char **dn )
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	char *secret = NULL;
	const char *tmp = NULL;
	char *user_dn = NULL;
	bool anon = False;

	/* assume anonymous if we don't have a specified user */

	tmp = idmap_config_const_string(dom->name, "ldap_user_dn", NULL);

	if ( tmp ) {
		secret = idmap_fetch_secret("ldap", dom->name, tmp);
		if (!secret) {
			DEBUG(0, ("get_credentials: Unable to fetch "
				  "auth credentials for %s in %s\n",
				  tmp, (dom==NULL)?"ALLOC":dom->name));
			ret = NT_STATUS_ACCESS_DENIED;
			goto done;
		}
		*dn = talloc_strdup(mem_ctx, tmp);
		CHECK_ALLOC_DONE(*dn);
	} else {
		if (!fetch_ldap_pw(&user_dn, &secret)) {
			DEBUG(2, ("get_credentials: Failed to lookup ldap "
				  "bind creds. Using anonymous connection.\n"));
			anon = True;
			*dn = NULL;
		} else {
			*dn = talloc_strdup(mem_ctx, user_dn);
			SAFE_FREE( user_dn );
			CHECK_ALLOC_DONE(*dn);
		}
	}

	smbldap_set_creds(ldap_state, anon, *dn, secret);
	ret = NT_STATUS_OK;

done:
	SAFE_FREE(secret);

	return ret;
}


/**********************************************************************
 Verify the sambaUnixIdPool entry in the directory.
**********************************************************************/

static NTSTATUS verify_idpool(struct idmap_domain *dom)
{
	NTSTATUS ret;
	TALLOC_CTX *mem_ctx;
	LDAPMessage *result = NULL;
	LDAPMod **mods = NULL;
	const char **attr_list;
	char *filter;
	int count;
	int rc;
	struct idmap_ldap_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	mem_ctx = talloc_new(ctx);
	if (mem_ctx == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	filter = talloc_asprintf(mem_ctx, "(objectclass=%s)", LDAP_OBJ_IDPOOL);
	CHECK_ALLOC_DONE(filter);

	attr_list = get_attr_list(mem_ctx, idpool_attr_list);
	CHECK_ALLOC_DONE(attr_list);

	rc = smbldap_search(ctx->smbldap_state,
				ctx->suffix,
				LDAP_SCOPE_SUBTREE,
				filter,
				attr_list,
				0,
				&result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(1, ("Unable to verify the idpool, "
			  "cannot continue initialization!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	count = ldap_count_entries(smbldap_get_ldap(ctx->smbldap_state),
				   result);

	ldap_msgfree(result);

	if ( count > 1 ) {
		DEBUG(0,("Multiple entries returned from %s (base == %s)\n",
			filter, ctx->suffix));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	else if (count == 0) {
		char *uid_str, *gid_str;

		uid_str = talloc_asprintf(mem_ctx, "%lu",
				(unsigned long)dom->low_id);
		gid_str = talloc_asprintf(mem_ctx, "%lu",
				(unsigned long)dom->low_id);

		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				"objectClass", LDAP_OBJ_IDPOOL);
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				get_attr_key2string(idpool_attr_list,
						    LDAP_ATTR_UIDNUMBER),
				uid_str);
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				get_attr_key2string(idpool_attr_list,
						    LDAP_ATTR_GIDNUMBER),
				gid_str);
		if (mods) {
			rc = smbldap_modify(ctx->smbldap_state,
						ctx->suffix,
						mods);
			ldap_mods_free(mods, True);
		} else {
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	ret = (rc == LDAP_SUCCESS)?NT_STATUS_OK:NT_STATUS_UNSUCCESSFUL;
done:
	talloc_free(mem_ctx);
	return ret;
}

/********************************
 Allocate a new uid or gid
********************************/

static NTSTATUS idmap_ldap_allocate_id_internal(struct idmap_domain *dom,
						struct unixid *xid)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	int rc = LDAP_SERVER_DOWN;
	int count = 0;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	LDAPMod **mods = NULL;
	char *id_str;
	char *new_id_str;
	char *filter = NULL;
	const char *dn = NULL;
	const char **attr_list;
	const char *type;
	struct idmap_ldap_context *ctx;
	int error = 0;

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	mem_ctx = talloc_new(ctx);
	if (!mem_ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* get type */
	switch (xid->type) {

	case ID_TYPE_UID:
		type = get_attr_key2string(idpool_attr_list,
					   LDAP_ATTR_UIDNUMBER);
	       	break;

	case ID_TYPE_GID:
		type = get_attr_key2string(idpool_attr_list,
					   LDAP_ATTR_GIDNUMBER);
		break;

	case ID_TYPE_BOTH:
		/*
		 * This is not supported here yet and
		 * already handled in idmap_rw_new_mapping()
		 */
		FALL_THROUGH;
	case ID_TYPE_NOT_SPECIFIED:
		/*
		 * This is handled in idmap_rw_new_mapping()
		 */
		FALL_THROUGH;
	default:
		DEBUG(2, ("Invalid ID type (0x%x)\n", xid->type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	filter = talloc_asprintf(mem_ctx, "(objectClass=%s)", LDAP_OBJ_IDPOOL);
	CHECK_ALLOC_DONE(filter);

	attr_list = get_attr_list(mem_ctx, idpool_attr_list);
	CHECK_ALLOC_DONE(attr_list);

	DEBUG(10, ("Search of the id pool (filter: %s)\n", filter));

	rc = smbldap_search(ctx->smbldap_state,
			   ctx->suffix,
			   LDAP_SCOPE_SUBTREE, filter,
			   attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("%s object not found\n", LDAP_OBJ_IDPOOL));
		goto done;
	}

	smbldap_talloc_autofree_ldapmsg(mem_ctx, result);

	count = ldap_count_entries(smbldap_get_ldap(ctx->smbldap_state),
				   result);
	if (count != 1) {
		DEBUG(0,("Single %s object not found\n", LDAP_OBJ_IDPOOL));
		goto done;
	}

	entry = ldap_first_entry(smbldap_get_ldap(ctx->smbldap_state), result);

	dn = smbldap_talloc_dn(mem_ctx,
			       smbldap_get_ldap(ctx->smbldap_state),
			       entry);
	if ( ! dn) {
		goto done;
	}

	id_str = smbldap_talloc_single_attribute(
				smbldap_get_ldap(ctx->smbldap_state),
				entry, type, mem_ctx);
	if (id_str == NULL) {
		DEBUG(0,("%s attribute not found\n", type));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	xid->id = smb_strtoul(id_str, NULL, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* make sure we still have room to grow */

	switch (xid->type) {
	case ID_TYPE_UID:
		if (xid->id > dom->high_id) {
			DEBUG(0,("Cannot allocate uid above %lu!\n",
				 (unsigned long)dom->high_id));
			goto done;
		}
		break;

	case ID_TYPE_GID:
		if (xid->id > dom->high_id) {
			DEBUG(0,("Cannot allocate gid above %lu!\n",
				 (unsigned long)dom->high_id));
			goto done;
		}
		break;

	default:
		/* impossible */
		goto done;
	}

	new_id_str = talloc_asprintf(mem_ctx, "%lu", (unsigned long)xid->id + 1);
	if ( ! new_id_str) {
		DEBUG(0,("Out of memory\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	smbldap_set_mod(&mods, LDAP_MOD_DELETE, type, id_str);
	smbldap_set_mod(&mods, LDAP_MOD_ADD, type, new_id_str);

	if (mods == NULL) {
		DEBUG(0,("smbldap_set_mod() failed.\n"));
		goto done;
	}

	DEBUG(10, ("Try to atomically increment the id (%s -> %s)\n",
		   id_str, new_id_str));

	rc = smbldap_modify(ctx->smbldap_state, dn, mods);

	ldap_mods_free(mods, True);

	if (rc != LDAP_SUCCESS) {
		DEBUG(1,("Failed to allocate new %s. "
			 "smbldap_modify() failed.\n", type));
		goto done;
	}

	ret = NT_STATUS_OK;

done:
	talloc_free(mem_ctx);
	return ret;
}

/**
 * Allocate a new unix-ID.
 * For now this is for the default idmap domain only.
 * Should be extended later on.
 */
static NTSTATUS idmap_ldap_allocate_id(struct idmap_domain *dom,
				       struct unixid *id)
{
	NTSTATUS ret;

	if (!strequal(dom->name, "*")) {
		DEBUG(3, ("idmap_ldap_allocate_id: "
			  "Refusing allocation of a new unixid for domain'%s'. "
			  "This is only supported for the default "
			  "domain \"*\".\n",
			   dom->name));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ret = idmap_ldap_allocate_id_internal(dom, id);

	return ret;
}


/**********************************************************************
 IDMAP MAPPING LDAP BACKEND
**********************************************************************/

static int idmap_ldap_close_destructor(struct idmap_ldap_context *ctx)
{
	smbldap_free_struct(&ctx->smbldap_state);
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */

	return 0;
}

/********************************
 Initialise idmap database.
********************************/

static NTSTATUS idmap_ldap_set_mapping(struct idmap_domain *dom,
				       const struct id_map *map);

static NTSTATUS idmap_ldap_db_init(struct idmap_domain *dom)
{
	NTSTATUS ret;
	struct idmap_ldap_context *ctx = NULL;
	const char *tmp = NULL;

	/* Only do init if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_zero(dom, struct idmap_ldap_context);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	tmp = idmap_config_const_string(dom->name, "ldap_url", NULL);

	if ( ! tmp) {
		DEBUG(1, ("ERROR: missing idmap ldap url\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ctx->url = talloc_strdup(ctx, tmp);

	trim_char(ctx->url, '\"', '\"');

	tmp = idmap_config_const_string(dom->name, "ldap_base_dn", NULL);
	if ( ! tmp || ! *tmp) {
		tmp = lp_ldap_idmap_suffix(talloc_tos());
		if ( ! tmp) {
			DEBUG(1, ("ERROR: missing idmap ldap suffix\n"));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	ctx->suffix = talloc_strdup(ctx, tmp);
	CHECK_ALLOC_DONE(ctx->suffix);

	ctx->rw_ops = talloc_zero(ctx, struct idmap_rw_ops);
	CHECK_ALLOC_DONE(ctx->rw_ops);

	ctx->rw_ops->get_new_id = idmap_ldap_allocate_id_internal;
	ctx->rw_ops->set_mapping = idmap_ldap_set_mapping;

	/* get_credentials deals with setting up creds */

	ret = smbldap_init(ctx, global_event_context(), ctx->url,
			   false, NULL, NULL, &ctx->smbldap_state);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("ERROR: smbldap_init (%s) failed!\n", ctx->url));
		goto done;
	}

	ret = get_credentials( ctx, ctx->smbldap_state,
			       dom, &ctx->user_dn );
	if ( !NT_STATUS_IS_OK(ret) ) {
		DEBUG(1,("idmap_ldap_db_init: Failed to get connection "
			 "credentials (%s)\n", nt_errstr(ret)));
		goto done;
	}

	/*
	 * Set the destructor on the context, so that resources are
	 * properly freed when the context is released.
	 */
	talloc_set_destructor(ctx, idmap_ldap_close_destructor);

	dom->private_data = ctx;

	ret = verify_idpool(dom);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("idmap_ldap_db_init: failed to verify ID pool (%s)\n",
			 nt_errstr(ret)));
		goto done;
	}

	return NT_STATUS_OK;

/*failed */
done:
	talloc_free(ctx);
	return ret;
}

/**
 * set a mapping.
 */

/* TODO: change this:  This function cannot be called to modify a mapping,
 * only set a new one */

static NTSTATUS idmap_ldap_set_mapping(struct idmap_domain *dom,
				       const struct id_map *map)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ldap_context *ctx;
	LDAPMessage *entry = NULL;
	LDAPMod **mods = NULL;
	const char *type;
	char *id_str;
	struct dom_sid_buf sid;
	char *dn;
	int rc = -1;

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	switch(map->xid.type) {
	case ID_TYPE_UID:
		type = get_attr_key2string(sidmap_attr_list,
					   LDAP_ATTR_UIDNUMBER);
		break;

	case ID_TYPE_GID:
		type = get_attr_key2string(sidmap_attr_list,
					   LDAP_ATTR_GIDNUMBER);
		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	memctx = talloc_new(ctx);
	if ( ! memctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	id_str = talloc_asprintf(memctx, "%lu", (unsigned long)map->xid.id);
	CHECK_ALLOC_DONE(id_str);

	dn = talloc_asprintf(memctx, "%s=%s,%s",
			get_attr_key2string(sidmap_attr_list, LDAP_ATTR_SID),
			dom_sid_str_buf(map->sid, &sid),
			ctx->suffix);
	CHECK_ALLOC_DONE(dn);

	smbldap_set_mod(&mods, LDAP_MOD_ADD,
			"objectClass", LDAP_OBJ_IDMAP_ENTRY);

	smbldap_make_mod(smbldap_get_ldap(ctx->smbldap_state),
			 entry, &mods, type, id_str);

	smbldap_make_mod(smbldap_get_ldap(ctx->smbldap_state), entry, &mods,
			 get_attr_key2string(sidmap_attr_list, LDAP_ATTR_SID),
			 sid.buf);

	if ( ! mods) {
		DEBUG(2, ("ERROR: No mods?\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* TODO: remove conflicting mappings! */

	smbldap_set_mod(&mods, LDAP_MOD_ADD, "objectClass", LDAP_OBJ_SID_ENTRY);

	DEBUG(10, ("Set DN %s (%s -> %s)\n", dn, sid.buf, id_str));

	rc = smbldap_add(ctx->smbldap_state, dn, mods);
	ldap_mods_free(mods, True);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(smbldap_get_ldap(ctx->smbldap_state),
				LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(0,("ldap_set_mapping_internals: Failed to add %s to %lu "
			 "mapping [%s]\n", sid.buf,
			 (unsigned long)map->xid.id, type));
		DEBUG(0, ("ldap_set_mapping_internals: Error was: %s (%s)\n",
			ld_error ? ld_error : "(NULL)", ldap_err2string (rc)));
		if (ld_error) {
			ldap_memfree(ld_error);
		}
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	DEBUG(10,("ldap_set_mapping: Successfully created mapping from %s to "
		  "%lu [%s]\n",	sid.buf, (unsigned long)map->xid.id, type));

	ret = NT_STATUS_OK;

done:
	talloc_free(memctx);
	return ret;
}

/**
 * Create a new mapping for an unmapped SID, also allocating a new ID.
 * If possible, this should be run inside a transaction to make the
 * action atomic.
 */
static NTSTATUS idmap_ldap_new_mapping(struct idmap_domain *dom, struct id_map *map)
{
	NTSTATUS ret;
	struct idmap_ldap_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	ret = idmap_rw_new_mapping(dom, ctx->rw_ops, map);

	return ret;
}

/**********************************
 lookup a set of unix ids.
**********************************/

static NTSTATUS idmap_ldap_unixids_to_sids(struct idmap_domain *dom,
					   struct id_map **ids)
{
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ldap_context *ctx;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	const char *uidNumber;
	const char *gidNumber;
	const char **attr_list;
	char *filter = NULL;
	bool multi = False;
	int idx = 0;
	int bidx = 0;
	int count;
	int rc;
	int i;
	int error = 0;

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	memctx = talloc_new(ctx);
	if ( ! memctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	uidNumber = get_attr_key2string(idpool_attr_list, LDAP_ATTR_UIDNUMBER);
	gidNumber = get_attr_key2string(idpool_attr_list, LDAP_ATTR_GIDNUMBER);

	attr_list = get_attr_list(memctx, sidmap_attr_list);

	if ( ! ids[1]) {
		/* if we are requested just one mapping use the simple filter */

		filter = talloc_asprintf(memctx, "(&(objectClass=%s)(%s=%lu))",
				LDAP_OBJ_IDMAP_ENTRY,
				(ids[0]->xid.type==ID_TYPE_UID)?uidNumber:gidNumber,
				(unsigned long)ids[0]->xid.id);
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		/* multiple mappings */
		multi = True;
	}

	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

again:
	if (multi) {

		talloc_free(filter);
		filter = talloc_asprintf(memctx,
					 "(&(objectClass=%s)(|",
					 LDAP_OBJ_IDMAP_ENTRY);
		CHECK_ALLOC_DONE(filter);

		bidx = idx;
		for (i = 0; (i < IDMAP_LDAP_MAX_IDS) && ids[idx]; i++, idx++) {
			filter = talloc_asprintf_append_buffer(filter, "(%s=%lu)",
					(ids[idx]->xid.type==ID_TYPE_UID)?uidNumber:gidNumber,
					(unsigned long)ids[idx]->xid.id);
			CHECK_ALLOC_DONE(filter);
		}
		filter = talloc_asprintf_append_buffer(filter, "))");
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		bidx = 0;
		idx = 1;
	}

	rc = smbldap_search(ctx->smbldap_state, ctx->suffix, LDAP_SCOPE_SUBTREE,
		filter, attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(3,("Failure looking up ids (%s)\n", ldap_err2string(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	count = ldap_count_entries(smbldap_get_ldap(ctx->smbldap_state),
				   result);

	if (count == 0) {
		DEBUG(10, ("NO SIDs found\n"));
	}

	for (i = 0; i < count; i++) {
		char *sidstr = NULL;
		char *tmp = NULL;
		enum id_type type;
		struct id_map *map;
		uint32_t id;
		struct dom_sid_buf buf;

		if (i == 0) { /* first entry */
			entry = ldap_first_entry(
				smbldap_get_ldap(ctx->smbldap_state), result);
		} else { /* following ones */
			entry = ldap_next_entry(
				smbldap_get_ldap(ctx->smbldap_state), entry);
		}
		if ( ! entry) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries "
				  "from results\n"));
			break;
		}

		/* first check if the SID is present */
		sidstr = smbldap_talloc_single_attribute(
				smbldap_get_ldap(ctx->smbldap_state),
				entry, LDAP_ATTRIBUTE_SID, memctx);
		if ( ! sidstr) { /* no sid, skip entry */
			DEBUG(2, ("WARNING SID not found on entry\n"));
			continue;
		}

		/* now try to see if it is a uid, if not try with a gid
		 * (gid is more common, but in case both uidNumber and
		 * gidNumber are returned the SID is mapped to the uid
		 *not the gid) */
		type = ID_TYPE_UID;
		tmp = smbldap_talloc_single_attribute(
				smbldap_get_ldap(ctx->smbldap_state),
				entry, uidNumber, memctx);
		if ( ! tmp) {
			type = ID_TYPE_GID;
			tmp = smbldap_talloc_single_attribute(
					smbldap_get_ldap(ctx->smbldap_state),
					entry, gidNumber, memctx);
		}
		if ( ! tmp) { /* wow very strange entry, how did it match ? */
			DEBUG(5, ("Unprobable match on (%s), no uidNumber, "
				  "nor gidNumber returned\n", sidstr));
			TALLOC_FREE(sidstr);
			continue;
		}

		id = smb_strtoul(tmp, NULL, 10, &error, SMB_STR_STANDARD);
		TALLOC_FREE(tmp);
		if (error != 0) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). "
				  "Filtered!\n", id,
				  dom->low_id, dom->high_id));
			TALLOC_FREE(sidstr);
			continue;
		}

		if (!idmap_unix_id_is_in_range(id, dom)) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). "
				  "Filtered!\n", id,
				  dom->low_id, dom->high_id));
			TALLOC_FREE(sidstr);
			continue;
		}

		map = idmap_find_map_by_id(&ids[bidx], type, id);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't match sid (%s) "
				  "with requested ids\n", sidstr));
			TALLOC_FREE(sidstr);
			continue;
		}

		if ( ! string_to_sid(map->sid, sidstr)) {
			DEBUG(2, ("ERROR: Invalid SID on entry\n"));
			TALLOC_FREE(sidstr);
			continue;
		}

		if (map->status == ID_MAPPED) {
			DEBUG(1, ("WARNING: duplicate %s mapping in LDAP. "
			      "overwriting mapping %u -> %s with %u -> %s\n",
			      (type == ID_TYPE_UID) ? "UID" : "GID",
			      id,
			      dom_sid_str_buf(map->sid, &buf),
			      id,
			      sidstr));
		}

		TALLOC_FREE(sidstr);

		/* mapped */
		map->status = ID_MAPPED;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n",
			   dom_sid_str_buf(map->sid, &buf),
			   (unsigned long)map->xid.id, map->xid.type));
	}

	/* free the ldap results */
	if (result) {
		ldap_msgfree(result);
		result = NULL;
	}

	if (multi && ids[idx]) { /* still some values to map */
		goto again;
	}

	ret = NT_STATUS_OK;

	/* mark all unknwon/expired ones as unmapped */
	for (i = 0; ids[i]; i++) {
		if (ids[i]->status != ID_MAPPED)
			ids[i]->status = ID_UNMAPPED;
	}

done:
	talloc_free(memctx);
	return ret;
}

/**********************************
 lookup a set of sids.
**********************************/

static NTSTATUS idmap_ldap_sids_to_unixids(struct idmap_domain *dom,
					   struct id_map **ids)
{
	LDAPMessage *entry = NULL;
	NTSTATUS ret;
	TALLOC_CTX *memctx;
	struct idmap_ldap_context *ctx;
	LDAPMessage *result = NULL;
	const char *uidNumber;
	const char *gidNumber;
	const char **attr_list;
	char *filter = NULL;
	bool multi = False;
	size_t num_required = 0;
	int idx = 0;
	int bidx = 0;
	int count;
	int rc;
	int i;

	/* Only do query if we are online */
	if (idmap_is_offline())	{
		return NT_STATUS_FILE_IS_OFFLINE;
	}

	ctx = talloc_get_type(dom->private_data, struct idmap_ldap_context);

	memctx = talloc_new(ctx);
	if ( ! memctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	uidNumber = get_attr_key2string(idpool_attr_list, LDAP_ATTR_UIDNUMBER);
	gidNumber = get_attr_key2string(idpool_attr_list, LDAP_ATTR_GIDNUMBER);

	attr_list = get_attr_list(memctx, sidmap_attr_list);

	if ( ! ids[1]) {
		struct dom_sid_buf buf;
		/* if we are requested just one mapping use the simple filter */

		filter = talloc_asprintf(memctx, "(&(objectClass=%s)(%s=%s))",
				LDAP_OBJ_IDMAP_ENTRY,
				LDAP_ATTRIBUTE_SID,
				dom_sid_str_buf(ids[0]->sid, &buf));
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]\n", filter));
	} else {
		/* multiple mappings */
		multi = True;
	}

	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

again:
	if (multi) {

		TALLOC_FREE(filter);
		filter = talloc_asprintf(memctx,
					 "(&(objectClass=%s)(|",
					 LDAP_OBJ_IDMAP_ENTRY);
		CHECK_ALLOC_DONE(filter);

		bidx = idx;
		for (i = 0; (i < IDMAP_LDAP_MAX_IDS) && ids[idx]; i++, idx++) {
			struct dom_sid_buf buf;
			filter = talloc_asprintf_append_buffer(filter, "(%s=%s)",
					LDAP_ATTRIBUTE_SID,
					dom_sid_str_buf(ids[idx]->sid, &buf));
			CHECK_ALLOC_DONE(filter);
		}
		filter = talloc_asprintf_append_buffer(filter, "))");
		CHECK_ALLOC_DONE(filter);
		DEBUG(10, ("Filter: [%s]", filter));
	} else {
		bidx = 0;
		idx = 1;
	}

	rc = smbldap_search(ctx->smbldap_state, ctx->suffix, LDAP_SCOPE_SUBTREE,
		filter, attr_list, 0, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(3,("Failure looking up sids (%s)\n",
			 ldap_err2string(rc)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	count = ldap_count_entries(smbldap_get_ldap(ctx->smbldap_state),
				   result);

	if (count == 0) {
		DEBUG(10, ("NO SIDs found\n"));
	}

	for (i = 0; i < count; i++) {
		char *sidstr = NULL;
		char *tmp = NULL;
		enum id_type type;
		struct id_map *map;
		struct dom_sid sid;
		struct dom_sid_buf buf;
		uint32_t id;
		int error = 0;

		if (i == 0) { /* first entry */
			entry = ldap_first_entry(
				smbldap_get_ldap(ctx->smbldap_state), result);
		} else { /* following ones */
			entry = ldap_next_entry(
				smbldap_get_ldap(ctx->smbldap_state), entry);
		}
		if ( ! entry) {
			DEBUG(2, ("ERROR: Unable to fetch ldap entries "
				  "from results\n"));
			break;
		}

		/* first check if the SID is present */
		sidstr = smbldap_talloc_single_attribute(
				smbldap_get_ldap(ctx->smbldap_state),
				entry, LDAP_ATTRIBUTE_SID, memctx);
		if ( ! sidstr) { /* no sid ??, skip entry */
			DEBUG(2, ("WARNING SID not found on entry\n"));
			continue;
		}

		if ( ! string_to_sid(&sid, sidstr)) {
			DEBUG(2, ("ERROR: Invalid SID on entry\n"));
			TALLOC_FREE(sidstr);
			continue;
		}

		map = idmap_find_map_by_sid(&ids[bidx], &sid);
		if (!map) {
			DEBUG(2, ("WARNING: couldn't find entry sid (%s) "
				  "in ids", sidstr));
			TALLOC_FREE(sidstr);
			continue;
		}

		/* now try to see if it is a uid, if not try with a gid
		 * (gid is more common, but in case both uidNumber and
		 * gidNumber are returned the SID is mapped to the uid
		 * not the gid) */
		type = ID_TYPE_UID;
		tmp = smbldap_talloc_single_attribute(
				smbldap_get_ldap(ctx->smbldap_state),
				entry, uidNumber, memctx);
		if ( ! tmp) {
			type = ID_TYPE_GID;
			tmp = smbldap_talloc_single_attribute(
					smbldap_get_ldap(ctx->smbldap_state),
					entry, gidNumber, memctx);
		}
		if ( ! tmp) { /* no ids ?? */
			DEBUG(5, ("no uidNumber, "
				  "nor gidNumber attributes found\n"));
			TALLOC_FREE(sidstr);
			continue;
		}

		id = smb_strtoul(tmp, NULL, 10, &error, SMB_STR_STANDARD);
		TALLOC_FREE(tmp);
		if (error != 0) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). "
				  "Filtered!\n", id,
				  dom->low_id, dom->high_id));
			TALLOC_FREE(sidstr);
			continue;
		}

		if (error != 0 || !idmap_unix_id_is_in_range(id, dom)) {
			DEBUG(5, ("Requested id (%u) out of range (%u - %u). "
				  "Filtered!\n", id,
				  dom->low_id, dom->high_id));
			TALLOC_FREE(sidstr);
			continue;
		}

		if (map->status == ID_MAPPED) {
			DEBUG(1, ("WARNING: duplicate %s mapping in LDAP. "
			      "overwriting mapping %s -> %u with %s -> %u\n",
			      (type == ID_TYPE_UID) ? "UID" : "GID",
			      sidstr, map->xid.id, sidstr, id));
		}

		TALLOC_FREE(sidstr);

		/* mapped */
		map->xid.type = type;
		map->xid.id = id;
		map->status = ID_MAPPED;

		DEBUG(10, ("Mapped %s -> %lu (%d)\n",
			   dom_sid_str_buf(map->sid, &buf),
			   (unsigned long)map->xid.id,
			   map->xid.type));
	}

	/* free the ldap results */
	if (result) {
		ldap_msgfree(result);
		result = NULL;
	}

	if (multi && ids[idx]) { /* still some values to map */
		goto again;
	}

	/*
	 *  try to create new mappings for unmapped sids
	 */
	for (i = 0; ids[i]; i++) {
		if (ids[i]->status != ID_MAPPED) {
			ids[i]->status = ID_UNMAPPED;
			if (ids[i]->sid != NULL) {
				ret = idmap_ldap_new_mapping(dom, ids[i]);
				DBG_DEBUG("idmap_ldap_new_mapping returned %s\n",
					  nt_errstr(ret));
				if (NT_STATUS_EQUAL(ret, STATUS_SOME_UNMAPPED)) {
					if (ids[i]->status == ID_REQUIRE_TYPE) {
						num_required += 1;
						continue;
					}
				}
				if (!NT_STATUS_IS_OK(ret)) {
					/*
					 * If we can't create
					 * a new mapping it's unlikely
					 * that it will work for the
					 * next entry.
					 */
					goto done;
				}
			}
		}
	}

	ret = NT_STATUS_OK;
	if (num_required > 0) {
		ret = STATUS_SOME_UNMAPPED;
	}

done:
	talloc_free(memctx);
	return ret;
}

/**********************************
 Close the idmap ldap instance
**********************************/

static const struct idmap_methods idmap_ldap_methods = {

	.init = idmap_ldap_db_init,
	.unixids_to_sids = idmap_ldap_unixids_to_sids,
	.sids_to_unixids = idmap_ldap_sids_to_unixids,
	.allocate_id = idmap_ldap_allocate_id,
};

NTSTATUS idmap_ldap_init(TALLOC_CTX *);
NTSTATUS idmap_ldap_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "ldap",
				  &idmap_ldap_methods);
}

