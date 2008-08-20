/* 
   Unix SMB/CIFS mplementation.
   DSDB schema header
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2006-2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2008

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
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "lib/util/dlinklist.h"
#include "param/param.h"


static int schema_set_attributes(struct ldb_context *ldb, struct dsdb_schema *schema)
{
	int ret = LDB_SUCCESS;
	
	struct dsdb_attribute *attr;
	
	for (attr = schema->attributes; attr; attr = attr->next) {
		const struct ldb_schema_syntax *s;
		if (!attr->syntax) {
			continue;
		}
		if (attr->syntax->ldb_syntax) {
			ret = ldb_schema_attribute_add(ldb, attr->lDAPDisplayName, 0,
						       attr->syntax->ldb_syntax);
		} else {
			s = ldb_standard_syntax_by_name(ldb, attr->syntax->ldap_oid);
			if (s) {
				ret = ldb_schema_attribute_add_with_syntax(ldb, attr->lDAPDisplayName, 0, s);
			} else {
				s = ldb_samba_syntax_by_name(ldb, attr->syntax->ldap_oid);
				if (s) {
					ret = ldb_schema_attribute_add_with_syntax(ldb, attr->lDAPDisplayName, 0, s);
				} else {
					ret = LDB_SUCCESS; /* Nothing to do here */
				}
			}
		}
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* Now put back the hardcoded Samba special handlers */
	return ldb_register_samba_handlers(ldb);
}


/**
 * Attach the schema to an opaque pointer on the ldb, so ldb modules
 * can find it 
 */

int dsdb_set_schema(struct ldb_context *ldb, struct dsdb_schema *schema)
{
	int ret;

	ret = ldb_set_opaque(ldb, "dsdb_schema", schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = schema_set_attributes(ldb, schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(ldb, schema);

	return LDB_SUCCESS;
}

/**
 * Global variable to hold one copy of the schema, used to avoid memory bloat
 */
static struct dsdb_schema *global_schema;

/**
 * Make this ldb use the 'global' schema, setup to avoid having multiple copies in this process
 */
int dsdb_set_global_schema(struct ldb_context *ldb)
{
	int ret;
	if (!global_schema) {
		return LDB_SUCCESS;
	}
	ret = ldb_set_opaque(ldb, "dsdb_schema", global_schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = schema_set_attributes(ldb, global_schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Keep a reference to this schema, just incase the global copy is replaced */
	if (talloc_reference(ldb, global_schema) == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

/**
 * Find the schema object for this ldb
 */

struct dsdb_schema *dsdb_get_schema(struct ldb_context *ldb)
{
	const void *p;
	struct dsdb_schema *schema;

	/* see if we have a cached copy */
	p = ldb_get_opaque(ldb, "dsdb_schema");
	if (!p) {
		return NULL;
	}

	schema = talloc_get_type(p, struct dsdb_schema);
	if (!schema) {
		return NULL;
	}

	return schema;
}

/**
 * Make the schema found on this ldb the 'global' schema
 */

void dsdb_make_schema_global(struct ldb_context *ldb)
{
	struct dsdb_schema *schema = dsdb_get_schema(ldb);
	if (!schema) {
		return;
	}

	if (global_schema) {
		talloc_unlink(talloc_autofree_context(), schema);
	}

	talloc_steal(talloc_autofree_context(), schema);
	global_schema = schema;

	dsdb_set_global_schema(ldb);
}


/**
 * Rather than read a schema from the LDB itself, read it from an ldif
 * file.  This allows schema to be loaded and used while adding the
 * schema itself to the directory.
 */

WERROR dsdb_attach_schema_from_ldif_file(struct ldb_context *ldb, const char *pf, const char *df)
{
	struct ldb_ldif *ldif;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	WERROR status;
	int ret;
	struct dsdb_schema *schema;
	const struct ldb_val *prefix_val;
	const struct ldb_val *info_val;
	struct ldb_val info_val_default;

	mem_ctx = talloc_new(ldb);
	if (!mem_ctx) {
		goto nomem;
	}

	schema = dsdb_new_schema(mem_ctx, lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")));

	schema->fsmo.we_are_master = true;
	schema->fsmo.master_dn = ldb_dn_new_fmt(schema, ldb, "@PROVISION_SCHEMA_MASTER");
	if (!schema->fsmo.master_dn) {
		goto nomem;
	}

	/*
	 * load the prefixMap attribute from pf
	 */
	ldif = ldb_ldif_read_string(ldb, &pf);
	if (!ldif) {
		status = WERR_INVALID_PARAM;
		goto failed;
	}
	talloc_steal(mem_ctx, ldif);

	msg = ldb_msg_canonicalize(ldb, ldif->msg);
	if (!msg) {
		goto nomem;
	}
	talloc_steal(mem_ctx, msg);
	talloc_free(ldif);

	prefix_val = ldb_msg_find_ldb_val(msg, "prefixMap");
	if (!prefix_val) {
	    	status = WERR_INVALID_PARAM;
		goto failed;
	}

	info_val = ldb_msg_find_ldb_val(msg, "schemaInfo");
	if (!info_val) {
		info_val_default = strhex_to_data_blob("FF0000000000000000000000000000000000000000");
		if (!info_val_default.data) {
			goto nomem;
		}
		talloc_steal(mem_ctx, info_val_default.data);
		info_val = &info_val_default;
	}

	status = dsdb_load_oid_mappings_ldb(schema, prefix_val, info_val);
	if (!W_ERROR_IS_OK(status)) {
		goto failed;
	}

	/*
	 * load the attribute and class definitions outof df
	 */
	while ((ldif = ldb_ldif_read_string(ldb, &df))) {
		bool is_sa;
		bool is_sc;

		talloc_steal(mem_ctx, ldif);

		msg = ldb_msg_canonicalize(ldb, ldif->msg);
		if (!msg) {
			goto nomem;
		}

		talloc_steal(mem_ctx, msg);
		talloc_free(ldif);

		is_sa = ldb_msg_check_string_attribute(msg, "objectClass", "attributeSchema");
		is_sc = ldb_msg_check_string_attribute(msg, "objectClass", "classSchema");

		if (is_sa) {
			struct dsdb_attribute *sa;

			sa = talloc_zero(schema, struct dsdb_attribute);
			if (!sa) {
				goto nomem;
			}

			status = dsdb_attribute_from_ldb(schema, msg, sa, sa);
			if (!W_ERROR_IS_OK(status)) {
				goto failed;
			}

			DLIST_ADD_END(schema->attributes, sa, struct dsdb_attribute *);
		} else if (is_sc) {
			struct dsdb_class *sc;

			sc = talloc_zero(schema, struct dsdb_class);
			if (!sc) {
				goto nomem;
			}

			status = dsdb_class_from_ldb(schema, msg, sc, sc);
			if (!W_ERROR_IS_OK(status)) {
				goto failed;
			}

			DLIST_ADD_END(schema->classes, sc, struct dsdb_class *);
		}
	}

	ret = dsdb_set_schema(ldb, schema);
	if (ret != LDB_SUCCESS) {
		status = WERR_FOOBAR;
		goto failed;
	}

	goto done;

nomem:
	status = WERR_NOMEM;
failed:
done:
	talloc_free(mem_ctx);
	return status;
}
