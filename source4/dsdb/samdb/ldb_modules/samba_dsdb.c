/*
   Samba4 module loading module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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
 *  Name: ldb
 *
 *  Component: Samba4 module loading module
 *
 *  Description: Implement a single 'module' in the ldb database,
 *  which loads the remaining modules based on 'choice of configuration' attributes
 *
 *  This is to avoid forcing a reprovision of the ldb databases when we change the internal structure of the code
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include <ldb.h>
#include <ldb_errors.h>
#include <ldb_module.h>
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "auth/credentials/credentials.h"
#include "param/secrets.h"
#include "lib/ldb-samba/ldb_wrap.h"

static int read_at_rootdse_record(struct ldb_context *ldb, struct ldb_module *module, TALLOC_CTX *mem_ctx,
				  struct ldb_message **msg, struct ldb_request *parent)
{
	int ret;
	static const char *rootdse_attrs[] = { "defaultNamingContext", "configurationNamingContext", "schemaNamingContext", NULL };
	struct ldb_result *rootdse_res;
	struct ldb_dn *rootdse_dn;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return ldb_oom(ldb);
	}

	rootdse_dn = ldb_dn_new(tmp_ctx, ldb, "@ROOTDSE");
	if (!rootdse_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search_dn(module, tmp_ctx, &rootdse_res, rootdse_dn,
	                            rootdse_attrs, DSDB_FLAG_NEXT_MODULE, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_steal(mem_ctx, rootdse_res->msgs);
	*msg = rootdse_res->msgs[0];

	talloc_free(tmp_ctx);

	return ret;
}

static int prepare_modules_line(struct ldb_context *ldb,
				TALLOC_CTX *mem_ctx,
				const struct ldb_message *rootdse_msg,
				struct ldb_message *msg, const char *backend_attr,
				const char *backend_mod, const char **backend_mod_list)
{
	int ret;
	const char **backend_full_list;
	const char *backend_dn;
	char *mod_list_string;
	char *full_string;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return ldb_oom(ldb);
	}

	if (backend_attr) {
		backend_dn = ldb_msg_find_attr_as_string(rootdse_msg, backend_attr, NULL);
		if (!backend_dn) {
			ldb_asprintf_errstring(ldb,
					       "samba_dsdb_init: "
					       "unable to read %s from %s:%s",
					       backend_attr, ldb_dn_get_linearized(rootdse_msg->dn),
					       ldb_errstring(ldb));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	} else {
		backend_dn = "*";
	}

	if (backend_mod) {
		char **b = str_list_make_single(tmp_ctx, backend_mod);
		backend_full_list = discard_const_p(const char *, b);
	} else {
		char **b = str_list_make_empty(tmp_ctx);
		backend_full_list = discard_const_p(const char *, b);
	}
	if (!backend_full_list) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	backend_full_list = str_list_append_const(backend_full_list, backend_mod_list);
	if (!backend_full_list) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	mod_list_string = str_list_join(tmp_ctx, backend_full_list, ',');

	/* str_list_append allocates on NULL */
	talloc_free(backend_full_list);

	if (!mod_list_string) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	full_string = talloc_asprintf(tmp_ctx, "%s:%s", backend_dn, mod_list_string);
	ret = ldb_msg_add_steal_string(msg, "modules", full_string);
	talloc_free(tmp_ctx);
	return ret;
}

static bool check_required_features(struct ldb_message_element *el)
{
	if (el != NULL) {
		int k;
		DATA_BLOB esf = data_blob_string_const(
			SAMBA_ENCRYPTED_SECRETS_FEATURE);
		DATA_BLOB lmdbl1 = data_blob_string_const(
			SAMBA_LMDB_LEVEL_ONE_FEATURE);
		for (k = 0; k < el->num_values; k++) {
			if ((data_blob_cmp(&esf, &el->values[k]) != 0) &&
			    (data_blob_cmp(&lmdbl1, &el->values[k]) != 0)) {
				return false;
			}
		}
	}
	return true;
}

static int samba_dsdb_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret, lock_ret, len, i, j;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_result *res;
	struct ldb_message *rootdse_msg = NULL, *partition_msg;
	struct ldb_dn *samba_dsdb_dn, *partition_dn, *indexlist_dn;
	struct ldb_module *backend_module, *module_chain;
	const char **final_module_list, **reverse_module_list;
	/*
	  Add modules to the list to activate them by default
	  beware often order is important

	  Some Known ordering constraints:
	  - rootdse must be first, as it makes redirects from "" -> cn=rootdse
	  - extended_dn_in must be before objectclass.c, as it resolves the DN
	  - objectclass must be before password_hash and samldb since these LDB
	    modules require the expanded "objectClass" list
	  - objectclass must be before descriptor and acl, as both assume that
	    objectClass values are sorted
	  - objectclass_attrs must be behind operational in order to see all
	    attributes (the operational module protects and therefore
	    suppresses per default some important ones)
	  - partition must be last
	  - each partition has its own module list then

	  The list is presented here as a set of declarations to show the
	  stack visually - the code below then handles the creation of the list
	  based on the parameters loaded from the database.
	*/
	static const char *modules_list1[] = {"resolve_oids",
					     "rootdse",
					     "dsdb_notification",
					     "schema_load",
					     "lazy_commit",
					     "dirsync",
					     "dsdb_paged_results",
					     "vlv",
					     "ranged_results",
					     "anr",
					     "server_sort",
					     "asq",
					     "extended_dn_store",
					     NULL };
	/* extended_dn_in or extended_dn_in_openldap goes here */
	static const char *modules_list1a[] = {"audit_log",
					     "objectclass",
					     "tombstone_reanimate",
					     "descriptor",
					     "acl",
					     "aclread",
					     "samldb",
					     "password_hash",
					     "instancetype",
					     "objectclass_attrs",
					     NULL };

	const char **link_modules;
	static const char *tdb_modules_list[] = {
		"rdn_name",
		"subtree_delete",
		"repl_meta_data",
		"group_audit_log",
		"encrypted_secrets",
		"operational",
		"unique_object_sids",
		"subtree_rename",
		"linked_attributes",
		NULL};

	const char *extended_dn_module;
	const char *extended_dn_module_ldb = "extended_dn_out_ldb";
	const char *extended_dn_in_module = "extended_dn_in";

	static const char *modules_list2[] = {"dns_notify",
					      "show_deleted",
					      "new_partition",
					      "partition",
					      NULL };

	const char **backend_modules;
	static const char *samba_dsdb_attrs[] = { SAMBA_COMPATIBLE_FEATURES_ATTR,
						  SAMBA_REQUIRED_FEATURES_ATTR, NULL };
	static const char *indexlist_attrs[] = { SAMBA_FEATURES_SUPPORTED_FLAG, NULL };

	const char *current_supportedFeatures[] = {SAMBA_SORTED_LINKS_FEATURE};

	if (!tmp_ctx) {
		return ldb_oom(ldb);
	}

	ret = ldb_register_samba_handlers(ldb);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	samba_dsdb_dn = ldb_dn_new(tmp_ctx, ldb, "@SAMBA_DSDB");
	if (!samba_dsdb_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	indexlist_dn = ldb_dn_new(tmp_ctx, ldb, "@INDEXLIST");
	if (!samba_dsdb_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	partition_dn = ldb_dn_new(tmp_ctx, ldb, DSDB_PARTITION_DN);
	if (!partition_dn) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

#define CHECK_LDB_RET(check_ret)				\
	do {							\
		if (check_ret != LDB_SUCCESS) {			\
			talloc_free(tmp_ctx);			\
			return check_ret;			\
		}						\
	} while (0)

	ret = dsdb_module_search_dn(module, tmp_ctx, &res, samba_dsdb_dn,
	                            samba_dsdb_attrs, DSDB_FLAG_NEXT_MODULE, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* do nothing, a very old db being upgraded */
	} else if (ret == LDB_SUCCESS) {
		struct ldb_message_element *requiredFeatures;
		struct ldb_message_element *old_compatibleFeatures;

		requiredFeatures = ldb_msg_find_element(res->msgs[0], SAMBA_REQUIRED_FEATURES_ATTR);
		if (!check_required_features(requiredFeatures)) {
			ldb_set_errstring(
				ldb,
				"This Samba database was created with "
				"a newer Samba version and is marked "
				"with extra requiredFeatures in "
				"@SAMBA_DSDB. This database can not "
				"safely be read by this Samba version");
			return LDB_ERR_OPERATIONS_ERROR;
		}

		old_compatibleFeatures = ldb_msg_find_element(res->msgs[0],
							      SAMBA_COMPATIBLE_FEATURES_ATTR);

		if (old_compatibleFeatures) {
			struct ldb_message *features_msg;
			struct ldb_message_element *features_el;
			int samba_options_supported = 0;
			ret = dsdb_module_search_dn(module, tmp_ctx, &res,
						    indexlist_dn,
						    indexlist_attrs,
						    DSDB_FLAG_NEXT_MODULE, NULL);
			if (ret == LDB_SUCCESS) {
				samba_options_supported
					= ldb_msg_find_attr_as_int(res->msgs[0],
								   SAMBA_FEATURES_SUPPORTED_FLAG,
								   0);

			} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				/*
				 * If we don't have @INDEXLIST yet, then we
				 * are so early in set-up that we know this is
				 * a blank DB, so no need to wripe out old
				 * features
				 */
				samba_options_supported = 1;
			}

			features_msg = ldb_msg_new(res);
			if (features_msg == NULL) {
				return ldb_module_operr(module);
			}
			features_msg->dn = samba_dsdb_dn;

			ldb_msg_add_empty(features_msg, SAMBA_COMPATIBLE_FEATURES_ATTR,
					  LDB_FLAG_MOD_DELETE, &features_el);

			if (samba_options_supported == 1) {
				for (i = 0;
				     old_compatibleFeatures && i < old_compatibleFeatures->num_values;
				     i++) {
					for (j = 0;
					     j < ARRAY_SIZE(current_supportedFeatures); j++) {
						if (strcmp((char *)old_compatibleFeatures->values[i].data,
							   current_supportedFeatures[j]) == 0) {
							break;
						}
					}
					if (j == ARRAY_SIZE(current_supportedFeatures)) {
						/*
						 * Add to list of features to remove
						 * (rather than all features)
						 */
						ret = ldb_msg_add_value(features_msg, SAMBA_COMPATIBLE_FEATURES_ATTR,
									&old_compatibleFeatures->values[i],
									NULL);
						if (ret != LDB_SUCCESS) {
							return ret;
						}
					}
				}

				if (features_el->num_values > 0) {
					/* Delete by list */
					ret = ldb_next_start_trans(module);
					if (ret != LDB_SUCCESS) {
						return ret;
					}
					ret = dsdb_module_modify(module, features_msg, DSDB_FLAG_NEXT_MODULE, NULL);
					if (ret != LDB_SUCCESS) {
						ldb_next_del_trans(module);
						return ret;
					}
					ret = ldb_next_end_trans(module);
					if (ret != LDB_SUCCESS) {
						return ret;
					}
				}
			} else {
				/* Delete all */
				ret = ldb_next_start_trans(module);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
				ret = dsdb_module_modify(module, features_msg, DSDB_FLAG_NEXT_MODULE, NULL);
				if (ret != LDB_SUCCESS) {
					ldb_next_del_trans(module);
					return ret;
				}
				ret = ldb_next_end_trans(module);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
		}

	} else {
		talloc_free(tmp_ctx);
		return ret;
	}

	backend_modules = NULL;
	extended_dn_module = extended_dn_module_ldb;
	link_modules = tdb_modules_list;

#define CHECK_MODULE_LIST \
	do {							\
		if (!final_module_list) {			\
			talloc_free(tmp_ctx);			\
			return ldb_oom(ldb);			\
		}						\
	} while (0)

	final_module_list = str_list_copy_const(tmp_ctx, modules_list1);
	CHECK_MODULE_LIST;

	final_module_list = str_list_add_const(final_module_list, extended_dn_in_module);
	CHECK_MODULE_LIST;

	final_module_list = str_list_append_const(final_module_list, modules_list1a);
	CHECK_MODULE_LIST;

	final_module_list = str_list_append_const(final_module_list, link_modules);
	CHECK_MODULE_LIST;

	final_module_list = str_list_add_const(final_module_list, extended_dn_module);
	CHECK_MODULE_LIST;

	final_module_list = str_list_append_const(final_module_list, modules_list2);
	CHECK_MODULE_LIST;


	ret = read_at_rootdse_record(ldb, module, tmp_ctx, &rootdse_msg, NULL);
	CHECK_LDB_RET(ret);

	partition_msg = ldb_msg_new(tmp_ctx);
	partition_msg->dn = ldb_dn_new(partition_msg, ldb, "@" DSDB_OPAQUE_PARTITION_MODULE_MSG_OPAQUE_NAME);

	ret = prepare_modules_line(ldb, tmp_ctx,
				   rootdse_msg,
				   partition_msg, "schemaNamingContext",
				   "schema_data", backend_modules);
	CHECK_LDB_RET(ret);

	ret = prepare_modules_line(ldb, tmp_ctx,
				   rootdse_msg,
				   partition_msg, NULL,
				   NULL, backend_modules);
	CHECK_LDB_RET(ret);

	ret = ldb_set_opaque(ldb, DSDB_OPAQUE_PARTITION_MODULE_MSG_OPAQUE_NAME, partition_msg);
	CHECK_LDB_RET(ret);

	talloc_steal(ldb, partition_msg);

	/* Now prepare the module chain. Oddly, we must give it to
	 * ldb_module_load_list in REVERSE */
	for (len = 0; final_module_list[len]; len++) { /* noop */};

	reverse_module_list = talloc_array(tmp_ctx, const char *, len+1);
	if (!reverse_module_list) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}
	for (i=0; i < len; i++) {
		reverse_module_list[i] = final_module_list[(len - 1) - i];
	}
	reverse_module_list[i] = NULL;

	/* The backend (at least until the partitions module
	 * reconfigures things) is the next module in the currently
	 * loaded chain */
	backend_module = ldb_module_next(module);
	ret = ldb_module_load_list(ldb, reverse_module_list, backend_module, &module_chain);
	CHECK_LDB_RET(ret);

	talloc_free(tmp_ctx);
	/* Set this as the 'next' module, so that we effectively append it to
	 * module chain */
	ldb_module_set_next(module, module_chain);

	ret = ldb_next_read_lock(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_next_init(module);

	lock_ret = ldb_next_read_unlock(module);

	if (lock_ret != LDB_SUCCESS) {
		return lock_ret;
	}

	return ret;
}

static const struct ldb_module_ops ldb_samba_dsdb_module_ops = {
	.name		   = "samba_dsdb",
	.init_context	   = samba_dsdb_init,
};

static struct ldb_message *dsdb_flags_ignore_fixup(TALLOC_CTX *mem_ctx,
						const struct ldb_message *_msg)
{
	struct ldb_message *msg = NULL;
	unsigned int i;

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(mem_ctx, _msg);
	if (msg == NULL) {
		return NULL;
	}

	for (i=0; i < msg->num_elements;) {
		struct ldb_message_element *e = &msg->elements[i];

		if (!(e->flags & DSDB_FLAG_INTERNAL_FORCE_META_DATA)) {
			i++;
			continue;
		}

		e->flags &= ~DSDB_FLAG_INTERNAL_FORCE_META_DATA;

		if (e->num_values != 0) {
			i++;
			continue;
		}

		ldb_msg_remove_element(msg, e);
	}

	return msg;
}

static int dsdb_flags_ignore_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *down_req = NULL;
	struct ldb_message *msg = NULL;
	int ret;

	msg = dsdb_flags_ignore_fixup(req, req->op.add.message);
	if (msg == NULL) {
		return ldb_module_oom(module);
	}

	ret = ldb_build_add_req(&down_req, ldb, req,
				msg,
				req->controls,
				req, dsdb_next_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static int dsdb_flags_ignore_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *down_req = NULL;
	struct ldb_message *msg = NULL;
	int ret;

	msg = dsdb_flags_ignore_fixup(req, req->op.mod.message);
	if (msg == NULL) {
		return ldb_module_oom(module);
	}

	ret = ldb_build_mod_req(&down_req, ldb, req,
				msg,
				req->controls,
				req, dsdb_next_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static const struct ldb_module_ops ldb_dsdb_flags_ignore_module_ops = {
	.name   = "dsdb_flags_ignore",
	.add    = dsdb_flags_ignore_add,
	.modify = dsdb_flags_ignore_modify,
};

int ldb_samba_dsdb_module_init(const char *version)
{
	int ret;
	LDB_MODULE_CHECK_VERSION(version);
	ret = ldb_register_module(&ldb_samba_dsdb_module_ops);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = ldb_register_module(&ldb_dsdb_flags_ignore_module_ops);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return LDB_SUCCESS;
}
