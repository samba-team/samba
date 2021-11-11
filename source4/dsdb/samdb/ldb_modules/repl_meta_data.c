/*
   ldb database library

   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2013
   Copyright (C) Andrew Tridgell 2005-2009
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Matthieu Patou <mat@samba.org> 2010-2011

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
 *  Component: ldb repl_meta_data module
 *
 *  Description: - add a unique objectGUID onto every new record,
 *               - handle whenCreated, whenChanged timestamps
 *               - handle uSNCreated, uSNChanged numbers
 *               - handle replPropertyMetaData attribute
 *
 *  Author: Simo Sorce
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/proto.h"
#include "dsdb/common/util.h"
#include "../libds/common/flags.h"
#include "librpc/gen_ndr/irpc.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "libcli/security/security.h"
#include "lib/util/dlinklist.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/util/tsort.h"
#include "lib/util/binsearch.h"

#undef DBGC_CLASS
#define DBGC_CLASS            DBGC_DRS_REPL

/* the RMD_VERSION for linked attributes starts from 1 */
#define RMD_VERSION_INITIAL   1

/*
 * It's 29/12/9999 at 23:59:59 UTC as specified in MS-ADTS 7.1.1.4.2
 * Deleted Objects Container
 */
static const NTTIME DELETED_OBJECT_CONTAINER_CHANGE_TIME = 2650466015990000000ULL;

struct replmd_private {
	TALLOC_CTX *la_ctx;
	struct la_group *la_list;
	struct nc_entry {
		struct nc_entry *prev, *next;
		struct ldb_dn *dn;
		uint64_t mod_usn;
		uint64_t mod_usn_urgent;
	} *ncs;
	struct ldb_dn *schema_dn;
	bool originating_updates;
	bool sorted_links;
	uint32_t total_links;
	uint32_t num_processed;
	bool recyclebin_enabled;
	bool recyclebin_state_known;
};

/*
 * groups link attributes together by source-object and attribute-ID,
 * to improve processing efficiency (i.e. for 'member' attribute, which
 * could have 100s or 1000s of links).
 * Note this grouping is best effort - the same source object could still
 * correspond to several la_groups (a lot depends on the order DRS sends
 * the links in). The groups currently don't span replication chunks (which
 * caps the size to ~1500 links by default).
 */
struct la_group {
	struct la_group *next, *prev;
	struct la_entry *la_entries;
};

struct la_entry {
	struct la_entry *next, *prev;
	struct drsuapi_DsReplicaLinkedAttribute *la;
	uint32_t dsdb_repl_flags;
};

struct replmd_replicated_request {
	struct ldb_module *module;
	struct ldb_request *req;

	const struct dsdb_schema *schema;
	struct GUID our_invocation_id;

	/* the controls we pass down */
	struct ldb_control **controls;

	/*
	 * Backlinks for the replmd_add() case (we want to create
	 * backlinks after creating the user, but before the end of
	 * the ADD request) 
	 */
	struct la_backlink *la_backlinks;

	/* details for the mode where we apply a bunch of inbound replication meessages */
	bool apply_mode;
	uint32_t index_current;
	struct dsdb_extended_replicated_objects *objs;

	struct ldb_message *search_msg;
	struct GUID local_parent_guid;

	uint64_t seq_num;
	bool is_urgent;

	bool isDeleted;

	bool fix_link_sid;
};

/*
 * the result of replmd_process_linked_attribute(): either there was no change
 * (update was ignored), a new link was added (either inactive or active), or
 * an existing link was modified (active/inactive status may have changed).
 */
typedef enum {
	LINK_CHANGE_NONE,
	LINK_CHANGE_ADDED,
	LINK_CHANGE_MODIFIED,
} replmd_link_changed;

static int replmd_replicated_apply_merge(struct replmd_replicated_request *ar);
static int replmd_delete_internals(struct ldb_module *module, struct ldb_request *req, bool re_delete);
static int replmd_check_upgrade_links(struct ldb_context *ldb,
				      struct parsed_dn *dns, uint32_t count,
				      struct ldb_message_element *el,
				      const char *ldap_oid);
static int replmd_verify_link_target(struct replmd_replicated_request *ar,
				     TALLOC_CTX *mem_ctx,
				     struct la_entry *la_entry,
				     struct ldb_dn *src_dn,
				     const struct dsdb_attribute *attr);
static int replmd_get_la_entry_source(struct ldb_module *module,
				      struct la_entry *la_entry,
				      TALLOC_CTX *mem_ctx,
				      const struct dsdb_attribute **ret_attr,
				      struct ldb_message **source_msg);
static int replmd_set_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v, struct dsdb_dn *dsdb_dn,
			     struct dsdb_dn *old_dsdb_dn, const struct GUID *invocation_id,
			     uint64_t usn, uint64_t local_usn, NTTIME nttime,
			     uint32_t version, bool deleted);

static int replmd_make_deleted_child_dn(TALLOC_CTX *tmp_ctx,
					struct ldb_context *ldb,
					struct ldb_dn *dn,
					const char *rdn_name,
					const struct ldb_val *rdn_value,
					struct GUID guid);

enum urgent_situation {
	REPL_URGENT_ON_CREATE = 1,
	REPL_URGENT_ON_UPDATE = 2,
	REPL_URGENT_ON_DELETE = 4
};

enum deletion_state {
	OBJECT_NOT_DELETED=1,
	OBJECT_DELETED=2,
	OBJECT_RECYCLED=3,
	OBJECT_TOMBSTONE=4,
	OBJECT_REMOVED=5
};

static bool replmd_recyclebin_enabled(struct ldb_module *module)
{
	bool enabled = false;
	struct replmd_private *replmd_private =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct replmd_private);

	/*
	 * only lookup the recycle-bin state once per replication, then cache
	 * the result. This can save us 1000s of DB searches
	 */
	if (!replmd_private->recyclebin_state_known) {
		int ret = dsdb_recyclebin_enabled(module, &enabled);
		if (ret != LDB_SUCCESS) {
			return false;
		}

		replmd_private->recyclebin_enabled = enabled;
		replmd_private->recyclebin_state_known = true;
	}

	return replmd_private->recyclebin_enabled;
}

static void replmd_deletion_state(struct ldb_module *module,
				  const struct ldb_message *msg,
				  enum deletion_state *current_state,
				  enum deletion_state *next_state)
{
	bool enabled = false;

	if (msg == NULL) {
		*current_state = OBJECT_REMOVED;
		if (next_state != NULL) {
			*next_state = OBJECT_REMOVED;
		}
		return;
	}

	enabled = replmd_recyclebin_enabled(module);

	if (ldb_msg_check_string_attribute(msg, "isDeleted", "TRUE")) {
		if (!enabled) {
			*current_state = OBJECT_TOMBSTONE;
			if (next_state != NULL) {
				*next_state = OBJECT_REMOVED;
			}
			return;
		}

		if (ldb_msg_check_string_attribute(msg, "isRecycled", "TRUE")) {
			*current_state = OBJECT_RECYCLED;
			if (next_state != NULL) {
				*next_state = OBJECT_REMOVED;
			}
			return;
		}

		*current_state = OBJECT_DELETED;
		if (next_state != NULL) {
			*next_state = OBJECT_RECYCLED;
		}
		return;
	}

	*current_state = OBJECT_NOT_DELETED;
	if (next_state == NULL) {
		return;
	}

	if (enabled) {
		*next_state = OBJECT_DELETED;
	} else {
		*next_state = OBJECT_TOMBSTONE;
	}
}

static const struct {
	const char *update_name;
	enum urgent_situation repl_situation;
} urgent_objects[] = {
		{"nTDSDSA", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_DELETE)},
		{"crossRef", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_DELETE)},
		{"attributeSchema", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_UPDATE)},
		{"classSchema", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_UPDATE)},
		{"secret", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_UPDATE)},
		{"rIDManager", (REPL_URGENT_ON_CREATE | REPL_URGENT_ON_UPDATE)},
		{NULL, 0}
};

/* Attributes looked for when updating or deleting, to check for a urgent replication needed */
static const char *urgent_attrs[] = {
		"lockoutTime",
		"pwdLastSet",
		"userAccountControl",
		NULL
};


static bool replmd_check_urgent_objectclass(const struct ldb_message_element *objectclass_el,
					enum urgent_situation situation)
{
	unsigned int i, j;
	for (i=0; urgent_objects[i].update_name; i++) {

		if ((situation & urgent_objects[i].repl_situation) == 0) {
			continue;
		}

		for (j=0; j<objectclass_el->num_values; j++) {
			const struct ldb_val *v = &objectclass_el->values[j];
			if (ldb_attr_cmp((const char *)v->data, urgent_objects[i].update_name) == 0) {
				return true;
			}
		}
	}
	return false;
}

static bool replmd_check_urgent_attribute(const struct ldb_message_element *el)
{
	if (ldb_attr_in_list(urgent_attrs, el->name)) {
		return true;
	}
	return false;
}

static int replmd_replicated_apply_isDeleted(struct replmd_replicated_request *ar);

/*
  initialise the module
  allocate the private structure and build the list
  of partition DNs for use by replmd_notify()
 */
static int replmd_init(struct ldb_module *module)
{
	struct replmd_private *replmd_private;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;

	replmd_private = talloc_zero(module, struct replmd_private);
	if (replmd_private == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_check_samba_compatible_feature(module,
						  SAMBA_SORTED_LINKS_FEATURE,
						  &replmd_private->sorted_links);
	if (ret != LDB_SUCCESS) {
		talloc_free(replmd_private);
		return ret;
	}

	replmd_private->schema_dn = ldb_get_schema_basedn(ldb);
	ldb_module_set_private(module, replmd_private);
	return ldb_next_init(module);
}

/*
  cleanup our per-transaction contexts
 */
static void replmd_txn_cleanup(struct replmd_private *replmd_private)
{
	talloc_free(replmd_private->la_ctx);
	replmd_private->la_list = NULL;
	replmd_private->la_ctx = NULL;
	replmd_private->recyclebin_state_known = false;
}


struct la_backlink {
	struct la_backlink *next, *prev;
	const char *attr_name;
	struct ldb_dn *forward_dn;
	struct GUID target_guid;
	bool active;
};

/*
  a ldb_modify request operating on modules below the
  current module
 */
static int linked_attr_modify(struct ldb_module *module,
			      const struct ldb_message *message,
			      struct ldb_request *parent)
{
	struct ldb_request *mod_req;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_result *res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_mod_req(&mod_req, ldb, tmp_ctx,
				message,
				NULL,
				res,
				ldb_modify_default_callback,
				parent);
	LDB_REQ_SET_LOCATION(mod_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_request_add_control(mod_req, DSDB_CONTROL_REPLICATED_UPDATE_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Run the new request */
	ret = ldb_next_request(module, mod_req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(mod_req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

/*
  process a backlinks we accumulated during a transaction, adding and
  deleting the backlinks from the target objects
 */
static int replmd_process_backlink(struct ldb_module *module, struct la_backlink *bl, struct ldb_request *parent)
{
	struct ldb_dn *target_dn, *source_dn;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message *msg;
	TALLOC_CTX *frame = talloc_stackframe();
	char *dn_string;

	/*
	  - find DN of target
	  - find DN of source
	  - construct ldb_message
              - either an add or a delete
	 */
	ret = dsdb_module_dn_by_guid(module, frame, &bl->target_guid, &target_dn, parent);
	if (ret != LDB_SUCCESS) {
		struct GUID_txt_buf guid_str;
		DBG_WARNING("Failed to find target DN for linked attribute with GUID %s\n",
			    GUID_buf_string(&bl->target_guid, &guid_str));
		DBG_WARNING("Please run 'samba-tool dbcheck' to resolve any missing backlinks.\n");
		talloc_free(frame);
		return LDB_SUCCESS;
	}

	msg = ldb_msg_new(frame);
	if (msg == NULL) {
		ldb_module_oom(module);
		talloc_free(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	source_dn = ldb_dn_copy(frame, bl->forward_dn);
	if (!source_dn) {
		ldb_module_oom(module);
		talloc_free(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	} else {
		/* Filter down to the attributes we want in the backlink */
		const char *accept[] = { "GUID", "SID", NULL };
		ldb_dn_extended_filter(source_dn, accept);
	}

	/* construct a ldb_message for adding/deleting the backlink */
	msg->dn = target_dn;
	dn_string = ldb_dn_get_extended_linearized(frame, bl->forward_dn, 1);
	if (!dn_string) {
		ldb_module_oom(module);
		talloc_free(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_msg_add_steal_string(msg, bl->attr_name, dn_string);
	if (ret != LDB_SUCCESS) {
		talloc_free(frame);
		return ret;
	}
	msg->elements[0].flags = bl->active?LDB_FLAG_MOD_ADD:LDB_FLAG_MOD_DELETE;

	/* a backlink should never be single valued. Unfortunately the
	   exchange schema has a attribute
	   msExchBridgeheadedLocalConnectorsDNBL which is single
	   valued and a backlink. We need to cope with that by
	   ignoring the single value flag */
	msg->elements[0].flags |= LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK;

	ret = dsdb_module_modify(module, msg, DSDB_FLAG_NEXT_MODULE, parent);
	if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE && !bl->active) {
		/* we allow LDB_ERR_NO_SUCH_ATTRIBUTE as success to
		   cope with possible corruption where the backlink has
		   already been removed */
		DEBUG(3,("WARNING: backlink from %s already removed from %s - %s\n",
			 ldb_dn_get_linearized(target_dn),
			 ldb_dn_get_linearized(source_dn),
			 ldb_errstring(ldb)));
		ret = LDB_SUCCESS;
	} else if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to %s backlink from %s to %s - %s",
				       bl->active?"add":"remove",
				       ldb_dn_get_linearized(source_dn),
				       ldb_dn_get_linearized(target_dn),
				       ldb_errstring(ldb));
		talloc_free(frame);
		return ret;
	}
	talloc_free(frame);
	return ret;
}

/*
  add a backlink to the list of backlinks to add/delete in the prepare
  commit

  forward_dn is stolen onto the defereed context
 */
static int replmd_defer_add_backlink(struct ldb_module *module,
				     struct replmd_private *replmd_private,
				     const struct dsdb_schema *schema,
				     struct replmd_replicated_request *ac,
				     struct ldb_dn *forward_dn,
				     struct GUID *target_guid, bool active,
				     const struct dsdb_attribute *schema_attr,
				     struct ldb_request *parent)
{
	const struct dsdb_attribute *target_attr;
	struct la_backlink *bl;
	
	bl = talloc(ac, struct la_backlink);
	if (bl == NULL) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	target_attr = dsdb_attribute_by_linkID(schema, schema_attr->linkID ^ 1);
	if (!target_attr) {
		/*
		 * windows 2003 has a broken schema where the
		 * definition of msDS-IsDomainFor is missing (which is
		 * supposed to be the backlink of the
		 * msDS-HasDomainNCs attribute
		 */
		return LDB_SUCCESS;
	}

	bl->attr_name = target_attr->lDAPDisplayName;
	bl->forward_dn = talloc_steal(bl, forward_dn);
	bl->target_guid = *target_guid;
	bl->active = active;

	DLIST_ADD(ac->la_backlinks, bl);

	return LDB_SUCCESS;
}

/*
  add a backlink to the list of backlinks to add/delete in the prepare
  commit
 */
static int replmd_add_backlink(struct ldb_module *module,
			       struct replmd_private *replmd_private,
			       const struct dsdb_schema *schema,
			       struct ldb_dn *forward_dn,
			       struct GUID *target_guid, bool active,
			       const struct dsdb_attribute *schema_attr,
			       struct ldb_request *parent)
{
	const struct dsdb_attribute *target_attr;
	struct la_backlink bl;
	int ret;
	
	target_attr = dsdb_attribute_by_linkID(schema, schema_attr->linkID ^ 1);
	if (!target_attr) {
		/*
		 * windows 2003 has a broken schema where the
		 * definition of msDS-IsDomainFor is missing (which is
		 * supposed to be the backlink of the
		 * msDS-HasDomainNCs attribute
		 */
		return LDB_SUCCESS;
	}

	bl.attr_name = target_attr->lDAPDisplayName;
	bl.forward_dn = forward_dn;
	bl.target_guid = *target_guid;
	bl.active = active;

	ret = replmd_process_backlink(module, &bl, parent);
	return ret;
}


/*
 * Callback for most write operations in this module:
 *
 * notify the repl task that a object has changed. The notifies are
 * gathered up in the replmd_private structure then written to the
 * @REPLCHANGED object in each partition during the prepare_commit
 */
static int replmd_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret;
	struct replmd_replicated_request *ac =
		talloc_get_type_abort(req->context, struct replmd_replicated_request);
	struct replmd_private *replmd_private =
		talloc_get_type_abort(ldb_module_get_private(ac->module), struct replmd_private);
	struct nc_entry *modified_partition;
	struct ldb_control *partition_ctrl;
	const struct dsdb_control_current_partition *partition;

	struct ldb_control **controls;

	partition_ctrl = ldb_reply_get_control(ares, DSDB_CONTROL_CURRENT_PARTITION_OID);

	controls = ares->controls;
	if (ldb_request_get_control(ac->req,
				    DSDB_CONTROL_CURRENT_PARTITION_OID) == NULL) {
		/*
		 * Remove the current partition control from what we pass up
		 * the chain if it hasn't been requested manually.
		 */
		controls = ldb_controls_except_specified(ares->controls, ares,
							 partition_ctrl);
	}

	if (ares->error != LDB_SUCCESS) {
		struct GUID_txt_buf guid_txt;
		struct ldb_message *msg = NULL;
		char *s = NULL;

		if (ac->apply_mode == false) {
			DBG_NOTICE("Originating update failure. Error is: %s\n",
				   ldb_strerror(ares->error));
			return ldb_module_done(ac->req, controls,
					       ares->response, ares->error);
		}

		msg = ac->objs->objects[ac->index_current].msg;
		/*
		 * Set at DBG_NOTICE as once these start to happe, they
		 * will happen a lot until resolved, due to repeated
		 * replication.  The caller will probably print the
		 * ldb error string anyway.
		 */
		DBG_NOTICE("DRS replication apply failure for %s. Error is: %s\n",
			   ldb_dn_get_linearized(msg->dn),
			   ldb_strerror(ares->error));

		s = ldb_ldif_message_redacted_string(ldb_module_get_ctx(ac->module),
						     ac,
						     LDB_CHANGETYPE_ADD,
						     msg);

		DBG_INFO("Failing DRS %s replication message was %s:\n%s\n",
			 ac->search_msg == NULL ? "ADD" : "MODIFY",
			 GUID_buf_string(&ac->objs->objects[ac->index_current].object_guid,
					 &guid_txt),
			 s);
		talloc_free(s);
		return ldb_module_done(ac->req, controls,
				       ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb_module_get_ctx(ac->module), "Invalid reply type for notify\n!");
		return ldb_module_done(ac->req, NULL,
				       NULL, LDB_ERR_OPERATIONS_ERROR);
	}

	if (ac->apply_mode == false) {
		struct la_backlink *bl;
		/*
		 * process our backlink list after an replmd_add(),
		 * creating and deleting backlinks as necessary (this
		 * code is sync).  The other cases are handled inline
		 * with the modify.
		 */
		for (bl=ac->la_backlinks; bl; bl=bl->next) {
			ret = replmd_process_backlink(ac->module, bl, ac->req);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL,
						       NULL, ret);
			}
		}
	}
	
	if (!partition_ctrl) {
		ldb_set_errstring(ldb_module_get_ctx(ac->module),"No partition control on reply");
		return ldb_module_done(ac->req, NULL,
				       NULL, LDB_ERR_OPERATIONS_ERROR);
	}

	partition = talloc_get_type_abort(partition_ctrl->data,
				    struct dsdb_control_current_partition);

	if (ac->seq_num > 0) {
		for (modified_partition = replmd_private->ncs; modified_partition;
		     modified_partition = modified_partition->next) {
			if (ldb_dn_compare(modified_partition->dn, partition->dn) == 0) {
				break;
			}
		}

		if (modified_partition == NULL) {
			modified_partition = talloc_zero(replmd_private, struct nc_entry);
			if (!modified_partition) {
				ldb_oom(ldb_module_get_ctx(ac->module));
				return ldb_module_done(ac->req, NULL,
						       NULL, LDB_ERR_OPERATIONS_ERROR);
			}
			modified_partition->dn = ldb_dn_copy(modified_partition, partition->dn);
			if (!modified_partition->dn) {
				ldb_oom(ldb_module_get_ctx(ac->module));
				return ldb_module_done(ac->req, NULL,
						       NULL, LDB_ERR_OPERATIONS_ERROR);
			}
			DLIST_ADD(replmd_private->ncs, modified_partition);
		}

		if (ac->seq_num > modified_partition->mod_usn) {
			modified_partition->mod_usn = ac->seq_num;
			if (ac->is_urgent) {
				modified_partition->mod_usn_urgent = ac->seq_num;
			}
		}
		if (!ac->apply_mode) {
			replmd_private->originating_updates = true;
		}
	}

	if (ac->apply_mode) {
		ret = replmd_replicated_apply_isDeleted(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		return ret;
	} else {
		/* free the partition control container here, for the
		 * common path.  Other cases will have it cleaned up
		 * eventually with the ares */
		talloc_free(partition_ctrl);
		return ldb_module_done(ac->req, controls,
				       ares->response, LDB_SUCCESS);
	}
}


/*
 * update a @REPLCHANGED record in each partition if there have been
 * any writes of replicated data in the partition
 */
static int replmd_notify_store(struct ldb_module *module, struct ldb_request *parent)
{
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(module), struct replmd_private);

	while (replmd_private->ncs) {
		int ret;
		struct nc_entry *modified_partition = replmd_private->ncs;

		ret = dsdb_module_save_partition_usn(module, modified_partition->dn,
						     modified_partition->mod_usn,
						     modified_partition->mod_usn_urgent, parent);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to save partition uSN for %s\n",
				 ldb_dn_get_linearized(modified_partition->dn)));
			return ret;
		}

		if (ldb_dn_compare(modified_partition->dn,
				   replmd_private->schema_dn) == 0) {
			struct ldb_result *ext_res;
			ret = dsdb_module_extended(module,
						   replmd_private->schema_dn,
						   &ext_res,
						   DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID,
						   ext_res,
						   DSDB_FLAG_NEXT_MODULE,
						   parent);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			talloc_free(ext_res);
		}

		DLIST_REMOVE(replmd_private->ncs, modified_partition);
		talloc_free(modified_partition);
	}

	return LDB_SUCCESS;
}


/*
  created a replmd_replicated_request context
 */
static struct replmd_replicated_request *replmd_ctx_init(struct ldb_module *module,
							 struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;
	const struct GUID *our_invocation_id;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct replmd_replicated_request);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req	= req;

	ac->schema = dsdb_get_schema(ldb, ac);
	if (!ac->schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "replmd_modify: no dsdb_schema loaded");
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		talloc_free(ac);
		return NULL;
	}

	/* get our invocationId */
	our_invocation_id = samdb_ntds_invocation_id(ldb);
	if (!our_invocation_id) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "replmd_add: unable to find invocationId\n");
		talloc_free(ac);
		return NULL;
	}
	ac->our_invocation_id = *our_invocation_id;

	return ac;
}

/*
  add a time element to a record
*/
static int add_time_element(struct ldb_message *msg, const char *attr, time_t t)
{
	struct ldb_message_element *el;
	char *s;
	int ret;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return LDB_SUCCESS;
	}

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_msg_add_string(msg, attr, s);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

/*
  add a uint64_t element to a record
*/
static int add_uint64_element(struct ldb_context *ldb, struct ldb_message *msg,
			      const char *attr, uint64_t v)
{
	struct ldb_message_element *el;
	int ret;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return LDB_SUCCESS;
	}

	ret = samdb_msg_add_uint64(ldb, msg, msg, attr, v);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

static int replmd_replPropertyMetaData1_attid_sort(const struct replPropertyMetaData1 *m1,
						   const struct replPropertyMetaData1 *m2)
{
	/*
	 * This assignment seems inoccous, but it is critical for the
	 * system, as we need to do the comparisons as a unsigned
	 * quantity, not signed (enums are signed integers)
	 */
	uint32_t attid_1 = m1->attid;
	uint32_t attid_2 = m2->attid;

	if (attid_1 == attid_2) {
		return 0;
	}

	/*
	 * See above regarding this being an unsigned comparison.
	 * Otherwise when the high bit is set on non-standard
	 * attributes, they would end up first, before objectClass
	 * (0).
	 */
	return attid_1 > attid_2 ? 1 : -1;
}

static int replmd_replPropertyMetaDataCtr1_verify(struct ldb_context *ldb,
						  struct replPropertyMetaDataCtr1 *ctr1,
						  struct ldb_dn *dn)
{
	if (ctr1->count == 0) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "No elements found in replPropertyMetaData for %s!\n",
			      ldb_dn_get_linearized(dn));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* the objectClass attribute is value 0x00000000, so must be first */
	if (ctr1->array[0].attid != DRSUAPI_ATTID_objectClass) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "No objectClass found in replPropertyMetaData for %s!\n",
			      ldb_dn_get_linearized(dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	return LDB_SUCCESS;
}

static int replmd_replPropertyMetaDataCtr1_sort_and_verify(struct ldb_context *ldb,
							   struct replPropertyMetaDataCtr1 *ctr1,
							   struct ldb_dn *dn)
{
	/* Note this is O(n^2) for the almost-sorted case, which this is */
	TYPESAFE_QSORT(ctr1->array, ctr1->count,
		       replmd_replPropertyMetaData1_attid_sort);
	return replmd_replPropertyMetaDataCtr1_verify(ldb, ctr1, dn);
}

static int replmd_ldb_message_element_attid_sort(const struct ldb_message_element *e1,
						 const struct ldb_message_element *e2,
						 const struct dsdb_schema *schema)
{
	const struct dsdb_attribute *a1;
	const struct dsdb_attribute *a2;

	/*
	 * TODO: make this faster by caching the dsdb_attribute pointer
	 *       on the ldb_messag_element
	 */

	a1 = dsdb_attribute_by_lDAPDisplayName(schema, e1->name);
	a2 = dsdb_attribute_by_lDAPDisplayName(schema, e2->name);

	/*
	 * TODO: remove this check, we should rely on e1 and e2 having valid attribute names
	 *       in the schema
	 */
	if (!a1 || !a2) {
		return strcasecmp(e1->name, e2->name);
	}
	if (a1->attributeID_id == a2->attributeID_id) {
		return 0;
	}
	return a1->attributeID_id > a2->attributeID_id ? 1 : -1;
}

static void replmd_ldb_message_sort(struct ldb_message *msg,
				    const struct dsdb_schema *schema)
{
	LDB_TYPESAFE_QSORT(msg->elements, msg->num_elements, schema, replmd_ldb_message_element_attid_sort);
}

static int replmd_build_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v, struct dsdb_dn *dsdb_dn,
			       const struct GUID *invocation_id,
			       uint64_t local_usn, NTTIME nttime);

static int parsed_dn_compare(struct parsed_dn *pdn1, struct parsed_dn *pdn2);

static int get_parsed_dns(struct ldb_module *module, TALLOC_CTX *mem_ctx,
			  struct ldb_message_element *el, struct parsed_dn **pdn,
			  const char *ldap_oid, struct ldb_request *parent);

static int check_parsed_dn_duplicates(struct ldb_module *module,
				      struct ldb_message_element *el,
				      struct parsed_dn *pdn);

/*
  fix up linked attributes in replmd_add.
  This involves setting up the right meta-data in extended DN
  components, and creating backlinks to the object
 */
static int replmd_add_fix_la(struct ldb_module *module, TALLOC_CTX *mem_ctx,
			     struct replmd_private *replmd_private,
			     struct ldb_message_element *el,
			     struct replmd_replicated_request *ac,
			     NTTIME now,
			     struct ldb_dn *forward_dn,
			     const struct dsdb_attribute *sa,
			     struct ldb_request *parent)
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct parsed_dn *pdn;
	/* We will take a reference to the schema in replmd_add_backlink */
	const struct dsdb_schema *schema = dsdb_get_schema(ldb, NULL);
	struct ldb_val *new_values = NULL;
	int ret;

	if (dsdb_check_single_valued_link(sa, el) == LDB_SUCCESS) {
		el->flags |= LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK;
	} else {
		ldb_asprintf_errstring(ldb,
				       "Attribute %s is single valued but "
				       "more than one value has been supplied",
				       el->name);
		talloc_free(tmp_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/*
	 * At the successful end of these functions el->values is
	 * overwritten with new_values.  However get_parsed_dns()
	 * points p->v at the supplied el and it effectively gets used
	 * as a working area by replmd_build_la_val().  So we must
	 * duplicate it because our caller only called
	 * ldb_msg_copy_shallow().
	 */

	el->values = talloc_memdup(tmp_ctx,
				   el->values,
				   sizeof(el->values[0]) * el->num_values);
	if (el->values == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = get_parsed_dns(module, tmp_ctx, el, &pdn,
			     sa->syntax->ldap_oid, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = check_parsed_dn_duplicates(module, el, pdn);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	new_values = talloc_array(tmp_ctx, struct ldb_val, el->num_values);
	if (new_values == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < el->num_values; i++) {
		struct parsed_dn *p = &pdn[i];
		ret = replmd_build_la_val(new_values, p->v, p->dsdb_dn,
					  &ac->our_invocation_id,
					  ac->seq_num, now);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		ret = replmd_defer_add_backlink(module, replmd_private,
						schema, ac,
						forward_dn, &p->guid, true, sa,
						parent);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		new_values[i] = *p->v;
	}
	el->values = talloc_steal(mem_ctx, new_values);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static int replmd_add_make_extended_dn(struct ldb_request *req,
				       const DATA_BLOB *guid_blob,
				       struct ldb_dn **_extended_dn)
{
	int ret;
        const DATA_BLOB *sid_blob;
	/* Calculate an extended DN for any linked attributes */
	struct ldb_dn *extended_dn = ldb_dn_copy(req, req->op.add.message->dn);
	if (!extended_dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_dn_set_extended_component(extended_dn, "GUID", guid_blob);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	sid_blob = ldb_msg_find_ldb_val(req->op.add.message, "objectSID");
	if (sid_blob != NULL) {
		ret = ldb_dn_set_extended_component(extended_dn, "SID", sid_blob);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	*_extended_dn = extended_dn;
	return LDB_SUCCESS;
}

/*
  intercept add requests
 */
static int replmd_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
        struct ldb_control *control;
	struct replmd_replicated_request *ac;
	enum ndr_err_code ndr_err;
	struct ldb_request *down_req;
	struct ldb_message *msg;
        const DATA_BLOB *guid_blob;
        DATA_BLOB guid_blob_stack;
	struct GUID guid;
	uint8_t guid_data[16];
	struct replPropertyMetaDataBlob nmd;
	struct ldb_val nmd_value;
	struct ldb_dn *extended_dn = NULL;
	
	/*
	 * The use of a time_t here seems odd, but as the NTTIME
	 * elements are actually declared as NTTIME_1sec in the IDL,
	 * getting a higher resolution timestamp is not required.
	 */
	time_t t = time(NULL);
	NTTIME now;
	char *time_str;
	int ret;
	unsigned int i;
	unsigned int functional_level;
	uint32_t ni=0;
	bool allow_add_guid = false;
	bool remove_current_guid = false;
	bool is_urgent = false;
	bool is_schema_nc = false;
	struct ldb_message_element *objectclass_el;
	struct replmd_private *replmd_private =
		talloc_get_type_abort(ldb_module_get_private(module), struct replmd_private);

        /* check if there's a show relax control (used by provision to say 'I know what I'm doing') */
        control = ldb_request_get_control(req, LDB_CONTROL_RELAX_OID);
	if (control) {
		allow_add_guid = true;
	}

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_add\n");

	guid_blob = ldb_msg_find_ldb_val(req->op.add.message, "objectGUID");
	if (guid_blob != NULL) {
		if (!allow_add_guid) {
			ldb_set_errstring(ldb,
					  "replmd_add: it's not allowed to add an object with objectGUID!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			NTSTATUS status = GUID_from_data_blob(guid_blob,&guid);
			if (!NT_STATUS_IS_OK(status)) {
				ldb_set_errstring(ldb,
						  "replmd_add: Unable to parse the 'objectGUID' as a GUID!");
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
			/* we remove this attribute as it can be a string and
			 * will not be treated correctly and then we will re-add
			 * it later on in the good format */
			remove_current_guid = true;
		}
	} else {
		/* a new GUID */
		guid = GUID_random();
		
		guid_blob_stack = data_blob_const(guid_data, sizeof(guid_data));
		
		/* This can't fail */
		ndr_push_struct_into_fixed_blob(&guid_blob_stack, &guid,
						(ndr_push_flags_fn_t)ndr_push_GUID);
		guid_blob = &guid_blob_stack;
	}

	ac = replmd_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_module_oom(module);
	}

	functional_level = dsdb_functional_level(ldb);

	/* Get a sequence number from the backend */
	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &ac->seq_num);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(ac, req->op.add.message);
	if (msg == NULL) {
		ldb_oom(ldb);
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* generated times */
	unix_to_nt_time(&now, t);
	time_str = ldb_timestring(msg, t);
	if (!time_str) {
		ldb_oom(ldb);
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (remove_current_guid) {
		ldb_msg_remove_attr(msg,"objectGUID");
	}

	/*
	 * remove autogenerated attributes
	 */
	ldb_msg_remove_attr(msg, "whenCreated");
	ldb_msg_remove_attr(msg, "whenChanged");
	ldb_msg_remove_attr(msg, "uSNCreated");
	ldb_msg_remove_attr(msg, "uSNChanged");
	ldb_msg_remove_attr(msg, "replPropertyMetaData");

	/*
	 * readd replicated attributes
	 */
	ret = ldb_msg_add_string(msg, "whenCreated", time_str);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}

	/* build the replication meta_data */
	ZERO_STRUCT(nmd);
	nmd.version		= 1;
	nmd.ctr.ctr1.count	= msg->num_elements;
	nmd.ctr.ctr1.array	= talloc_array(msg,
					       struct replPropertyMetaData1,
					       nmd.ctr.ctr1.count);
	if (!nmd.ctr.ctr1.array) {
		ldb_oom(ldb);
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	is_schema_nc = ldb_dn_compare_base(replmd_private->schema_dn, msg->dn) == 0;

	for (i=0; i < msg->num_elements;) {
		struct ldb_message_element *e = &msg->elements[i];
		struct replPropertyMetaData1 *m = &nmd.ctr.ctr1.array[ni];
		const struct dsdb_attribute *sa;

		if (e->name[0] == '@') {
			i++;
			continue;
		}

		sa = dsdb_attribute_by_lDAPDisplayName(ac->schema, e->name);
		if (!sa) {
			ldb_debug_set(ldb, LDB_DEBUG_ERROR,
				      "replmd_add: attribute '%s' not defined in schema\n",
				      e->name);
			talloc_free(ac);
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		if ((sa->systemFlags & DS_FLAG_ATTR_NOT_REPLICATED) || (sa->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED)) {
			/* if the attribute is not replicated (0x00000001)
			 * or constructed (0x00000004) it has no metadata
			 */
			i++;
			continue;
		}

		if (sa->linkID != 0 && functional_level > DS_DOMAIN_FUNCTION_2000) {
			if (extended_dn == NULL) {
				ret = replmd_add_make_extended_dn(req,
								  guid_blob,
								  &extended_dn);
				if (ret != LDB_SUCCESS) {
					talloc_free(ac);
					return ret;
				}
			}			

			/*
			 * Prepare the context for the backlinks and
			 * create metadata for the forward links.  The
			 * backlinks are created in
			 * replmd_op_callback() after the successful
			 * ADD of the object.
			 */
			ret = replmd_add_fix_la(module, msg->elements,
						replmd_private, e,
						ac, now,
						extended_dn,
						sa, req);
			if (ret != LDB_SUCCESS) {
				talloc_free(ac);
				return ret;
			}
			/* linked attributes are not stored in
			   replPropertyMetaData in FL above w2k */
			i++;
			continue;
		}

		m->attid   = dsdb_attribute_get_attid(sa, is_schema_nc);
		m->version = 1;
		if (m->attid == DRSUAPI_ATTID_isDeleted) {
			const struct ldb_val *rdn_val = ldb_dn_get_rdn_val(msg->dn);
			const char* rdn;

			if (rdn_val == NULL) {
				ldb_oom(ldb);
				talloc_free(ac);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			rdn = (const char*)rdn_val->data;
			if (strcmp(rdn, "Deleted Objects") == 0) {
				/*
				 * Set the originating_change_time to 29/12/9999 at 23:59:59
				 * as specified in MS-ADTS 7.1.1.4.2 Deleted Objects Container
				 */
				m->originating_change_time	= DELETED_OBJECT_CONTAINER_CHANGE_TIME;
			} else {
				m->originating_change_time	= now;
			}
		} else {
			m->originating_change_time	= now;
		}
		m->originating_invocation_id	= ac->our_invocation_id;
		m->originating_usn		= ac->seq_num;
		m->local_usn			= ac->seq_num;
		ni++;

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

	/* fix meta data count */
	nmd.ctr.ctr1.count = ni;

	/*
	 * sort meta data array
	 */
	ret = replmd_replPropertyMetaDataCtr1_sort_and_verify(ldb, &nmd.ctr.ctr1, msg->dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "%s: error during direct ADD: %s", __func__, ldb_errstring(ldb));
		talloc_free(ac);
		return ret;
	}

	/* generated NDR encoded values */
	ndr_err = ndr_push_struct_blob(&nmd_value, msg,
				       &nmd,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ldb_oom(ldb);
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * add the autogenerated values
	 */
	ret = dsdb_msg_add_guid(msg, &guid, "objectGUID");
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}
	ret = ldb_msg_add_string(msg, "whenChanged", time_str);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNCreated", ac->seq_num);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", ac->seq_num);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &nmd_value, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(ac);
		return ret;
	}

	/*
	 * sort the attributes by attid before storing the object
	 */
	replmd_ldb_message_sort(msg, ac->schema);

	/*
	 * Assert that we do have an objectClass
	 */
	objectclass_el = ldb_msg_find_element(msg, "objectClass");
	if (objectclass_el == NULL) {
		ldb_asprintf_errstring(ldb, __location__
				       ": objectClass missing on %s\n",
				       ldb_dn_get_linearized(msg->dn));
		talloc_free(ac);
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}
	is_urgent = replmd_check_urgent_objectclass(objectclass_el,
							REPL_URGENT_ON_CREATE);

	ac->is_urgent = is_urgent;
	ret = ldb_build_add_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, replmd_op_callback,
				req);

	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* current partition control is needed by "replmd_op_callback" */
	if (ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID) == NULL) {
		ret = ldb_request_add_control(down_req,
					      DSDB_CONTROL_CURRENT_PARTITION_OID,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	if (functional_level == DS_DOMAIN_FUNCTION_2000) {
		ret = ldb_request_add_control(down_req, DSDB_CONTROL_APPLY_LINKS, false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	/* mark the relax control done */
	if (control) {
		control->critical = 0;
	}
	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}


/*
 * update the replPropertyMetaData for one element
 */
static int replmd_update_rpmd_element(struct ldb_context *ldb,
				      struct ldb_message *msg,
				      struct ldb_message_element *el,
				      struct ldb_message_element *old_el,
				      struct replPropertyMetaDataBlob *omd,
				      const struct dsdb_schema *schema,
				      uint64_t *seq_num,
				      const struct GUID *our_invocation_id,
				      NTTIME now,
				      bool is_schema_nc,
				      bool is_forced_rodc,
				      struct ldb_request *req)
{
	uint32_t i;
	const struct dsdb_attribute *a;
	struct replPropertyMetaData1 *md1;
	bool may_skip = false;
	uint32_t attid;

	a = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
	if (a == NULL) {
		if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)) {
			/* allow this to make it possible for dbcheck
			   to remove bad attributes */
			return LDB_SUCCESS;
		}

		DEBUG(0,(__location__ ": Unable to find attribute %s in schema\n",
			 el->name));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	attid = dsdb_attribute_get_attid(a, is_schema_nc);

	if ((a->systemFlags & DS_FLAG_ATTR_NOT_REPLICATED) || (a->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED)) {
		return LDB_SUCCESS;
	}

	/*
	 * if the attribute's value haven't changed, and this isn't
	 * just a delete of everything then return LDB_SUCCESS Unless
	 * we have the provision control or if the attribute is
	 * interSiteTopologyGenerator as this page explain:
	 * http://support.microsoft.com/kb/224815 this attribute is
	 * periodicaly written by the DC responsible for the intersite
	 * generation in a given site
	 *
	 * Unchanged could be deleting or replacing an already-gone
	 * thing with an unconstrained delete/empty replace or a
	 * replace with the same value, but not an add with the same
	 * value because that could be about adding a duplicate (which
	 * is for someone else to error out on).
	 */
	if (old_el != NULL && ldb_msg_element_equal_ordered(el, old_el)) {
		if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) {
			may_skip = true;
		}
	} else if (old_el == NULL && el->num_values == 0) {
		if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) {
			may_skip = true;
		} else if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE) {
			may_skip = true;
		}
	} else if (a->linkID != 0 && LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE &&
		   ldb_request_get_control(req, DSDB_CONTROL_REPLMD_VANISH_LINKS) != NULL) {
		/*
		 * We intentionally skip the version bump when attempting to
		 * vanish links.
		 *
		 * The control is set by dbcheck and expunge-tombstones which
		 * both attempt to be non-replicating. Otherwise, making an
		 * alteration to the replication state would trigger a
		 * broadcast of all expunged objects.
		 */
		may_skip = true;
	}

	if (el->flags & DSDB_FLAG_INTERNAL_FORCE_META_DATA) {
		may_skip = false;
		el->flags &= ~DSDB_FLAG_INTERNAL_FORCE_META_DATA;
	}

	if (may_skip) {
		if (strcmp(el->name, "interSiteTopologyGenerator") != 0 &&
		    !ldb_request_get_control(req, LDB_CONTROL_PROVISION_OID)) {
			/*
			 * allow this to make it possible for dbcheck
			 * to rebuild broken metadata
			 */
			return LDB_SUCCESS;
		}
	}

	for (i=0; i<omd->ctr.ctr1.count; i++) {
		/*
		 * First check if we find it under the msDS-IntID,
		 * then check if we find it under the OID and
		 * prefixMap ID.
		 *
		 * This allows the administrator to simply re-write
		 * the attributes and so restore replication, which is
		 * likely what they will try to do.
		 */
		if (attid == omd->ctr.ctr1.array[i].attid) {
			break;
		}

		if (a->attributeID_id == omd->ctr.ctr1.array[i].attid) {
			break;
		}
	}

	if (a->linkID != 0 && dsdb_functional_level(ldb) > DS_DOMAIN_FUNCTION_2000) {
		/* linked attributes are not stored in
		   replPropertyMetaData in FL above w2k, but we do
		   raise the seqnum for the object  */
		if (*seq_num == 0 &&
		    ldb_sequence_number(ldb, LDB_SEQ_NEXT, seq_num) != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return LDB_SUCCESS;
	}

	if (i == omd->ctr.ctr1.count) {
		/* we need to add a new one */
		omd->ctr.ctr1.array = talloc_realloc(msg, omd->ctr.ctr1.array,
						     struct replPropertyMetaData1, omd->ctr.ctr1.count+1);
		if (omd->ctr.ctr1.array == NULL) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		omd->ctr.ctr1.count++;
		ZERO_STRUCT(omd->ctr.ctr1.array[i]);
	}

	/* Get a new sequence number from the backend. We only do this
	 * if we have a change that requires a new
	 * replPropertyMetaData element
	 */
	if (*seq_num == 0) {
		int ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, seq_num);
		if (ret != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	md1 = &omd->ctr.ctr1.array[i];
	md1->version++;
	md1->attid = attid;

	if (md1->attid == DRSUAPI_ATTID_isDeleted) {
		const struct ldb_val *rdn_val = ldb_dn_get_rdn_val(msg->dn);
		const char* rdn;

		if (rdn_val == NULL) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		rdn = (const char*)rdn_val->data;
		if (strcmp(rdn, "Deleted Objects") == 0) {
			/*
			 * Set the originating_change_time to 29/12/9999 at 23:59:59
			 * as specified in MS-ADTS 7.1.1.4.2 Deleted Objects Container
			 */
			md1->originating_change_time	= DELETED_OBJECT_CONTAINER_CHANGE_TIME;
		} else {
			md1->originating_change_time	= now;
		}
	} else {
		md1->originating_change_time	= now;
	}
	md1->originating_invocation_id = *our_invocation_id;
	md1->originating_usn           = *seq_num;
	md1->local_usn                 = *seq_num;

	if (is_forced_rodc) {
		/* Force version to 0 to be overridden later via replication */
		md1->version = 0;
	}

	return LDB_SUCCESS;
}

/*
 * Bump the replPropertyMetaData version on an attribute, and if it
 * has changed (or forced by leaving rdn_old NULL), update the value
 * in the entry.
 *
 * This is important, as calling a modify operation may not change the
 * version number if the values appear unchanged, but a rename between
 * parents bumps this value.
 *
 */
static int replmd_update_rpmd_rdn_attr(struct ldb_context *ldb,
				       struct ldb_message *msg,
				       const struct ldb_val *rdn_new,
				       const struct ldb_val *rdn_old,
				       struct replPropertyMetaDataBlob *omd,
				       struct replmd_replicated_request *ar,
				       NTTIME now,
				       bool is_schema_nc,
				       bool is_forced_rodc)
{
	const char *rdn_name = ldb_dn_get_rdn_name(msg->dn);
	const struct dsdb_attribute *rdn_attr =
		dsdb_attribute_by_lDAPDisplayName(ar->schema, rdn_name);
	const char *attr_name = rdn_attr != NULL ?
				rdn_attr->lDAPDisplayName :
				rdn_name;
	struct ldb_message_element new_el = {
		.flags = LDB_FLAG_MOD_REPLACE,
		.name = attr_name,
		.num_values = 1,
		.values = discard_const_p(struct ldb_val, rdn_new)
	};
	struct ldb_message_element old_el = {
		.flags = LDB_FLAG_MOD_REPLACE,
		.name = attr_name,
		.num_values = rdn_old ? 1 : 0,
		.values = discard_const_p(struct ldb_val, rdn_old)
	};

	if (ldb_msg_element_equal_ordered(&new_el, &old_el) == false) {
		int ret = ldb_msg_add(msg, &new_el, LDB_FLAG_MOD_REPLACE);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}
	}

	return replmd_update_rpmd_element(ldb, msg, &new_el, NULL,
					  omd, ar->schema, &ar->seq_num,
					  &ar->our_invocation_id,
					  now, is_schema_nc, is_forced_rodc,
					  ar->req);

}

static uint64_t find_max_local_usn(struct replPropertyMetaDataBlob omd)
{
	uint32_t count = omd.ctr.ctr1.count;
	uint64_t max = 0;
	uint32_t i;
	for (i=0; i < count; i++) {
		struct replPropertyMetaData1 m = omd.ctr.ctr1.array[i];
		if (max < m.local_usn) {
			max = m.local_usn;
		}
	}
	return max;
}

/*
 * update the replPropertyMetaData object each time we modify an
 * object. This is needed for DRS replication, as the merge on the
 * client is based on this object
 */
static int replmd_update_rpmd(struct ldb_module *module,
			      const struct dsdb_schema *schema,
			      struct ldb_request *req,
			      const char * const *rename_attrs,
			      struct ldb_message *msg, uint64_t *seq_num,
			      time_t t, bool is_schema_nc,
			      bool *is_urgent, bool *rodc)
{
	const struct ldb_val *omd_value;
	enum ndr_err_code ndr_err;
	struct replPropertyMetaDataBlob omd;
	unsigned int i;
	NTTIME now;
	const struct GUID *our_invocation_id;
	int ret;
	const char * const *attrs = NULL;
	const char * const attrs2[] = { "uSNChanged", "objectClass", "instanceType", NULL };
	struct ldb_result *res;
	struct ldb_context *ldb;
	struct ldb_message_element *objectclass_el;
	enum urgent_situation situation;
	bool rmd_is_provided;
	bool rmd_is_just_resorted = false;
	const char *not_rename_attrs[4 + msg->num_elements];
	bool is_forced_rodc = false;

	if (rename_attrs) {
		attrs = rename_attrs;
	} else {
		for (i = 0; i < msg->num_elements; i++) {
			not_rename_attrs[i] = msg->elements[i].name;
		}
		not_rename_attrs[i] = "replPropertyMetaData";
		not_rename_attrs[i+1] = "objectClass";
		not_rename_attrs[i+2] = "instanceType";
		not_rename_attrs[i+3] = NULL;
		attrs = not_rename_attrs;
	}

	ldb = ldb_module_get_ctx(module);

	ret = samdb_rodc(ldb, rodc);
	if (ret != LDB_SUCCESS) {
		DEBUG(4, (__location__ ": unable to tell if we are an RODC\n"));
		*rodc = false;
	}

	if (*rodc &&
	    ldb_request_get_control(req, DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE)) {
		is_forced_rodc = true;
	}

	our_invocation_id = samdb_ntds_invocation_id(ldb);
	if (!our_invocation_id) {
		/* this happens during an initial vampire while
		   updating the schema */
		DEBUG(5,("No invocationID - skipping replPropertyMetaData update\n"));
		return LDB_SUCCESS;
	}

	unix_to_nt_time(&now, t);

	if (ldb_request_get_control(req, DSDB_CONTROL_CHANGEREPLMETADATA_OID)) {
		rmd_is_provided = true;
		if (ldb_request_get_control(req, DSDB_CONTROL_CHANGEREPLMETADATA_RESORT_OID)) {
			rmd_is_just_resorted = true;
		}
	} else {
		rmd_is_provided = false;
	}

	/* if isDeleted is present and is TRUE, then we consider we are deleting,
	 * otherwise we consider we are updating */
	if (ldb_msg_check_string_attribute(msg, "isDeleted", "TRUE")) {
		situation = REPL_URGENT_ON_DELETE;
	} else if (rename_attrs) {
		situation = REPL_URGENT_ON_CREATE | REPL_URGENT_ON_DELETE;
	} else {
		situation = REPL_URGENT_ON_UPDATE;
	}

	if (rmd_is_provided) {
		/* In this case the change_replmetadata control was supplied */
		/* We check that it's the only attribute that is provided
		 * (it's a rare case so it's better to keep the code simplier)
		 * We also check that the highest local_usn is bigger or the same as
		 * uSNChanged. */
		uint64_t db_seq;
		if( msg->num_elements != 1 ||
			strncmp(msg->elements[0].name,
				"replPropertyMetaData", 20) ) {
			DEBUG(0,(__location__ ": changereplmetada control called without "\
				"a specified replPropertyMetaData attribute or with others\n"));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (situation != REPL_URGENT_ON_UPDATE) {
			DEBUG(0,(__location__ ": changereplmetada control can't be called when deleting an object\n"));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		omd_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
		if (!omd_value) {
			DEBUG(0,(__location__ ": replPropertyMetaData was not specified for Object %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ndr_err = ndr_pull_struct_blob(omd_value, msg, &omd,
					       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0,(__location__ ": Failed to parse replPropertyMetaData for %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = dsdb_module_search_dn(module, msg, &res, msg->dn, attrs2,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_RECYCLED |
					    DSDB_SEARCH_SHOW_EXTENDED_DN |
					    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
					    DSDB_SEARCH_REVEAL_INTERNALS, req);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (rmd_is_just_resorted == false) {
			*seq_num = find_max_local_usn(omd);

			db_seq = ldb_msg_find_attr_as_uint64(res->msgs[0], "uSNChanged", 0);

			/*
			 * The test here now allows for a new
			 * replPropertyMetaData with no change, if was
			 * just dbcheck re-sorting the values.
			 */
			if (*seq_num <= db_seq) {
				DEBUG(0,(__location__ ": changereplmetada control provided but max(local_usn)" \
					 " is less than uSNChanged (max = %lld uSNChanged = %lld)\n",
					 (long long)*seq_num, (long long)db_seq));
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}

	} else {
		/* search for the existing replPropertyMetaDataBlob. We need
		 * to use REVEAL and ask for DNs in storage format to support
		 * the check for values being the same in
		 * replmd_update_rpmd_element()
		 */
		ret = dsdb_module_search_dn(module, msg, &res, msg->dn, attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_RECYCLED |
					    DSDB_SEARCH_SHOW_EXTENDED_DN |
					    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
					    DSDB_SEARCH_REVEAL_INTERNALS, req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		omd_value = ldb_msg_find_ldb_val(res->msgs[0], "replPropertyMetaData");
		if (!omd_value) {
			DEBUG(0,(__location__ ": Object %s does not have a replPropertyMetaData attribute\n",
				 ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ndr_err = ndr_pull_struct_blob(omd_value, msg, &omd,
					       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0,(__location__ ": Failed to parse replPropertyMetaData for %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (omd.version != 1) {
			DEBUG(0,(__location__ ": bad version %u in replPropertyMetaData for %s\n",
				 omd.version, ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		for (i=0; i<msg->num_elements;) {
			struct ldb_message_element *el = &msg->elements[i];
			struct ldb_message_element *old_el;

			old_el = ldb_msg_find_element(res->msgs[0], el->name);
			ret = replmd_update_rpmd_element(ldb, msg, el, old_el,
							 &omd, schema, seq_num,
							 our_invocation_id,
							 now, is_schema_nc,
							 is_forced_rodc,
							 req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			if (!*is_urgent && (situation == REPL_URGENT_ON_UPDATE)) {
				*is_urgent = replmd_check_urgent_attribute(el);
			}

			if (!(el->flags & DSDB_FLAG_INTERNAL_FORCE_META_DATA)) {
				i++;
				continue;
			}

			el->flags &= ~DSDB_FLAG_INTERNAL_FORCE_META_DATA;

			if (el->num_values != 0) {
				i++;
				continue;
			}

			ldb_msg_remove_element(msg, el);
		}
	}

	/*
	 * Assert that we have an objectClass attribute - this is major
	 * corruption if we don't have this!
	 */
	objectclass_el = ldb_msg_find_element(res->msgs[0], "objectClass");
	if (objectclass_el != NULL) {
		/*
		 * Now check if this objectClass means we need to do urgent replication
		 */
		if (!*is_urgent && replmd_check_urgent_objectclass(objectclass_el,
								   situation)) {
			*is_urgent = true;
		}
	} else if (!ldb_request_get_control(req, DSDB_CONTROL_DBCHECK)) {
		ldb_asprintf_errstring(ldb, __location__
				       ": objectClass missing on %s\n",
				       ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/*
	 * replmd_update_rpmd_element has done an update if the
	 * seq_num is set
	 */
	if (*seq_num != 0 || rmd_is_just_resorted == true) {
		struct ldb_val *md_value;
		struct ldb_message_element *el;

		/*if we are RODC and this is a DRSR update then its ok*/
		if (!ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)
		    && !ldb_request_get_control(req, DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA)
		    && !is_forced_rodc) {
			unsigned instanceType;

			if (*rodc) {
				ldb_set_errstring(ldb, "RODC modify is forbidden!");
				return LDB_ERR_REFERRAL;
			}

			instanceType = ldb_msg_find_attr_as_uint(res->msgs[0], "instanceType", INSTANCE_TYPE_WRITE);
			if (!(instanceType & INSTANCE_TYPE_WRITE)) {
				return ldb_error(ldb, LDB_ERR_UNWILLING_TO_PERFORM,
						 "cannot change replicated attribute on partial replica");
			}
		}

		md_value = talloc(msg, struct ldb_val);
		if (md_value == NULL) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = replmd_replPropertyMetaDataCtr1_sort_and_verify(ldb, &omd.ctr.ctr1, msg->dn);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "%s: %s", __func__, ldb_errstring(ldb));
			return ret;
		}

		ndr_err = ndr_push_struct_blob(md_value, msg, &omd,
					       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0,(__location__ ": Failed to marshall replPropertyMetaData for %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_msg_add_empty(msg, "replPropertyMetaData", LDB_FLAG_MOD_REPLACE, &el);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to add updated replPropertyMetaData %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return ret;
		}

		el->num_values = 1;
		el->values = md_value;
	}

	return LDB_SUCCESS;
}

static int parsed_dn_compare(struct parsed_dn *pdn1, struct parsed_dn *pdn2)
{
	int ret = ndr_guid_compare(&pdn1->guid, &pdn2->guid);
	if (ret == 0) {
		return data_blob_cmp(&pdn1->dsdb_dn->extra_part,
				     &pdn2->dsdb_dn->extra_part);
	}
	return ret;
}

/*
  get a series of message element values as an array of DNs and GUIDs
  the result is sorted by GUID
 */
static int get_parsed_dns(struct ldb_module *module, TALLOC_CTX *mem_ctx,
			  struct ldb_message_element *el, struct parsed_dn **pdn,
			  const char *ldap_oid, struct ldb_request *parent)
{
	unsigned int i;
	bool values_are_sorted = true;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	if (el == NULL) {
		*pdn = NULL;
		return LDB_SUCCESS;
	}

	(*pdn) = talloc_array(mem_ctx, struct parsed_dn, el->num_values);
	if (!*pdn) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i=0; i<el->num_values; i++) {
		struct ldb_val *v = &el->values[i];
		NTSTATUS status;
		struct ldb_dn *dn;
		struct parsed_dn *p;

		p = &(*pdn)[i];

		p->dsdb_dn = dsdb_dn_parse(*pdn, ldb, v, ldap_oid);
		if (p->dsdb_dn == NULL) {
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		dn = p->dsdb_dn->dn;

		status = dsdb_get_extended_dn_guid(dn, &p->guid, "GUID");
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) ||
		    unlikely(GUID_all_zero(&p->guid))) {
			/* we got a DN without a GUID - go find the GUID */
			int ret = dsdb_module_guid_by_dn(module, dn, &p->guid, parent);
			if (ret != LDB_SUCCESS) {
				char *dn_str = NULL;
				dn_str = ldb_dn_get_extended_linearized(mem_ctx,
									(dn), 1);
				ldb_asprintf_errstring(ldb,
						"Unable to find GUID for DN %s\n",
						dn_str);
				if (ret == LDB_ERR_NO_SUCH_OBJECT &&
				    LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE &&
				    ldb_attr_cmp(el->name, "member") == 0) {
					return LDB_ERR_UNWILLING_TO_PERFORM;
				}
				return ret;
			}
			ret = dsdb_set_extended_dn_guid(dn, &p->guid, "GUID");
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		} else if (!NT_STATUS_IS_OK(status)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (i > 0 && values_are_sorted) {
			int cmp = parsed_dn_compare(p, &(*pdn)[i - 1]);
			if (cmp < 0) {
				values_are_sorted = false;
			}
		}
		/* keep a pointer to the original ldb_val */
		p->v = v;
	}
	if (! values_are_sorted) {
		TYPESAFE_QSORT(*pdn, el->num_values, parsed_dn_compare);
	}
	return LDB_SUCCESS;
}

/*
 * Get a series of trusted message element values. The result is sorted by
 * GUID, even though the GUIDs might not be known. That works because we trust
 * the database to give us the elements like that if the
 * replmd_private->sorted_links flag is set.
 *
 * We also ensure that the links are in the Functional Level 2003
 * linked attributes format.
 */
static int get_parsed_dns_trusted_fallback(struct ldb_module *module,
					   struct replmd_private *replmd_private,
					   TALLOC_CTX *mem_ctx,
					   struct ldb_message_element *el,
					   struct parsed_dn **pdn,
					   const char *ldap_oid,
					   struct ldb_request *parent)
{
	int ret;
	if (el == NULL) {
		*pdn = NULL;
		return LDB_SUCCESS;
	}

	if (!replmd_private->sorted_links) {
		/* We need to sort the list. This is the slow old path we want
		   to avoid.
		 */
		ret = get_parsed_dns(module, mem_ctx, el, pdn, ldap_oid,
				      parent);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	} else {
		ret = get_parsed_dns_trusted(mem_ctx, el, pdn);
		if (ret != LDB_SUCCESS) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/*
	 * This upgrades links to FL2003 style, and sorts the result
	 * if that was needed.
	 *
	 * TODO: Add a database feature that asserts we have no FL2000
	 *       style links to avoid this check or add a feature that
	 *       uses a similar check to find sorted/unsorted links
	 *       for an on-the-fly upgrade.
	 */

	ret = replmd_check_upgrade_links(ldb_module_get_ctx(module),
					 *pdn, el->num_values,
					 el,
					 ldap_oid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/*
   Return LDB_SUCCESS if a parsed_dn list contains no duplicate values,
   otherwise an error code. For compatibility the error code differs depending
   on whether or not the attribute is "member".

   As always, the parsed_dn list is assumed to be sorted.
 */
static int check_parsed_dn_duplicates(struct ldb_module *module,
				      struct ldb_message_element *el,
				      struct parsed_dn *pdn)
{
	unsigned int i;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	for (i = 1; i < el->num_values; i++) {
		struct parsed_dn *p = &pdn[i];
		if (parsed_dn_compare(p, &pdn[i - 1]) == 0) {
			ldb_asprintf_errstring(ldb,
					       "Linked attribute %s has "
					       "multiple identical values",
					       el->name);
			if (ldb_attr_cmp(el->name, "member") == 0) {
				return LDB_ERR_ENTRY_ALREADY_EXISTS;
			} else {
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
		}
	}
	return LDB_SUCCESS;
}

/*
  build a new extended DN, including all meta data fields

  RMD_FLAGS           = DSDB_RMD_FLAG_* bits
  RMD_ADDTIME         = originating_add_time
  RMD_INVOCID         = originating_invocation_id
  RMD_CHANGETIME      = originating_change_time
  RMD_ORIGINATING_USN = originating_usn
  RMD_LOCAL_USN       = local_usn
  RMD_VERSION         = version
 */
static int replmd_build_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v,
			       struct dsdb_dn *dsdb_dn,
			       const struct GUID *invocation_id,
			       uint64_t local_usn, NTTIME nttime)
{
	return replmd_set_la_val(mem_ctx, v, dsdb_dn, NULL, invocation_id,
				 local_usn, local_usn, nttime,
				 RMD_VERSION_INITIAL, false);
}

static int replmd_update_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v, struct dsdb_dn *dsdb_dn,
				struct dsdb_dn *old_dsdb_dn, const struct GUID *invocation_id,
				uint64_t seq_num, uint64_t local_usn, NTTIME nttime,
				bool deleted);

/*
  check if any links need upgrading from w2k format
 */
static int replmd_check_upgrade_links(struct ldb_context *ldb,
				      struct parsed_dn *dns, uint32_t count,
				      struct ldb_message_element *el,
				      const char *ldap_oid)
{
	uint32_t i;
	const struct GUID *invocation_id = NULL;
	for (i=0; i<count; i++) {
		NTSTATUS status;
		uint32_t version;
		int ret;
		if (dns[i].dsdb_dn == NULL) {
			ret = really_parse_trusted_dn(dns, ldb, &dns[i],
						      ldap_oid);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_INVALID_DN_SYNTAX;
			}
		}

		status = dsdb_get_extended_dn_uint32(dns[i].dsdb_dn->dn,
						     &version, "RMD_VERSION");
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			/*
			 *  We optimistically assume they are all the same; if
			 *  the first one is fixed, they are all fixed.
			 *
			 *  If the first one was *not* fixed and we find a
			 *  later one that is, that is an occasion to shout
			 *  with DEBUG(0).
			 */
			if (i == 0) {
				return LDB_SUCCESS;
			}
			DEBUG(0, ("Mixed w2k and fixed format "
				  "linked attributes\n"));
			continue;
		}

		if (invocation_id == NULL) {
			invocation_id = samdb_ntds_invocation_id(ldb);
			if (invocation_id == NULL) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}


		/* it's an old one that needs upgrading */
		ret = replmd_update_la_val(el->values, dns[i].v,
					   dns[i].dsdb_dn, dns[i].dsdb_dn,
					   invocation_id, 1, 1, 0, false);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/*
	 * This sort() is critical for the operation of
	 * get_parsed_dns_trusted_fallback() because callers of this function
	 * expect a sorted list, and FL2000 style links are not
	 * sorted.  In particular, as well as the upgrade case,
	 * get_parsed_dns_trusted_fallback() is called from
	 * replmd_delete_remove_link() even in FL2000 mode
	 *
	 * We do not normally pay the cost of the qsort() due to the
	 * early return in the RMD_VERSION found case.
	 */
	TYPESAFE_QSORT(dns, count, parsed_dn_compare);
	return LDB_SUCCESS;
}

/*
  Sets the value for a linked attribute, including all meta data fields

  see replmd_build_la_val for value names
 */
static int replmd_set_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v, struct dsdb_dn *dsdb_dn,
			     struct dsdb_dn *old_dsdb_dn, const struct GUID *invocation_id,
			     uint64_t usn, uint64_t local_usn, NTTIME nttime,
			     uint32_t version, bool deleted)
{
	struct ldb_dn *dn = dsdb_dn->dn;
	const char *tstring, *usn_string, *flags_string;
	struct ldb_val tval;
	struct ldb_val iid;
	struct ldb_val usnv, local_usnv;
	struct ldb_val vers, flagsv;
	const struct ldb_val *old_addtime = NULL;
	NTSTATUS status;
	int ret;
	const char *dnstring;
	char *vstring;
	uint32_t rmd_flags = deleted?DSDB_RMD_FLAG_DELETED:0;

	tstring = talloc_asprintf(mem_ctx, "%llu", (unsigned long long)nttime);
	if (!tstring) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	tval = data_blob_string_const(tstring);

	usn_string = talloc_asprintf(mem_ctx, "%llu", (unsigned long long)usn);
	if (!usn_string) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	usnv = data_blob_string_const(usn_string);

	usn_string = talloc_asprintf(mem_ctx, "%llu", (unsigned long long)local_usn);
	if (!usn_string) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	local_usnv = data_blob_string_const(usn_string);

	status = GUID_to_ndr_blob(invocation_id, dn, &iid);
	if (!NT_STATUS_IS_OK(status)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	flags_string = talloc_asprintf(mem_ctx, "%u", rmd_flags);
	if (!flags_string) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	flagsv = data_blob_string_const(flags_string);

	ret = ldb_dn_set_extended_component(dn, "RMD_FLAGS", &flagsv);
	if (ret != LDB_SUCCESS) return ret;

	/* get the ADDTIME from the original */
	if (old_dsdb_dn != NULL) {
		old_addtime = ldb_dn_get_extended_component(old_dsdb_dn->dn,
							    "RMD_ADDTIME");
	}
	if (old_addtime == NULL) {
		old_addtime = &tval;
	}
	if (dsdb_dn != old_dsdb_dn ||
	    ldb_dn_get_extended_component(dn, "RMD_ADDTIME") == NULL) {
		ret = ldb_dn_set_extended_component(dn, "RMD_ADDTIME", old_addtime);
		if (ret != LDB_SUCCESS) return ret;
	}

	/* use our invocation id */
	ret = ldb_dn_set_extended_component(dn, "RMD_INVOCID", &iid);
	if (ret != LDB_SUCCESS) return ret;

	/* changetime is the current time */
	ret = ldb_dn_set_extended_component(dn, "RMD_CHANGETIME", &tval);
	if (ret != LDB_SUCCESS) return ret;

	/* update the USN */
	ret = ldb_dn_set_extended_component(dn, "RMD_ORIGINATING_USN", &usnv);
	if (ret != LDB_SUCCESS) return ret;

	ret = ldb_dn_set_extended_component(dn, "RMD_LOCAL_USN", &local_usnv);
	if (ret != LDB_SUCCESS) return ret;

	vstring = talloc_asprintf(mem_ctx, "%lu", (unsigned long)version);
	vers = data_blob_string_const(vstring);
	ret = ldb_dn_set_extended_component(dn, "RMD_VERSION", &vers);
	if (ret != LDB_SUCCESS) return ret;

	dnstring = dsdb_dn_get_extended_linearized(mem_ctx, dsdb_dn, 1);
	if (dnstring == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*v = data_blob_string_const(dnstring);

	return LDB_SUCCESS;
}

/**
 * Updates the value for a linked attribute, including all meta data fields
 */
static int replmd_update_la_val(TALLOC_CTX *mem_ctx, struct ldb_val *v, struct dsdb_dn *dsdb_dn,
				struct dsdb_dn *old_dsdb_dn, const struct GUID *invocation_id,
				uint64_t usn, uint64_t local_usn, NTTIME nttime,
				bool deleted)
{
	uint32_t old_version;
	uint32_t version = RMD_VERSION_INITIAL;
	NTSTATUS status;

	/*
	 * We're updating the linked attribute locally, so increase the version
	 * by 1 so that other DCs will see the change when it gets replicated out
	 */
	status = dsdb_get_extended_dn_uint32(old_dsdb_dn->dn, &old_version,
					     "RMD_VERSION");

	if (NT_STATUS_IS_OK(status)) {
		version = old_version + 1;
	}

	return replmd_set_la_val(mem_ctx, v, dsdb_dn, old_dsdb_dn, invocation_id,
				 usn, local_usn, nttime, version, deleted);
}

/*
  handle adding a linked attribute
 */
static int replmd_modify_la_add(struct ldb_module *module,
				struct replmd_private *replmd_private,
				struct replmd_replicated_request *ac,
				struct ldb_message *msg,
				struct ldb_message_element *el,
				struct ldb_message_element *old_el,
				const struct dsdb_attribute *schema_attr,
				time_t t,
				struct ldb_dn *msg_dn,
				struct ldb_request *parent)
{
	unsigned int i, j;
	struct parsed_dn *dns, *old_dns;
	TALLOC_CTX *tmp_ctx = talloc_new(msg);
	int ret;
	struct ldb_val *new_values = NULL;
	unsigned old_num_values = old_el ? old_el->num_values : 0;
	unsigned num_values = 0;
	unsigned max_num_values;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	NTTIME now;
	unix_to_nt_time(&now, t);

	/* get the DNs to be added, fully parsed.
	 *
	 * We need full parsing because they came off the wire and we don't
	 * trust them, besides which we need their details to know where to put
	 * them.
	 */
	ret = get_parsed_dns(module, tmp_ctx, el, &dns,
			     schema_attr->syntax->ldap_oid, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* get the existing DNs, lazily parsed */
	ret = get_parsed_dns_trusted_fallback(module, replmd_private,
					      tmp_ctx, old_el, &old_dns,
					      schema_attr->syntax->ldap_oid,
					      parent);

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	max_num_values = old_num_values + el->num_values;
	if (max_num_values < old_num_values) {
		DEBUG(0, ("we seem to have overflow in replmd_modify_la_add. "
			  "old values: %u, new values: %u, sum: %u\n",
			  old_num_values, el->num_values, max_num_values));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	new_values = talloc_zero_array(tmp_ctx, struct ldb_val, max_num_values);

	if (new_values == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * For each new value, find where it would go in the list. If there is
	 * a matching GUID there, we update the existing value; otherwise we
	 * put it in place.
	 */
	j = 0;
	for (i = 0; i < el->num_values; i++) {
		struct parsed_dn *exact;
		struct parsed_dn *next;
		unsigned offset;
		int err = parsed_dn_find(ldb, old_dns, old_num_values,
					 &dns[i].guid,
					 dns[i].dsdb_dn->dn,
					 dns[i].dsdb_dn->extra_part, 0,
					 &exact, &next,
					 schema_attr->syntax->ldap_oid,
					 true);
		if (err != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return err;
		}

		if (ac->fix_link_sid) {
			char *fixed_dnstring = NULL;
			struct dom_sid tmp_sid = { 0, };
			DATA_BLOB sid_blob = data_blob_null;
			enum ndr_err_code ndr_err;
			NTSTATUS status;
			int num;

			if (exact == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			if (dns[i].dsdb_dn->dn_format != DSDB_NORMAL_DN) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			/*
			 * Only "<GUID=...><SID=...>" is allowed.
			 *
			 * We get the GUID to just to find the old
			 * value and the SID in order to add it
			 * to the found value.
			 */

			num = ldb_dn_get_comp_num(dns[i].dsdb_dn->dn);
			if (num != 0) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			num = ldb_dn_get_extended_comp_num(dns[i].dsdb_dn->dn);
			if (num != 2) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			status = dsdb_get_extended_dn_sid(exact->dsdb_dn->dn,
							  &tmp_sid, "SID");
			if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				/* this is what we expect */
			} else if (NT_STATUS_IS_OK(status)) {
				struct GUID_txt_buf guid_str;
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
						       "i[%u] SID NOT MISSING... Attribute %s already "
						       "exists for target GUID %s, SID %s, DN: %s",
						       i, el->name,
						       GUID_buf_string(&exact->guid,
								       &guid_str),
						       dom_sid_string(tmp_ctx, &tmp_sid),
						       dsdb_dn_get_extended_linearized(tmp_ctx,
							       exact->dsdb_dn, 1));
				talloc_free(tmp_ctx);
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			} else {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			status = dsdb_get_extended_dn_sid(dns[i].dsdb_dn->dn,
							  &tmp_sid, "SID");
			if (!NT_STATUS_IS_OK(status)) {
				struct GUID_txt_buf guid_str;
				ldb_asprintf_errstring(ldb,
						       "NO SID PROVIDED... Attribute %s already "
						       "exists for target GUID %s",
						       el->name,
						       GUID_buf_string(&exact->guid,
								       &guid_str));
				talloc_free(tmp_ctx);
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}

			ndr_err = ndr_push_struct_blob(&sid_blob, tmp_ctx, &tmp_sid,
						       (ndr_push_flags_fn_t)ndr_push_dom_sid);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			ret = ldb_dn_set_extended_component(exact->dsdb_dn->dn, "SID", &sid_blob);
			data_blob_free(&sid_blob);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			fixed_dnstring = dsdb_dn_get_extended_linearized(
					new_values, exact->dsdb_dn, 1);
			if (fixed_dnstring == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			/*
			 * We just replace the existing value...
			 */
			*exact->v = data_blob_string_const(fixed_dnstring);

			continue;
		}

		if (exact != NULL) {
			/*
			 * We are trying to add one that exists, which is only
			 * allowed if it was previously deleted.
			 *
			 * When we do undelete a link we change it in place.
			 * It will be copied across into the right spot in due
			 * course.
			 */
			uint32_t rmd_flags;
			rmd_flags = dsdb_dn_rmd_flags(exact->dsdb_dn->dn);

			if (!(rmd_flags & DSDB_RMD_FLAG_DELETED)) {
				struct GUID_txt_buf guid_str;
				ldb_asprintf_errstring(ldb,
						       "Attribute %s already "
						       "exists for target GUID %s",
						       el->name,
						       GUID_buf_string(&exact->guid,
								       &guid_str));
				talloc_free(tmp_ctx);
				/* error codes for 'member' need to be
				   special cased */
				if (ldb_attr_cmp(el->name, "member") == 0) {
					return LDB_ERR_ENTRY_ALREADY_EXISTS;
				} else {
					return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				}
			}

			ret = replmd_update_la_val(new_values, exact->v,
						   dns[i].dsdb_dn,
						   exact->dsdb_dn,
						   &ac->our_invocation_id,
						   ac->seq_num, ac->seq_num,
						   now, false);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			ret = replmd_add_backlink(module, replmd_private,
						  ac->schema,
						  msg_dn,
						  &dns[i].guid, 
						  true,
						  schema_attr,
						  parent);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
				}
			continue;
		}
		/*
		 * Here we don't have an exact match.
		 *
		 * If next is NULL, this one goes beyond the end of the
		 * existing list, so we need to add all of those ones first.
		 *
		 * If next is not NULL, we need to add all the ones before
		 * next.
		 */
		if (next == NULL) {
			offset = old_num_values;
		} else {
			/* next should have been parsed, but let's make sure */
			if (next->dsdb_dn == NULL) {
				ret = really_parse_trusted_dn(tmp_ctx, ldb, next,
							      schema_attr->syntax->ldap_oid);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			offset = MIN(next - old_dns, old_num_values);
		}

		/* put all the old ones before next on the list */
		for (; j < offset; j++) {
			new_values[num_values] = *old_dns[j].v;
			num_values++;
		}

		ret = replmd_add_backlink(module, replmd_private,
					  ac->schema, msg_dn,
					  &dns[i].guid,
					  true, schema_attr,
					  parent);
		/* Make the new linked attribute ldb_val. */
		ret = replmd_build_la_val(new_values, &new_values[num_values],
					  dns[i].dsdb_dn, &ac->our_invocation_id,
					  ac->seq_num, now);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		num_values++;
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}
	/* copy the rest of the old ones (if any) */
	for (; j < old_num_values; j++) {
		new_values[num_values] = *old_dns[j].v;
		num_values++;
	}

	talloc_steal(msg->elements, new_values);
	if (old_el != NULL) {
		talloc_steal(msg->elements, old_el->values);
	}
	el->values = new_values;
	el->num_values = num_values;

	talloc_free(tmp_ctx);

	/* we now tell the backend to replace all existing values
	   with the one we have constructed */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}


/*
  handle deleting all active linked attributes
 */
static int replmd_modify_la_delete(struct ldb_module *module,
				   struct replmd_private *replmd_private,
				   struct replmd_replicated_request *ac,
				   struct ldb_message *msg,
				   struct ldb_message_element *el,
				   struct ldb_message_element *old_el,
				   const struct dsdb_attribute *schema_attr,
				   time_t t,
				   struct ldb_dn *msg_dn,
				   struct ldb_request *parent)
{
	unsigned int i;
	struct parsed_dn *dns, *old_dns;
	TALLOC_CTX *tmp_ctx = NULL;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_control *vanish_links_ctrl = NULL;
	bool vanish_links = false;
	unsigned int num_to_delete = el->num_values;
	uint32_t rmd_flags;
	NTTIME now;

	unix_to_nt_time(&now, t);

	if (old_el == NULL || old_el->num_values == 0) {
		/* there is nothing to delete... */
		if (num_to_delete == 0) {
			/* and we're deleting nothing, so that's OK */
			return LDB_SUCCESS;
		}
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	tmp_ctx = talloc_new(msg);
	if (tmp_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = get_parsed_dns(module, tmp_ctx, el, &dns,
			     schema_attr->syntax->ldap_oid, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = get_parsed_dns_trusted_fallback(module, replmd_private,
					      tmp_ctx, old_el, &old_dns,
					      schema_attr->syntax->ldap_oid,
					      parent);

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	vanish_links_ctrl = ldb_request_get_control(parent, DSDB_CONTROL_REPLMD_VANISH_LINKS);
	if (vanish_links_ctrl) {
		vanish_links = true;
		vanish_links_ctrl->critical = false;
	}

	/* we empty out el->values here to avoid damage if we return early. */
	el->num_values = 0;
	el->values = NULL;

	/*
	 * If vanish links is set, we are actually removing members of
	 *  old_el->values; otherwise we are just marking them deleted.
	 *
	 * There is a special case when no values are given: we remove them
	 * all. When we have the vanish_links control we just have to remove
	 * the backlinks and change our element to replace the existing values
	 * with the empty list.
	 */

	if (num_to_delete == 0) {
		for (i = 0; i < old_el->num_values; i++) {
			struct parsed_dn *p = &old_dns[i];
			if (p->dsdb_dn == NULL) {
				ret = really_parse_trusted_dn(tmp_ctx, ldb, p,
							      schema_attr->syntax->ldap_oid);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			ret = replmd_add_backlink(module, replmd_private,
						  ac->schema, msg_dn, &p->guid,
						  false, schema_attr,
						  parent);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}
			if (vanish_links) {
				continue;
			}

			rmd_flags = dsdb_dn_rmd_flags(p->dsdb_dn->dn);
			if (rmd_flags & DSDB_RMD_FLAG_DELETED) {
				continue;
			}

			ret = replmd_update_la_val(old_el->values, p->v,
						   p->dsdb_dn, p->dsdb_dn,
						   &ac->our_invocation_id,
						   ac->seq_num, ac->seq_num,
						   now, true);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}
		}

		if (vanish_links) {
			el->flags = LDB_FLAG_MOD_REPLACE;
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}
	}


	for (i = 0; i < num_to_delete; i++) {
		struct parsed_dn *p = &dns[i];
		struct parsed_dn *exact = NULL;
		struct parsed_dn *next = NULL;
		ret = parsed_dn_find(ldb, old_dns, old_el->num_values,
				     &p->guid,
				     NULL,
				     p->dsdb_dn->extra_part, 0,
				     &exact, &next,
				     schema_attr->syntax->ldap_oid,
				     true);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		if (exact == NULL) {
			struct GUID_txt_buf buf;
			ldb_asprintf_errstring(ldb, "Attribute %s doesn't "
					       "exist for target GUID %s",
					       el->name,
					       GUID_buf_string(&p->guid, &buf));
			if (ldb_attr_cmp(el->name, "member") == 0) {
				talloc_free(tmp_ctx);
				return LDB_ERR_UNWILLING_TO_PERFORM;
			} else {
				talloc_free(tmp_ctx);
				return LDB_ERR_NO_SUCH_ATTRIBUTE;
			}
		}

		if (vanish_links) {
			if (CHECK_DEBUGLVL(5)) {
				rmd_flags = dsdb_dn_rmd_flags(exact->dsdb_dn->dn);
				if ((rmd_flags & DSDB_RMD_FLAG_DELETED)) {
					struct GUID_txt_buf buf;
					const char *guid_str = \
						GUID_buf_string(&p->guid, &buf);
					DEBUG(5, ("Deleting deleted linked "
						  "attribute %s to %s, because "
						  "vanish_links control is set\n",
						  el->name, guid_str));
				}
			}

			/* remove the backlink */
			ret = replmd_add_backlink(module,
						  replmd_private,
						  ac->schema,
						  msg_dn,
						  &p->guid,
						  false, schema_attr,
						  parent);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			/* We flag the deletion and tidy it up later. */
			exact->v = NULL;
			continue;
		}

		rmd_flags = dsdb_dn_rmd_flags(exact->dsdb_dn->dn);

		if (rmd_flags & DSDB_RMD_FLAG_DELETED) {
			struct GUID_txt_buf buf;
			const char *guid_str = GUID_buf_string(&p->guid, &buf);
			ldb_asprintf_errstring(ldb, "Attribute %s already "
					       "deleted for target GUID %s",
					       el->name, guid_str);
			if (ldb_attr_cmp(el->name, "member") == 0) {
				talloc_free(tmp_ctx);
				return LDB_ERR_UNWILLING_TO_PERFORM;
			} else {
				talloc_free(tmp_ctx);
				return LDB_ERR_NO_SUCH_ATTRIBUTE;
			}
		}

		ret = replmd_update_la_val(old_el->values, exact->v,
					   exact->dsdb_dn, exact->dsdb_dn,
					   &ac->our_invocation_id,
					   ac->seq_num, ac->seq_num,
					   now, true);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		ret = replmd_add_backlink(module, replmd_private,
					  ac->schema, msg_dn,
					  &p->guid,
					  false, schema_attr,
					  parent);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	if (vanish_links) {
		unsigned j = 0;
		struct ldb_val *tmp_vals = NULL;

		tmp_vals = talloc_array(tmp_ctx, struct ldb_val,
					old_el->num_values);
		if (tmp_vals == NULL) {
			talloc_free(tmp_ctx);
			return ldb_module_oom(module);
		}
		for (i = 0; i < old_el->num_values; i++) {
			if (old_dns[i].v == NULL) {
				continue;
			}
			tmp_vals[j] = *old_dns[i].v;
			j++;
		}
		for (i = 0; i < j; i++) {
			old_el->values[i] = tmp_vals[i];
		}
		old_el->num_values = j;
	}

	el->values = talloc_steal(msg->elements, old_el->values);
	el->num_values = old_el->num_values;

	talloc_free(tmp_ctx);

	/* we now tell the backend to replace all existing values
	   with the one we have constructed */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

/*
  handle replacing a linked attribute
 */
static int replmd_modify_la_replace(struct ldb_module *module,
				    struct replmd_private *replmd_private,
				    struct replmd_replicated_request *ac,
				    struct ldb_message *msg,
				    struct ldb_message_element *el,
				    struct ldb_message_element *old_el,
				    const struct dsdb_attribute *schema_attr,
				    time_t t,
				    struct ldb_dn *msg_dn,
				    struct ldb_request *parent)
{
	unsigned int i, old_i, new_i;
	struct parsed_dn *dns, *old_dns;
	TALLOC_CTX *tmp_ctx = talloc_new(msg);
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_val *new_values = NULL;
	const char *ldap_oid = schema_attr->syntax->ldap_oid;
	unsigned int old_num_values;
	unsigned int repl_num_values;
	unsigned int max_num_values;
	NTTIME now;

	unix_to_nt_time(&now, t);

	/*
	 * The replace operation is unlike the replace and delete cases in that
	 * we need to look at every existing link to see whether it is being
	 * retained or deleted. In other words, we can't avoid parsing the GUIDs.
	 *
	 * As we are trying to combine two sorted lists, the algorithm we use
	 * is akin to the merge phase of a merge sort. We interleave the two
	 * lists, doing different things depending on which side the current
	 * item came from.
	 *
	 * There are three main cases, with some sub-cases.
	 *
	 *  - a DN is in the old list but not the new one. It needs to be
	 *    marked as deleted (but left in the list).
	 *     - maybe it is already deleted, and we have less to do.
	 *
	 *  - a DN is in both lists. The old data gets replaced by the new,
	 *    and the list doesn't grow. The old link may have been marked as
	 *    deleted, in which case we undelete it.
	 *
	 *  - a DN is in the new list only. We add it in the right place.
	 */

	old_num_values = old_el ? old_el->num_values : 0;
	repl_num_values = el->num_values;
	max_num_values = old_num_values + repl_num_values;

	if (max_num_values == 0) {
		/* There is nothing to do! */
		return LDB_SUCCESS;
	}

	/*
	 * At the successful end of these functions el->values is
	 * overwritten with new_values.  However get_parsed_dns()
	 * points p->v at the supplied el and it effectively gets used
	 * as a working area by replmd_build_la_val().  So we must
	 * duplicate it because our caller only called
	 * ldb_msg_copy_shallow().
	 */

	el->values = talloc_memdup(tmp_ctx,
				   el->values,
				   sizeof(el->values[0]) * el->num_values);
	if (el->values == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = get_parsed_dns(module, tmp_ctx, el, &dns, ldap_oid, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = check_parsed_dn_duplicates(module, el, dns);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = get_parsed_dns(module, tmp_ctx, old_el, &old_dns,
			     ldap_oid, parent);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = replmd_check_upgrade_links(ldb, old_dns, old_num_values,
					 old_el, ldap_oid);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	new_values = talloc_array(tmp_ctx, struct ldb_val, max_num_values);
	if (new_values == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	old_i = 0;
	new_i = 0;
	for (i = 0; i < max_num_values; i++) {
		int cmp;
		struct parsed_dn *old_p, *new_p;
		if (old_i < old_num_values && new_i < repl_num_values) {
			old_p = &old_dns[old_i];
			new_p = &dns[new_i];
			cmp = parsed_dn_compare(old_p, new_p);
		} else if (old_i < old_num_values) {
			/* the new list is empty, read the old list */
			old_p = &old_dns[old_i];
			new_p = NULL;
			cmp = -1;
		} else if (new_i < repl_num_values) {
			/* the old list is empty, read new list */
			old_p = NULL;
			new_p = &dns[new_i];
			cmp = 1;
		} else {
			break;
		}

		if (cmp < 0) {
			/*
			 * An old ones that come before the next replacement
			 * (if any). We mark it as deleted and add it to the
			 * final list.
			 */
			uint32_t rmd_flags = dsdb_dn_rmd_flags(old_p->dsdb_dn->dn);
			if ((rmd_flags & DSDB_RMD_FLAG_DELETED) == 0) {
				ret = replmd_update_la_val(new_values, old_p->v,
							   old_p->dsdb_dn,
							   old_p->dsdb_dn,
							   &ac->our_invocation_id,
							   ac->seq_num, ac->seq_num,
							   now, true);
				if (ret != LDB_SUCCESS) {
					talloc_free(tmp_ctx);
					return ret;
				}

				ret = replmd_add_backlink(module, replmd_private,
							  ac->schema,
							  msg_dn,
							  &old_p->guid, false,
							  schema_attr,
							  parent);
				if (ret != LDB_SUCCESS) {
					talloc_free(tmp_ctx);
					return ret;
				}
			}
			new_values[i] = *old_p->v;
			old_i++;
		} else if (cmp == 0) {
			/*
			 * We are overwriting one. If it was previously
			 * deleted, we need to add a backlink.
			 *
			 * Note that if any RMD_FLAGs in an extended new DN
			 * will be ignored.
			 */
			uint32_t rmd_flags;

			ret = replmd_update_la_val(new_values, old_p->v,
						   new_p->dsdb_dn,
						   old_p->dsdb_dn,
						   &ac->our_invocation_id,
						   ac->seq_num, ac->seq_num,
						   now, false);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

			rmd_flags = dsdb_dn_rmd_flags(old_p->dsdb_dn->dn);
			if ((rmd_flags & DSDB_RMD_FLAG_DELETED) != 0) {
				ret = replmd_add_backlink(module, replmd_private,
							  ac->schema,
							  msg_dn,
							  &new_p->guid, true,
							  schema_attr,
							  parent);
				if (ret != LDB_SUCCESS) {
					talloc_free(tmp_ctx);
					return ret;
				}
			}

			new_values[i] = *old_p->v;
			old_i++;
			new_i++;
		} else {
			/*
			 * Replacements that don't match an existing one. We
			 * just add them to the final list.
			 */
			ret = replmd_build_la_val(new_values,
						  new_p->v,
						  new_p->dsdb_dn,
						  &ac->our_invocation_id,
						  ac->seq_num, now);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}
			ret = replmd_add_backlink(module, replmd_private,
						  ac->schema,
						  msg_dn,
						  &new_p->guid, true,
						  schema_attr,
						  parent);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}
			new_values[i] = *new_p->v;
			new_i++;
		}
	}
	if (old_el != NULL) {
		talloc_steal(msg->elements, old_el->values);
	}
	el->values = talloc_steal(msg->elements, new_values);
	el->num_values = i;
	talloc_free(tmp_ctx);

	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}


/*
  handle linked attributes in modify requests
 */
static int replmd_modify_handle_linked_attribs(struct ldb_module *module,
					       struct replmd_private *replmd_private,
					       struct replmd_replicated_request *ac,
					       struct ldb_message *msg,
					       time_t t,
					       struct ldb_request *parent)
{
	struct ldb_result *res;
	unsigned int i;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message *old_msg;

	if (dsdb_functional_level(ldb) == DS_DOMAIN_FUNCTION_2000) {
		/*
		 * Nothing special is required for modifying or vanishing links
		 * in fl2000 since they are just strings in a multi-valued
		 * attribute.
		 */
		struct ldb_control *ctrl = ldb_request_get_control(parent,
								   DSDB_CONTROL_REPLMD_VANISH_LINKS);
		if (ctrl) {
			ctrl->critical = false;
		}
		return LDB_SUCCESS;
	}

	/*
	 * TODO:
	 *
	 * We should restrict this to the intersection of the list of
	 * linked attributes in the schema and the list of attributes
	 * being modified.
	 *
	 * This will help performance a little, as otherwise we have
	 * to allocate the entire object value-by-value.
	 */
	ret = dsdb_module_search_dn(module, msg, &res, msg->dn, NULL,
	                            DSDB_FLAG_NEXT_MODULE |
	                            DSDB_SEARCH_SHOW_RECYCLED |
				    DSDB_SEARCH_REVEAL_INTERNALS |
				    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				    parent);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	old_msg = res->msgs[0];

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct ldb_message_element *old_el, *new_el;
		unsigned int mod_type = LDB_FLAG_MOD_TYPE(el->flags);
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(ldb,
					       "%s: attribute %s is not a valid attribute in schema",
					       __FUNCTION__, el->name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}
		if (schema_attr->linkID == 0) {
			continue;
		}
		if ((schema_attr->linkID & 1) == 1) {
			struct ldb_control *ctrl;

			ctrl = ldb_request_get_control(parent,
						       DSDB_CONTROL_REPLMD_VANISH_LINKS);
			if (ctrl != NULL) {
				ctrl->critical = false;
				continue;
			}
			ctrl = ldb_request_get_control(parent,
						       DSDB_CONTROL_DBCHECK);
			if (ctrl != NULL) {
				continue;
			}

			/* Odd is for the target.  Illegal to modify */
			ldb_asprintf_errstring(ldb,
					       "attribute %s must not be modified directly, it is a linked attribute", el->name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		old_el = ldb_msg_find_element(old_msg, el->name);
		switch (mod_type) {
		case LDB_FLAG_MOD_REPLACE:
			ret = replmd_modify_la_replace(module, replmd_private,
						       ac, msg, el, old_el,
						       schema_attr, t,
						       old_msg->dn,
						       parent);
			break;
		case LDB_FLAG_MOD_DELETE:
			ret = replmd_modify_la_delete(module, replmd_private,
						      ac, msg, el, old_el,
						      schema_attr, t,
						      old_msg->dn,
						      parent);
			break;
		case LDB_FLAG_MOD_ADD:
			ret = replmd_modify_la_add(module, replmd_private,
						   ac, msg, el, old_el,
						   schema_attr, t,
						   old_msg->dn,
						   parent);
			break;
		default:
			ldb_asprintf_errstring(ldb,
					       "invalid flags 0x%x for %s linked attribute",
					       el->flags, el->name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ret = dsdb_check_single_valued_link(schema_attr, el);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb,
					       "Attribute %s is single valued but more than one value has been supplied",
					       el->name);
			/* Return codes as found on Windows 2012r2 */
			if (mod_type == LDB_FLAG_MOD_REPLACE) {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			} else {
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
		} else {
			el->flags |= LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK;
		}

		if (old_el) {
			ldb_msg_remove_attr(old_msg, el->name);
		}
		ldb_msg_add_empty(old_msg, el->name, 0, &new_el);
		new_el->num_values = el->num_values;
		new_el->values = talloc_steal(msg->elements, el->values);

		/* TODO: this relises a bit too heavily on the exact
		   behaviour of ldb_msg_find_element and
		   ldb_msg_remove_element */
		old_el = ldb_msg_find_element(msg, el->name);
		if (old_el != el) {
			ldb_msg_remove_element(msg, old_el);
			i--;
		}
	}

	talloc_free(res);
	return ret;
}


static int send_rodc_referral(struct ldb_request *req,
			      struct ldb_context *ldb,
			      struct ldb_dn *dn)
{
	char *referral = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct ldb_dn *fsmo_role_dn = NULL;
	struct ldb_dn *role_owner_dn = NULL;
	const char *domain = NULL;
	WERROR werr;

	lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				 struct loadparm_context);

	werr = dsdb_get_fsmo_role_info(req, ldb, DREPL_PDC_MASTER,
				       &fsmo_role_dn, &role_owner_dn);

	if (W_ERROR_IS_OK(werr)) {
		struct ldb_dn *server_dn = ldb_dn_copy(req, role_owner_dn);
		if (server_dn != NULL) {
			ldb_dn_remove_child_components(server_dn, 1);
			domain = samdb_dn_to_dnshostname(ldb, req,
							 server_dn);
		}
	}

	if (domain == NULL) {
		domain = lpcfg_dnsdomain(lp_ctx);
	}

	referral = talloc_asprintf(req, "ldap://%s/%s",
				   domain,
				   ldb_dn_get_linearized(dn));
	if (referral == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_module_send_referral(req, referral);
}


static int replmd_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	time_t t = time(NULL);
	int ret;
	bool is_urgent = false, rodc = false;
	bool is_schema_nc = false;
	unsigned int functional_level;
	const struct ldb_message_element *guid_el = NULL;
	struct ldb_control *sd_propagation_control;
	struct ldb_control *fix_links_control = NULL;
	struct ldb_control *fix_dn_name_control = NULL;
	struct ldb_control *fix_dn_sid_control = NULL;
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(module), struct replmd_private);

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	sd_propagation_control = ldb_request_get_control(req,
					DSDB_CONTROL_SEC_DESC_PROPAGATION_OID);
	if (sd_propagation_control != NULL) {
		if (req->op.mod.message->num_elements != 1) {
			return ldb_module_operr(module);
		}
		ret = strcmp(req->op.mod.message->elements[0].name,
			     "nTSecurityDescriptor");
		if (ret != 0) {
			return ldb_module_operr(module);
		}

		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	fix_links_control = ldb_request_get_control(req,
					DSDB_CONTROL_DBCHECK_FIX_DUPLICATE_LINKS);
	if (fix_links_control != NULL) {
		struct dsdb_schema *schema = NULL;
		const struct dsdb_attribute *sa = NULL;

		if (req->op.mod.message->num_elements != 1) {
			return ldb_module_operr(module);
		}

		if (req->op.mod.message->elements[0].flags != LDB_FLAG_MOD_REPLACE) {
			return ldb_module_operr(module);
		}

		schema = dsdb_get_schema(ldb, req);
		if (schema == NULL) {
			return ldb_module_operr(module);
		}

		sa = dsdb_attribute_by_lDAPDisplayName(schema,
				req->op.mod.message->elements[0].name);
		if (sa == NULL) {
			return ldb_module_operr(module);
		}

		if (sa->linkID == 0) {
			return ldb_module_operr(module);
		}

		fix_links_control->critical = false;
		return ldb_next_request(module, req);
	}

	fix_dn_name_control = ldb_request_get_control(req,
					DSDB_CONTROL_DBCHECK_FIX_LINK_DN_NAME);
	if (fix_dn_name_control != NULL) {
		struct dsdb_schema *schema = NULL;
		const struct dsdb_attribute *sa = NULL;

		if (req->op.mod.message->num_elements != 2) {
			return ldb_module_operr(module);
		}

		if (req->op.mod.message->elements[0].flags != LDB_FLAG_MOD_DELETE) {
			return ldb_module_operr(module);
		}

		if (req->op.mod.message->elements[1].flags != LDB_FLAG_MOD_ADD) {
			return ldb_module_operr(module);
		}

		if (req->op.mod.message->elements[0].num_values != 1) {
			return ldb_module_operr(module);
		}

		if (req->op.mod.message->elements[1].num_values != 1) {
			return ldb_module_operr(module);
		}

		schema = dsdb_get_schema(ldb, req);
		if (schema == NULL) {
			return ldb_module_operr(module);
		}

		if (ldb_attr_cmp(req->op.mod.message->elements[0].name,
				 req->op.mod.message->elements[1].name) != 0) {
			return ldb_module_operr(module);
		}

		sa = dsdb_attribute_by_lDAPDisplayName(schema,
				req->op.mod.message->elements[0].name);
		if (sa == NULL) {
			return ldb_module_operr(module);
		}

		if (sa->dn_format == DSDB_INVALID_DN) {
			return ldb_module_operr(module);
		}

		if (sa->linkID != 0) {
			return ldb_module_operr(module);
		}

		/*
		 * If we are run from dbcheck and we are not updating
		 * a link (as these would need to be sorted and so
		 * can't go via such a simple update, then do not
		 * trigger replicated updates and a new USN from this
		 * change, it wasn't a real change, just a new
		 * (correct) string DN
		 */

		fix_dn_name_control->critical = false;
		return ldb_next_request(module, req);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_modify\n");

	guid_el = ldb_msg_find_element(req->op.mod.message, "objectGUID");
	if (guid_el != NULL) {
		ldb_set_errstring(ldb,
				  "replmd_modify: it's not allowed to change the objectGUID!");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ac = replmd_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_module_oom(module);
	}

	functional_level = dsdb_functional_level(ldb);

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (msg == NULL) {
		ldb_oom(ldb);
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	fix_dn_sid_control = ldb_request_get_control(req,
					DSDB_CONTROL_DBCHECK_FIX_LINK_DN_SID);
	if (fix_dn_sid_control != NULL) {
		const struct dsdb_attribute *sa = NULL;

		if (msg->num_elements != 1) {
			talloc_free(ac);
			return ldb_module_operr(module);
		}

		if (msg->elements[0].flags != LDB_FLAG_MOD_ADD) {
			talloc_free(ac);
			return ldb_module_operr(module);
		}

		if (msg->elements[0].num_values != 1) {
			talloc_free(ac);
			return ldb_module_operr(module);
		}

		sa = dsdb_attribute_by_lDAPDisplayName(ac->schema,
				msg->elements[0].name);
		if (sa == NULL) {
			talloc_free(ac);
			return ldb_module_operr(module);
		}

		if (sa->dn_format != DSDB_NORMAL_DN) {
			talloc_free(ac);
			return ldb_module_operr(module);
		}

		fix_dn_sid_control->critical = false;
		ac->fix_link_sid = true;

		goto handle_linked_attribs;
	}

	ldb_msg_remove_attr(msg, "whenChanged");
	ldb_msg_remove_attr(msg, "uSNChanged");

	is_schema_nc = ldb_dn_compare_base(replmd_private->schema_dn, msg->dn) == 0;

	ret = replmd_update_rpmd(module, ac->schema, req, NULL,
				 msg, &ac->seq_num, t, is_schema_nc,
				 &is_urgent, &rodc);
	if (rodc && (ret == LDB_ERR_REFERRAL)) {
		ret = send_rodc_referral(req, ldb, msg->dn);
		talloc_free(ac);
		return ret;

	}

	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

 handle_linked_attribs:
	ret = replmd_modify_handle_linked_attribs(module, replmd_private,
						  ac, msg, t, req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* TODO:
	 * - replace the old object with the newly constructed one
	 */

	ac->is_urgent = is_urgent;

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, replmd_op_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* current partition control is needed by "replmd_op_callback" */
	if (ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID) == NULL) {
		ret = ldb_request_add_control(down_req,
					      DSDB_CONTROL_CURRENT_PARTITION_OID,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	/* If we are in functional level 2000, then
	 * replmd_modify_handle_linked_attribs will have done
	 * nothing */
	if (functional_level == DS_DOMAIN_FUNCTION_2000) {
		ret = ldb_request_add_control(down_req, DSDB_CONTROL_APPLY_LINKS, false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	talloc_steal(down_req, msg);

	/* we only change whenChanged and uSNChanged if the seq_num
	   has changed */
	if (ac->seq_num != 0) {
		ret = add_time_element(msg, "whenChanged", t);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			ldb_operr(ldb);
			return ret;
		}

		ret = add_uint64_element(ldb, msg, "uSNChanged", ac->seq_num);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			ldb_operr(ldb);
			return ret;
		}
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static int replmd_rename_callback(struct ldb_request *req, struct ldb_reply *ares);

/*
  handle a rename request

  On a rename we need to do an extra ldb_modify which sets the
  whenChanged and uSNChanged attributes.  We do this in a callback after the success.
 */
static int replmd_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_control *fix_dn_name_control = NULL;
	struct replmd_replicated_request *ac;
	int ret;
	struct ldb_request *down_req;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	fix_dn_name_control = ldb_request_get_control(req,
					DSDB_CONTROL_DBCHECK_FIX_LINK_DN_NAME);
	if (fix_dn_name_control != NULL) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_rename\n");

	ac = replmd_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_module_oom(module);
	}

	ret = ldb_build_rename_req(&down_req, ldb, ac,
				   ac->req->op.rename.olddn,
				   ac->req->op.rename.newdn,
				   ac->req->controls,
				   ac, replmd_rename_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

/* After the rename is compleated, update the whenchanged etc */
static int replmd_rename_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	const struct dsdb_attribute *rdn_attr;
	const char *rdn_name;
	const struct ldb_val *rdn_val;
	const char *attrs[5] = { NULL, };
	time_t t = time(NULL);
	int ret;
	bool is_urgent = false, rodc = false;
	bool is_schema_nc;
	struct replmd_replicated_request *ac =
		talloc_get_type(req->context, struct replmd_replicated_request);
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(ac->module),
				struct replmd_private);

	ldb = ldb_module_get_ctx(ac->module);

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb,
			"invalid reply type in repl_meta_data rename callback");
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	/* TODO:
	 * - replace the old object with the newly constructed one
	 */

	msg = ldb_msg_new(ac);
	if (msg == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->dn = ac->req->op.rename.newdn;

	is_schema_nc = ldb_dn_compare_base(replmd_private->schema_dn, msg->dn) == 0;

	rdn_name = ldb_dn_get_rdn_name(msg->dn);
	if (rdn_name == NULL) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_operr(ldb));
	}

	/* normalize the rdn attribute name */
	rdn_attr = dsdb_attribute_by_lDAPDisplayName(ac->schema, rdn_name);
	if (rdn_attr == NULL) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_operr(ldb));
	}
	rdn_name = rdn_attr->lDAPDisplayName;

	rdn_val = ldb_dn_get_rdn_val(msg->dn);
	if (rdn_val == NULL) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_operr(ldb));
	}

	if (ldb_msg_add_empty(msg, rdn_name, LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_oom(ldb));
	}
	if (ldb_msg_add_value(msg, rdn_name, rdn_val, NULL) != 0) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_oom(ldb));
	}
	if (ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_oom(ldb));
	}
	if (ldb_msg_add_value(msg, "name", rdn_val, NULL) != 0) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_oom(ldb));
	}

	/*
	 * here we let replmd_update_rpmd() only search for
	 * the existing "replPropertyMetaData" and rdn_name attributes.
	 *
	 * We do not want the existing "name" attribute as
	 * the "name" attribute needs to get the version
	 * updated on rename even if the rdn value hasn't changed.
	 *
	 * This is the diff of the meta data, for a moved user
	 * on a w2k8r2 server:
	 *
	 * # record 1
	 * -dn: CN=sdf df,CN=Users,DC=bla,DC=base
	 * +dn: CN=sdf df,OU=TestOU,DC=bla,DC=base
	 *  replPropertyMetaData:     NDR: struct replPropertyMetaDataBlob
	 *         version                  : 0x00000001 (1)
	 *         reserved                 : 0x00000000 (0)
	 * @@ -66,11 +66,11 @@ replPropertyMetaData:     NDR: struct re
	 *                      local_usn                : 0x00000000000037a5 (14245)
	 *                 array: struct replPropertyMetaData1
	 *                      attid                    : DRSUAPI_ATTID_name (0x90001)
	 * -                    version                  : 0x00000001 (1)
	 * -                    originating_change_time  : Wed Feb  9 17:20:49 2011 CET
	 * +                    version                  : 0x00000002 (2)
	 * +                    originating_change_time  : Wed Apr  6 15:21:01 2011 CEST
	 *                      originating_invocation_id: 0d36ca05-5507-4e62-aca3-354bab0d39e1
	 * -                    originating_usn          : 0x00000000000037a5 (14245)
	 * -                    local_usn                : 0x00000000000037a5 (14245)
	 * +                    originating_usn          : 0x0000000000003834 (14388)
	 * +                    local_usn                : 0x0000000000003834 (14388)
	 *                 array: struct replPropertyMetaData1
	 *                      attid                    : DRSUAPI_ATTID_userAccountControl (0x90008)
	 *                      version                  : 0x00000004 (4)
	 */
	attrs[0] = "replPropertyMetaData";
	attrs[1] = "objectClass";
	attrs[2] = "instanceType";
	attrs[3] = rdn_name;
	attrs[4] = NULL;

	ret = replmd_update_rpmd(ac->module, ac->schema, req, attrs,
				 msg, &ac->seq_num, t,
				 is_schema_nc, &is_urgent, &rodc);
	if (rodc && (ret == LDB_ERR_REFERRAL)) {
		ret = send_rodc_referral(req, ldb, ac->req->op.rename.olddn);
		talloc_free(ares);
		return ldb_module_done(req, NULL, NULL, ret);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	if (ac->seq_num == 0) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       ldb_error(ldb, ret,
					"internal error seq_num == 0"));
	}
	ac->is_urgent = is_urgent;

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, replmd_op_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* current partition control is needed by "replmd_op_callback" */
	if (ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID) == NULL) {
		ret = ldb_request_add_control(down_req,
					      DSDB_CONTROL_CURRENT_PARTITION_OID,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(ac);
			return ret;
		}
	}

	talloc_steal(down_req, msg);

	ret = add_time_element(msg, "whenChanged", t);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		ldb_operr(ldb);
		return ret;
	}

	ret = add_uint64_element(ldb, msg, "uSNChanged", ac->seq_num);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		ldb_operr(ldb);
		return ret;
	}

	/* go on with the call chain - do the modify after the rename */
	return ldb_next_request(ac->module, down_req);
}

/*
 * remove links from objects that point at this object when an object
 * is deleted.  We remove it from the NEXT module per MS-DRSR 5.160
 * RemoveObj which states that link removal due to the object being
 * deleted is NOT an originating update - they just go away!
 *
 */
static int replmd_delete_remove_link(struct ldb_module *module,
				     const struct dsdb_schema *schema,
				     struct replmd_private *replmd_private,
				     struct ldb_dn *dn,
				     struct GUID *guid,
				     struct ldb_message_element *el,
				     const struct dsdb_attribute *sa,
				     struct ldb_request *parent,
				     bool *caller_should_vanish)
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	for (i=0; i<el->num_values; i++) {
		struct dsdb_dn *dsdb_dn;
		int ret;
		struct ldb_message *msg;
		const struct dsdb_attribute *target_attr;
		struct ldb_message_element *el2;
		const char *dn_str;
		struct ldb_val dn_val;
		uint32_t dsdb_flags = 0;
		const char *attrs[] = { NULL, NULL };
		struct ldb_result *link_res;
		struct ldb_message *link_msg;
		struct ldb_message_element *link_el;
		struct parsed_dn *link_dns;
		struct parsed_dn *p = NULL, *unused = NULL;

		if (dsdb_dn_is_deleted_val(&el->values[i])) {
			continue;
		}

		dsdb_dn = dsdb_dn_parse(tmp_ctx, ldb, &el->values[i], sa->syntax->ldap_oid);
		if (!dsdb_dn) {
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* remove the link */
		msg = ldb_msg_new(tmp_ctx);
		if (!msg) {
			ldb_module_oom(module);
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		msg->dn = dsdb_dn->dn;

		target_attr = dsdb_attribute_by_linkID(schema, sa->linkID ^ 1);
		if (target_attr == NULL) {
			continue;
		}
		attrs[0] = target_attr->lDAPDisplayName;

		ret = ldb_msg_add_empty(msg, target_attr->lDAPDisplayName,
					LDB_FLAG_MOD_DELETE, &el2);
		if (ret != LDB_SUCCESS) {
			ldb_module_oom(module);
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = dsdb_module_search_dn(module, tmp_ctx, &link_res,
					    msg->dn, attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_EXTENDED_DN |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    parent);

		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			DBG_WARNING("Failed to find forward link object %s "
				    "to remove backlink %s on %s",
				    ldb_dn_get_linearized(msg->dn),
				    sa->lDAPDisplayName,
				    ldb_dn_get_linearized(dn));
			*caller_should_vanish = true;
			continue;
		}

		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		link_msg = link_res->msgs[0];
		link_el = ldb_msg_find_element(link_msg,
					       target_attr->lDAPDisplayName);
		if (link_el == NULL) {
			DBG_WARNING("Failed to find forward link on %s "
				    "as %s to remove backlink %s on %s",
				    ldb_dn_get_linearized(msg->dn),
				    target_attr->lDAPDisplayName,
				    sa->lDAPDisplayName,
				    ldb_dn_get_linearized(dn));
			*caller_should_vanish = true;
			continue;
		}

		/*
		 * This call 'upgrades' the links in link_dns, but we
		 * do not commit the result back into the database, so
		 * this is safe to call in FL2000 or on databases that
		 * have been run at that level in the past.
		 */
		ret = get_parsed_dns_trusted_fallback(module, replmd_private,
						tmp_ctx,
						link_el, &link_dns,
						target_attr->syntax->ldap_oid,
						parent);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		ret = parsed_dn_find(ldb, link_dns, link_el->num_values,
				     guid, dn,
				     data_blob_null, 0,
				     &p, &unused,
				     target_attr->syntax->ldap_oid, false);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		if (p == NULL) {
			DBG_WARNING("Failed to find forward link on %s "
				    "as %s to remove backlink %s on %s",
				    ldb_dn_get_linearized(msg->dn),
				    target_attr->lDAPDisplayName,
				    sa->lDAPDisplayName,
				    ldb_dn_get_linearized(dn));
			*caller_should_vanish = true;
			continue;
		}

		/*
		 * If we find a backlink to ourself, we will delete
		 * the forward link before we get to process that
		 * properly, so just let the caller process this via
		 * the forward link.
		 *
		 * We do this once we are sure we have the forward
		 * link (to ourself) in case something is very wrong
		 * and they are out of sync.
		 */
		if (ldb_dn_compare(dsdb_dn->dn, dn) == 0) {
			continue;
		}

		/* This needs to get the Binary DN, by first searching */
		dn_str = dsdb_dn_get_linearized(tmp_ctx,
						p->dsdb_dn);

		dn_val = data_blob_string_const(dn_str);
		el2->values = &dn_val;
		el2->num_values = 1;

		/*
		 * Ensure that we tell the modification to vanish any linked
		 * attributes (not simply mark them as isDeleted = TRUE)
		 */
		dsdb_flags |= DSDB_REPLMD_VANISH_LINKS;

		ret = dsdb_module_modify(module, msg, dsdb_flags|DSDB_FLAG_OWN_MODULE, parent);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


/*
  handle update of replication meta data for deletion of objects

  This also handles the mapping of delete to a rename operation
  to allow deletes to be replicated.

  It also handles the incoming deleted objects, to ensure they are
  fully deleted here.  In that case re_delete is true, and we do not
  use this as a signal to change the deleted state, just reinforce it.

 */
static int replmd_delete_internals(struct ldb_module *module, struct ldb_request *req, bool re_delete)
{
	int ret = LDB_ERR_OTHER;
	bool retb, disallow_move_on_delete;
	struct ldb_dn *old_dn = NULL, *new_dn = NULL;
	const char *rdn_name;
	const struct ldb_val *rdn_value, *new_rdn_value;
	struct GUID guid;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema;
	struct ldb_message *msg, *old_msg;
	struct ldb_message_element *el;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res, *parent_res;
	static const char * const preserved_attrs[] = {
		/*
		 * This list MUST be kept in case-insensitive sorted order,
		 * as we  use it in a binary search with ldb_attr_cmp().
		 *
		 * We get this hard-coded list from
		 * MS-ADTS section 3.1.1.5.5.1.1 "Tombstone Requirements".
		 */
		"attributeID",
		"attributeSyntax",
		"distinguishedName",
		"dNReferenceUpdate",
		"dNSHostName",
		"flatName",
		"governsID",
		"groupType",
		"instanceType",
		"isDeleted",
		"isRecycled",
		"lastKnownParent",
		"lDAPDisplayName",
		"legacyExchangeDN",
		"mS-DS-CreatorSID",
		"msDS-LastKnownRDN",
		"msDS-PortLDAP",
		"mSMQOwnerID",
		"name",
		"nCName",
		"nTSecurityDescriptor",
		"objectClass",
		"objectGUID",
		"objectSid",
		"oMSyntax",
		"proxiedObjectName",
		"replPropertyMetaData",
		"sAMAccountName",
		"securityIdentifier",
		"sIDHistory",
		"subClassOf",
		"systemFlags",
		"trustAttributes",
		"trustDirection",
		"trustPartner",
		"trustType",
		"userAccountControl",
		"uSNChanged",
		"uSNCreated",
		"whenChanged",
		"whenCreated",
		/*
		 * DO NOT JUST APPEND TO THIS LIST.
		 *
		 * In case you missed the note at the top, this list is kept
		 * in case-insensitive sorted order. In the unlikely event you
		 * need to add an attrbute, please add it in the RIGHT PLACE.
		 */
	};
	static const char * const all_attrs[] = {
		DSDB_SECRET_ATTRIBUTES,
		"*",
		NULL
	};
	static const struct ldb_val true_val = {
		.data = discard_const_p(uint8_t, "TRUE"),
		.length = 4
	};
	
	unsigned int i;
	uint32_t dsdb_flags = 0;
	struct replmd_private *replmd_private;
	enum deletion_state deletion_state, next_deletion_state;

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	/*
	 * We have to allow dbcheck to remove an object that
	 * is beyond repair, and to do so totally.  This could
	 * mean we we can get a partial object from the other
	 * DC, causing havoc, so dbcheck suggests
	 * re-replication first.  dbcheck sets both DBCHECK
	 * and RELAX in this situation.
	 */
	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)
	    && ldb_request_get_control(req, DSDB_CONTROL_DBCHECK)) {
		/* really, really remove it */
		return ldb_next_request(module, req);
	}

	tmp_ctx = talloc_new(ldb);
	if (!tmp_ctx) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (!schema) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	old_dn = ldb_dn_copy(tmp_ctx, req->op.del.dn);

	/* we need the complete msg off disk, so we can work out which
	   attributes need to be removed */
	ret = dsdb_module_search_dn(module, tmp_ctx, &res, old_dn, all_attrs,
	                            DSDB_FLAG_NEXT_MODULE |
	                            DSDB_SEARCH_SHOW_RECYCLED |
				    DSDB_SEARCH_REVEAL_INTERNALS |
				    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT, req);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "repmd_delete: Failed to %s %s, because we failed to find it: %s",
				       re_delete ? "re-delete" : "delete",
				       ldb_dn_get_linearized(old_dn),
				       ldb_errstring(ldb_module_get_ctx(module)));
		talloc_free(tmp_ctx);
		return ret;
	}
	old_msg = res->msgs[0];

	replmd_deletion_state(module, old_msg,
			      &deletion_state,
			      &next_deletion_state);

	/* This supports us noticing an incoming isDeleted and acting on it */
	if (re_delete) {
		SMB_ASSERT(deletion_state > OBJECT_NOT_DELETED);
		next_deletion_state = deletion_state;
	}

	if (next_deletion_state == OBJECT_REMOVED) {
		/*
		 * We have to prevent objects being deleted, even if
		 * the administrator really wants them gone, as
		 * without the tombstone, we can get a partial object
		 * from the other DC, causing havoc.
		 *
		 * The only other valid case is when the 180 day
		 * timeout has expired, when relax is specified.
		 */
		if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)) {
			/* it is already deleted - really remove it this time */
			talloc_free(tmp_ctx);
			return ldb_next_request(module, req);
		}

		ldb_asprintf_errstring(ldb, "Refusing to delete tombstone object %s.  "
				       "This check is to prevent corruption of the replicated state.",
				       ldb_dn_get_linearized(old_msg->dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	rdn_name = ldb_dn_get_rdn_name(old_dn);
	rdn_value = ldb_dn_get_rdn_val(old_dn);
	if ((rdn_name == NULL) || (rdn_value == NULL)) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->dn = old_dn;

	/* consider the SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE flag */
	disallow_move_on_delete =
		(ldb_msg_find_attr_as_int(old_msg, "systemFlags", 0)
		 & SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE);

	/* work out where we will be renaming this object to */
	if (!disallow_move_on_delete) {
		struct ldb_dn *deleted_objects_dn;
		ret = dsdb_get_deleted_objects_dn(ldb, tmp_ctx, old_dn,
						  &deleted_objects_dn);

		/*
		 * We should not move objects if we can't find the
		 * deleted objects DN.  Not moving (or otherwise
		 * harming) the Deleted Objects DN itself is handled
		 * in the caller.
		 */
		if (re_delete && (ret != LDB_SUCCESS)) {
			new_dn = ldb_dn_get_parent(tmp_ctx, old_dn);
			if (new_dn == NULL) {
				ldb_module_oom(module);
				talloc_free(tmp_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
		} else if (ret != LDB_SUCCESS) {
			/* this is probably an attempted delete on a partition
			 * that doesn't allow delete operations, such as the
			 * schema partition */
			ldb_asprintf_errstring(ldb, "No Deleted Objects container for DN %s",
					       ldb_dn_get_linearized(old_dn));
			talloc_free(tmp_ctx);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		} else {
			new_dn = deleted_objects_dn;
		}
	} else {
		new_dn = ldb_dn_get_parent(tmp_ctx, old_dn);
		if (new_dn == NULL) {
			ldb_module_oom(module);
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* get the objects GUID from the search we just did */
	guid = samdb_result_guid(old_msg, "objectGUID");

	if (deletion_state == OBJECT_NOT_DELETED) {
		struct ldb_message_element *is_deleted_el;

		ret = replmd_make_deleted_child_dn(tmp_ctx,
						   ldb,
						   new_dn,
						   rdn_name, rdn_value,
						   guid);

		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}

		ret = ldb_msg_add_value(msg, "isDeleted", &true_val,
					&is_deleted_el);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, __location__
					       ": Failed to add isDeleted string to the msg");
			talloc_free(tmp_ctx);
			return ret;
		}
		is_deleted_el->flags = LDB_FLAG_MOD_REPLACE;
	} else {
		/*
		 * No matter what has happened with other renames etc, try again to
		 * get this to be under the deleted DN. See MS-DRSR 5.160 RemoveObj
		 */

		struct ldb_dn *rdn = ldb_dn_copy(tmp_ctx, old_dn);
		retb = ldb_dn_remove_base_components(rdn, ldb_dn_get_comp_num(rdn) - 1);
		if (!retb) {
			ldb_asprintf_errstring(ldb, __location__
					       ": Unable to add a prepare rdn of %s",
					       ldb_dn_get_linearized(rdn));
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		SMB_ASSERT(ldb_dn_get_comp_num(rdn) == 1);

		retb = ldb_dn_add_child(new_dn, rdn);
		if (!retb) {
			ldb_asprintf_errstring(ldb, __location__
					       ": Unable to add rdn %s to base dn: %s",
					       ldb_dn_get_linearized(rdn),
					       ldb_dn_get_linearized(new_dn));
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/*
	  now we need to modify the object in the following ways:

	  - add isDeleted=TRUE
	  - update rDN and name, with new rDN
	  - remove linked attributes
	  - remove objectCategory and sAMAccountType
	  - remove attribs not on the preserved list
	     - preserved if in above list, or is rDN
	  - remove all linked attribs from this object
	  - remove all links from other objects to this object
	    (note we use the backlinks to do this, so we won't find one-way
	     links that still point to this object, or deactivated two-way
	     links, i.e. 'member' after the user has been removed from the
	     group)
	  - add lastKnownParent
	  - update replPropertyMetaData?

	  see MS-ADTS "Tombstone Requirements" section 3.1.1.5.5.1.1
	 */

	if (deletion_state == OBJECT_NOT_DELETED) {
		struct ldb_dn *parent_dn = ldb_dn_get_parent(tmp_ctx, old_dn);
		char *parent_dn_str = NULL;
		struct ldb_message_element *p_el;

		/* we need the storage form of the parent GUID */
		ret = dsdb_module_search_dn(module, tmp_ctx, &parent_res,
					    parent_dn, NULL,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
					    DSDB_SEARCH_REVEAL_INTERNALS|
					    DSDB_SEARCH_SHOW_RECYCLED, req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "repmd_delete: Failed to %s %s, "
					       "because we failed to find it's parent (%s): %s",
					       re_delete ? "re-delete" : "delete",
					       ldb_dn_get_linearized(old_dn),
					       ldb_dn_get_linearized(parent_dn),
					       ldb_errstring(ldb_module_get_ctx(module)));
			talloc_free(tmp_ctx);
			return ret;
		}

		/*
		 * Now we can use the DB version,
		 * it will have the extended DN info in it
		 */
		parent_dn = parent_res->msgs[0]->dn;
		parent_dn_str = ldb_dn_get_extended_linearized(tmp_ctx,
							       parent_dn,
							       1);
		if (parent_dn_str == NULL) {
			talloc_free(tmp_ctx);
			return ldb_module_oom(module);
		}

		ret = ldb_msg_add_steal_string(msg, "lastKnownParent",
					       parent_dn_str);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, __location__
					       ": Failed to add lastKnownParent "
					       "string when deleting %s",
					       ldb_dn_get_linearized(old_dn));
			talloc_free(tmp_ctx);
			return ret;
		}
		p_el = ldb_msg_find_element(msg,
					    "lastKnownParent");
		if (p_el == NULL) {
			talloc_free(tmp_ctx);
			return ldb_module_operr(module);
		}
		p_el->flags = LDB_FLAG_MOD_REPLACE;

		if (next_deletion_state == OBJECT_DELETED) {
			ret = ldb_msg_add_value(msg, "msDS-LastKnownRDN", rdn_value, NULL);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb, __location__
						       ": Failed to add msDS-LastKnownRDN "
						       "string when deleting %s",
						       ldb_dn_get_linearized(old_dn));
				talloc_free(tmp_ctx);
				return ret;
			}
			p_el = ldb_msg_find_element(msg,
						    "msDS-LastKnownRDN");
			if (p_el == NULL) {
				talloc_free(tmp_ctx);
				return ldb_module_operr(module);
			}
			p_el->flags = LDB_FLAG_MOD_ADD;
		}
	}

	switch (next_deletion_state) {

	case OBJECT_RECYCLED:
	case OBJECT_TOMBSTONE:

		/*
		 * MS-ADTS 3.1.1.5.5.1.1 Tombstone Requirements
		 * describes what must be removed from a tombstone
		 * object
		 *
		 * MS-ADTS 3.1.1.5.5.1.3 Recycled-Object Requirements
		 * describes what must be removed from a recycled
		 * object
		 *
		 */

		/*
		 * we also mark it as recycled, meaning this object can't be
		 * recovered (we are stripping its attributes).
		 * This is done only if we have this schema object of course ...
		 * This behavior is identical to the one of Windows 2008R2 which
		 * always set the isRecycled attribute, even if the recycle-bin is
		 * not activated and what ever the forest level is.
		 */
		if (dsdb_attribute_by_lDAPDisplayName(schema, "isRecycled") != NULL) {
			struct ldb_message_element *is_recycled_el;

			ret = ldb_msg_add_value(msg, "isRecycled", &true_val,
						&is_recycled_el);
			if (ret != LDB_SUCCESS) {
				DEBUG(0,(__location__ ": Failed to add isRecycled string to the msg\n"));
				ldb_module_oom(module);
				talloc_free(tmp_ctx);
				return ret;
			}
			is_recycled_el->flags = LDB_FLAG_MOD_REPLACE;
		}

		replmd_private = talloc_get_type(ldb_module_get_private(module),
						 struct replmd_private);
		/* work out which of the old attributes we will be removing */
		for (i=0; i<old_msg->num_elements; i++) {
			const struct dsdb_attribute *sa;
			el = &old_msg->elements[i];
			sa = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
			if (!sa) {
				const char *old_dn_str
					= ldb_dn_get_linearized(old_dn);

				ldb_asprintf_errstring(ldb,
						       __location__
						       ": Attribute %s "
						       "not found in schema "
						       "when deleting %s. "
						       "Existing record is invalid",
						       el->name,
						       old_dn_str);
				talloc_free(tmp_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			if (ldb_attr_cmp(el->name, rdn_name) == 0) {
				/* don't remove the rDN */
				continue;
			}

			if (sa->linkID & 1) {
				bool caller_should_vanish = false;
				/*
				 * we have a backlink in this object
				 * that needs to be removed. We're not
				 * allowed to remove it directly
				 * however, so we instead setup a
				 * modify to delete the corresponding
				 * forward link
				 */
				ret = replmd_delete_remove_link(module, schema,
								replmd_private,
								old_dn, &guid,
								el, sa, req,
								&caller_should_vanish);
				if (ret != LDB_SUCCESS) {
					const char *old_dn_str
						= ldb_dn_get_linearized(old_dn);
					ldb_asprintf_errstring(ldb,
							       __location__
							       ": Failed to remove backlink of "
							       "%s when deleting %s: %s",
							       el->name,
							       old_dn_str,
							       ldb_errstring(ldb));
					talloc_free(tmp_ctx);
					return LDB_ERR_OPERATIONS_ERROR;
				}

				if (caller_should_vanish == false) {
					/*
					 * now we continue, which means we
					 * won't remove this backlink
					 * directly
					 */
					continue;
				}

				/*
				 * Otherwise vanish the link, we are
				 * out of sync and the controlling
				 * object does not have the source
				 * link any more
				 */

				dsdb_flags |= DSDB_REPLMD_VANISH_LINKS;

			} else if (sa->linkID == 0) {
				const char * const *attr = NULL;
				if (sa->searchFlags & SEARCH_FLAG_PRESERVEONDELETE) {
					continue;
				}
				BINARY_ARRAY_SEARCH_V(preserved_attrs,
						      ARRAY_SIZE(preserved_attrs),
						      el->name,
						      ldb_attr_cmp,
						      attr);
				/*
				 * If we are preserving, do not do the
				 * ldb_msg_add_empty() below, continue
				 * to the next element
				 */
				if (attr != NULL) {
					continue;
				}
			} else {
				/*
				 * Ensure that we tell the modification to vanish any linked
				 * attributes (not simply mark them as isDeleted = TRUE)
				 */
				dsdb_flags |= DSDB_REPLMD_VANISH_LINKS;
			}
			ret = ldb_msg_add_empty(msg, el->name, LDB_FLAG_MOD_DELETE, &el);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				ldb_module_oom(module);
				return ret;
			}
		}

		break;

	case OBJECT_DELETED:
		/*
		 * MS-ADTS 3.1.1.5.5.1.2 Deleted-Object Requirements
		 * describes what must be removed from a deleted
		 * object
		 */

		ret = ldb_msg_add_empty(msg, "objectCategory", LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			ldb_module_oom(module);
			return ret;
		}

		ret = ldb_msg_add_empty(msg, "sAMAccountType", LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			ldb_module_oom(module);
			return ret;
		}

		break;

	default:
		break;
	}

	if (deletion_state == OBJECT_NOT_DELETED) {
		const struct dsdb_attribute *sa;

		/* work out what the new rdn value is, for updating the
		   rDN and name fields */
		new_rdn_value = ldb_dn_get_rdn_val(new_dn);
		if (new_rdn_value == NULL) {
			talloc_free(tmp_ctx);
			return ldb_operr(ldb);
		}

		sa = dsdb_attribute_by_lDAPDisplayName(schema, rdn_name);
		if (!sa) {
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_msg_add_value(msg, sa->lDAPDisplayName, new_rdn_value,
					&el);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		el->flags = LDB_FLAG_MOD_REPLACE;

		el = ldb_msg_find_element(old_msg, "name");
		if (el) {
			ret = ldb_msg_add_value(msg, "name", new_rdn_value, &el);
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}
			el->flags = LDB_FLAG_MOD_REPLACE;
		}
	}

	/*
	 * TODO: Per MS-DRSR 5.160 RemoveObj we should remove links directly, not as an originating update!
	 *
	 */

	/*
	 * No matter what has happned with other renames, try again to
	 * get this to be under the deleted DN.
	 */
	if (strcmp(ldb_dn_get_linearized(old_dn), ldb_dn_get_linearized(new_dn)) != 0) {
		/* now rename onto the new DN */
		ret = dsdb_module_rename(module, old_dn, new_dn, DSDB_FLAG_NEXT_MODULE, req);
		if (ret != LDB_SUCCESS){
			DEBUG(0,(__location__ ": Failed to rename object from '%s' to '%s' - %s\n",
				 ldb_dn_get_linearized(old_dn),
				 ldb_dn_get_linearized(new_dn),
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return ret;
		}
		msg->dn = new_dn;
	}

	ret = dsdb_module_modify(module, msg, dsdb_flags|DSDB_FLAG_OWN_MODULE, req);
	if (ret != LDB_SUCCESS) {
		char *s = NULL;
		/*
		 * This should not fail, so be quite verbose in the
		 * error handling if it fails
		 */
		if (strcmp(ldb_dn_get_linearized(old_dn),
			   ldb_dn_get_linearized(new_dn)) != 0) {
			DBG_NOTICE("Failure to handle '%s' of object %s "
				   "after successful rename to %s.  "
				   "Error during tombstone modificaton was: %s\n",
				   re_delete ? "re-delete" : "delete",
				   ldb_dn_get_linearized(new_dn),
				   ldb_dn_get_linearized(old_dn),
				   ldb_errstring(ldb));
		} else {
			DBG_NOTICE("Failure to handle '%s' of object %s. "
				   "Error during tombstone modificaton was: %s\n",
				   re_delete ? "re-delete" : "delete",
				   ldb_dn_get_linearized(new_dn),
				   ldb_errstring(ldb));
		}
		s = ldb_ldif_message_redacted_string(ldb_module_get_ctx(module),
						     tmp_ctx,
						     LDB_CHANGETYPE_MODIFY,
						     msg);

		DBG_INFO("Failed tombstone modify%s was:\n%s\n",
			 (dsdb_flags & DSDB_REPLMD_VANISH_LINKS) ?
			 " with VANISH_LINKS" : "",
			 s);
		ldb_asprintf_errstring(ldb,
				       "replmd_delete: Failed to modify"
				       " object %s in '%s' - %s",
				       ldb_dn_get_linearized(old_dn),
				       re_delete ? "re-delete" : "delete",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_free(tmp_ctx);

	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}

static int replmd_delete(struct ldb_module *module, struct ldb_request *req)
{
	return replmd_delete_internals(module, req, false);
}


static int replmd_replicated_request_error(struct replmd_replicated_request *ar, int ret)
{
	return ret;
}

static int replmd_replicated_request_werror(struct replmd_replicated_request *ar, WERROR status)
{
	int ret = LDB_ERR_OTHER;
	/* TODO: do some error mapping */

	/* Let the caller know the full WERROR */
	ar->objs->error = status;

	return ret;
}


static struct replPropertyMetaData1 *
replmd_replPropertyMetaData1_find_attid(struct replPropertyMetaDataBlob *md_blob,
                                        enum drsuapi_DsAttributeId attid)
{
	uint32_t i;
	struct replPropertyMetaDataCtr1 *rpmd_ctr = &md_blob->ctr.ctr1;

	for (i = 0; i < rpmd_ctr->count; i++) {
		if (rpmd_ctr->array[i].attid == attid) {
			return &rpmd_ctr->array[i];
		}
	}
	return NULL;
}


/*
   return true if an update is newer than an existing entry
   see section 5.11 of MS-ADTS
*/
static bool replmd_update_is_newer(const struct GUID *current_invocation_id,
				   const struct GUID *update_invocation_id,
				   uint32_t current_version,
				   uint32_t update_version,
				   NTTIME current_change_time,
				   NTTIME update_change_time)
{
	if (update_version != current_version) {
		return update_version > current_version;
	}
	if (update_change_time != current_change_time) {
		return update_change_time > current_change_time;
	}
	return GUID_compare(update_invocation_id, current_invocation_id) > 0;
}

static bool replmd_replPropertyMetaData1_is_newer(struct replPropertyMetaData1 *cur_m,
						  struct replPropertyMetaData1 *new_m)
{
	return replmd_update_is_newer(&cur_m->originating_invocation_id,
				      &new_m->originating_invocation_id,
				      cur_m->version,
				      new_m->version,
				      cur_m->originating_change_time,
				      new_m->originating_change_time);
}

static bool replmd_replPropertyMetaData1_new_should_be_taken(uint32_t dsdb_repl_flags,
							     struct replPropertyMetaData1 *cur_m,
							     struct replPropertyMetaData1 *new_m)
{
	bool cmp;

	/*
	 * If the new replPropertyMetaData entry for this attribute is
	 * not provided (this happens in the case where we look for
	 * ATTID_name, but the name was not changed), then the local
	 * state is clearly still current, as the remote
	 * server didn't send it due to being older the high watermark
	 * USN we sent.
	 */
	if (new_m == NULL) {
		return false;
	}

	if (dsdb_repl_flags & DSDB_REPL_FLAG_PRIORITISE_INCOMING) {
		/*
		 * if we compare equal then do an
		 * update. This is used when a client
		 * asks for a FULL_SYNC, and can be
		 * used to recover a corrupt
		 * replica.
		 *
		 * This call is a bit tricky, what we
		 * are doing it turning the 'is_newer'
		 * call into a 'not is older' by
		 * swapping cur_m and new_m, and negating the
		 * outcome.
		 */
		cmp = !replmd_replPropertyMetaData1_is_newer(new_m,
							     cur_m);
	} else {
		cmp = replmd_replPropertyMetaData1_is_newer(cur_m,
							    new_m);
	}
	return cmp;
}


/*
  form a DN for a deleted (DEL:) or conflict (CNF:) DN
 */
static int replmd_make_prefix_child_dn(TALLOC_CTX *tmp_ctx,
				       struct ldb_context *ldb,
				       struct ldb_dn *dn,
				       const char *four_char_prefix,
				       const char *rdn_name,
				       const struct ldb_val *rdn_value,
				       struct GUID guid)
{
	struct ldb_val deleted_child_rdn_val;
	struct GUID_txt_buf guid_str;
	int ret;
	bool retb;

	GUID_buf_string(&guid, &guid_str);

	retb = ldb_dn_add_child_fmt(dn, "X=Y");
	if (!retb) {
		ldb_asprintf_errstring(ldb, __location__
				       ": Unable to add a formatted child to dn: %s",
				       ldb_dn_get_linearized(dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * TODO: Per MS-ADTS 3.1.1.5.5 Delete Operation
	 * we should truncate this value to ensure the RDN is not more than 255 chars.
	 *
	 * However we MS-ADTS 3.1.1.5.1.2 Naming Constraints indicates that:
	 *
	 * "Naming constraints are not enforced for replicated
	 * updates." so this is safe and we don't have to work out not
	 * splitting a UTF8 char right now.
	 */
	deleted_child_rdn_val = ldb_val_dup(tmp_ctx, rdn_value);

	/*
	 * sizeof(guid_str.buf) will always be longer than
	 * strlen(guid_str.buf) but we allocate using this and
	 * waste the trailing bytes to avoid scaring folks
	 * with memcpy() using strlen() below
	 */

	deleted_child_rdn_val.data
		= talloc_realloc(tmp_ctx, deleted_child_rdn_val.data,
				 uint8_t,
				 rdn_value->length + 5
				 + sizeof(guid_str.buf));
	if (!deleted_child_rdn_val.data) {
		ldb_asprintf_errstring(ldb, __location__
				       ": Unable to add a formatted child to dn: %s",
				       ldb_dn_get_linearized(dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	deleted_child_rdn_val.length =
		rdn_value->length + 5
		+ strlen(guid_str.buf);

	SMB_ASSERT(deleted_child_rdn_val.length <
		   talloc_get_size(deleted_child_rdn_val.data));

	/*
	 * talloc won't allocate more than 256MB so we can't
	 * overflow but just to be sure
	 */
	if (deleted_child_rdn_val.length < rdn_value->length) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	deleted_child_rdn_val.data[rdn_value->length] = 0x0a;
	memcpy(&deleted_child_rdn_val.data[rdn_value->length + 1],
	       four_char_prefix, 4);
	memcpy(&deleted_child_rdn_val.data[rdn_value->length + 5],
	       guid_str.buf,
	       sizeof(guid_str.buf));

	/* Now set the value into the RDN, without parsing it */
	ret = ldb_dn_set_component(
		dn,
		0,
		rdn_name,
		deleted_child_rdn_val);

	return ret;
}


/*
  form a conflict DN
 */
static struct ldb_dn *replmd_conflict_dn(TALLOC_CTX *mem_ctx,
					 struct ldb_context *ldb,
					 struct ldb_dn *dn,
					 struct GUID *guid)
{
	const struct ldb_val *rdn_val;
	const char *rdn_name;
	struct ldb_dn *new_dn;
	int ret;

	rdn_val = ldb_dn_get_rdn_val(dn);
	rdn_name = ldb_dn_get_rdn_name(dn);
	if (!rdn_val || !rdn_name) {
		return NULL;
	}

	new_dn = ldb_dn_get_parent(mem_ctx, dn);
	if (!new_dn) {
		return NULL;
	}

	ret = replmd_make_prefix_child_dn(mem_ctx,
					  ldb, new_dn,
					  "CNF:",
					  rdn_name,
					  rdn_val,
					  *guid);
	if (ret != LDB_SUCCESS) {
		return NULL;
	}
	return new_dn;
}

/*
  form a deleted DN
 */
static int replmd_make_deleted_child_dn(TALLOC_CTX *tmp_ctx,
					struct ldb_context *ldb,
					struct ldb_dn *dn,
					const char *rdn_name,
					const struct ldb_val *rdn_value,
					struct GUID guid)
{
	return replmd_make_prefix_child_dn(tmp_ctx,
					   ldb, dn,
					   "DEL:",
					   rdn_name,
					   rdn_value,
					   guid);
}


/*
  perform a modify operation which sets the rDN and name attributes to
  their current values. This has the effect of changing these
  attributes to have been last updated by the current DC. This is
  needed to ensure that renames performed as part of conflict
  resolution are propagated to other DCs
 */
static int replmd_name_modify(struct replmd_replicated_request *ar,
			      struct ldb_request *req, struct ldb_dn *dn)
{
	struct ldb_message *msg;
	const char *rdn_name;
	const struct ldb_val *rdn_val;
	const struct dsdb_attribute *rdn_attr;
	int ret;

	msg = ldb_msg_new(req);
	if (msg == NULL) {
		goto failed;
	}
	msg->dn = dn;

	rdn_name = ldb_dn_get_rdn_name(dn);
	if (rdn_name == NULL) {
		goto failed;
	}

	/* normalize the rdn attribute name */
	rdn_attr = dsdb_attribute_by_lDAPDisplayName(ar->schema, rdn_name);
	if (rdn_attr == NULL) {
		goto failed;
	}
	rdn_name = rdn_attr->lDAPDisplayName;

	rdn_val = ldb_dn_get_rdn_val(dn);
	if (rdn_val == NULL) {
		goto failed;
	}

	if (ldb_msg_add_empty(msg, rdn_name, LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		goto failed;
	}
	if (ldb_msg_add_value(msg, rdn_name, rdn_val, NULL) != 0) {
		goto failed;
	}
	if (ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		goto failed;
	}
	if (ldb_msg_add_value(msg, "name", rdn_val, NULL) != 0) {
		goto failed;
	}

	/*
	 * We have to mark this as a replicated update otherwise
	 * schema_data may reject a rename in the schema partition
	 */

	ret = dsdb_module_modify(ar->module, msg,
				 DSDB_FLAG_OWN_MODULE|DSDB_FLAG_REPLICATED_UPDATE,
				 req);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to modify rDN/name of DN being DRS renamed '%s' - %s",
			 ldb_dn_get_linearized(dn),
			 ldb_errstring(ldb_module_get_ctx(ar->module))));
		return ret;
	}

	talloc_free(msg);

	return LDB_SUCCESS;

failed:
	talloc_free(msg);
	DEBUG(0,(__location__ ": Failed to setup modify rDN/name of DN being DRS renamed '%s'",
		 ldb_dn_get_linearized(dn)));
	return LDB_ERR_OPERATIONS_ERROR;
}


/*
  callback for conflict DN handling where we have renamed the incoming
  record. After renaming it, we need to ensure the change of name and
  rDN for the incoming record is seen as an originating update by this DC.

  This also handles updating lastKnownParent for entries sent to lostAndFound
 */
static int replmd_op_name_modify_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar =
		talloc_get_type_abort(req->context, struct replmd_replicated_request);
	struct ldb_dn *conflict_dn = NULL;
	int ret;

	if (ares->error != LDB_SUCCESS) {
		/* call the normal callback for everything except success */
		return replmd_op_callback(req, ares);
	}

	switch (req->operation) {
	case LDB_ADD:
		conflict_dn = req->op.add.message->dn;
		break;
	case LDB_MODIFY:
		conflict_dn = req->op.mod.message->dn;
		break;
	default:
		smb_panic("replmd_op_name_modify_callback called in unknown circumstances");
	}

	/* perform a modify of the rDN and name of the record */
	ret = replmd_name_modify(ar, req, conflict_dn);
	if (ret != LDB_SUCCESS) {
		ares->error = ret;
		return replmd_op_callback(req, ares);
	}

	if (ar->objs->objects[ar->index_current].last_known_parent) {
		struct ldb_message *msg = ldb_msg_new(req);
		if (msg == NULL) {
			ldb_module_oom(ar->module);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		msg->dn = req->op.add.message->dn;

		ret = ldb_msg_add_steal_string(msg, "lastKnownParent",
					       ldb_dn_get_extended_linearized(msg, ar->objs->objects[ar->index_current].last_known_parent, 1));
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to add lastKnownParent string to the msg\n"));
			ldb_module_oom(ar->module);
			return ret;
		}
		msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;

		ret = dsdb_module_modify(ar->module, msg, DSDB_FLAG_OWN_MODULE, req);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to modify lastKnownParent of lostAndFound DN '%s' - %s",
				 ldb_dn_get_linearized(msg->dn),
				 ldb_errstring(ldb_module_get_ctx(ar->module))));
			return ret;
		}
		TALLOC_FREE(msg);
	}

	return replmd_op_callback(req, ares);
}



/*
 * A helper for replmd_op_possible_conflict_callback() and
 * replmd_replicated_handle_rename()
 */
static int incoming_dn_should_be_renamed(TALLOC_CTX *mem_ctx,
					 struct replmd_replicated_request *ar,
					 struct ldb_dn *conflict_dn,
					 struct ldb_result **res,
					 bool *rename_incoming_record)
{
	int ret;
	bool rodc;
	enum ndr_err_code ndr_err;
	const struct ldb_val *omd_value = NULL;
	struct replPropertyMetaDataBlob omd, *rmd = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(ar->module);
	const char *attrs[] = { "replPropertyMetaData", "objectGUID", NULL };
	struct replPropertyMetaData1 *omd_name = NULL;
	struct replPropertyMetaData1 *rmd_name = NULL;
	struct ldb_message *msg = NULL;

	ret = samdb_rodc(ldb, &rodc);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(
			ldb,
			"Failed to determine if we are an RODC when attempting "
			"to form conflict DN: %s",
			ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (rodc) {
		/*
		 * We are on an RODC, or were a GC for this
		 * partition, so we have to fail this until
		 * someone who owns the partition sorts it
		 * out
		 */
		ldb_asprintf_errstring(
			ldb,
			"Conflict adding object '%s' from incoming replication "
			"but we are read only for the partition.  \n"
			" - We must fail the operation until a master for this "
			"partition resolves the conflict",
			ldb_dn_get_linearized(conflict_dn));
		 return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * first we need the replPropertyMetaData attribute from the
	 * old record
	 */
	ret = dsdb_module_search_dn(ar->module, mem_ctx, res, conflict_dn,
				    attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_SEARCH_SHOW_DELETED |
				    DSDB_SEARCH_SHOW_RECYCLED, ar->req);
	if (ret != LDB_SUCCESS) {
		DBG_ERR(__location__
			": Unable to find object for conflicting record '%s'\n",
			ldb_dn_get_linearized(conflict_dn));
		 return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = (*res)->msgs[0];
	omd_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
	if (omd_value == NULL) {
		DBG_ERR(__location__
			": Unable to find replPropertyMetaData for conflicting "
			"record '%s'\n",
			ldb_dn_get_linearized(conflict_dn));
		 return LDB_ERR_OPERATIONS_ERROR;
	}

	ndr_err = ndr_pull_struct_blob(
		omd_value, msg, &omd,
		(ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR(__location__
			": Failed to parse old replPropertyMetaData for %s\n",
			ldb_dn_get_linearized(conflict_dn));
		 return LDB_ERR_OPERATIONS_ERROR;
	}

	rmd = ar->objs->objects[ar->index_current].meta_data;

	/*
	 * we decide which is newer based on the RPMD on the name
	 * attribute.  See [MS-DRSR] ResolveNameConflict.
	 *
	 * We expect omd_name to be present, as this is from a local
	 * search, but while rmd_name should have been given to us by
	 * the remote server, if it is missing we just prefer the
	 * local name in
	 * replmd_replPropertyMetaData1_new_should_be_taken()
	 */
	rmd_name = replmd_replPropertyMetaData1_find_attid(rmd,
							   DRSUAPI_ATTID_name);
	omd_name = replmd_replPropertyMetaData1_find_attid(&omd,
							   DRSUAPI_ATTID_name);
	if (!omd_name) {
		DBG_ERR(__location__
			": Failed to find name attribute in "
			"local LDB replPropertyMetaData for %s\n",
			 ldb_dn_get_linearized(conflict_dn));
		 return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Should we preserve the current record, and so rename the
	 * incoming record to be a conflict?
	 */
	*rename_incoming_record =
		!replmd_replPropertyMetaData1_new_should_be_taken(
			(ar->objs->dsdb_repl_flags &
			 DSDB_REPL_FLAG_PRIORITISE_INCOMING),
			omd_name, rmd_name);

	return LDB_SUCCESS;
}


/*
  callback for replmd_replicated_apply_add()
  This copes with the creation of conflict records in the case where
  the DN exists, but with a different objectGUID
 */
static int replmd_op_possible_conflict_callback(struct ldb_request *req, struct ldb_reply *ares, int (*callback)(struct ldb_request *req, struct ldb_reply *ares))
{
	struct ldb_dn *conflict_dn;
	struct replmd_replicated_request *ar =
		talloc_get_type_abort(req->context, struct replmd_replicated_request);
	struct ldb_result *res;
	int ret;
	bool rename_incoming_record;
	struct ldb_message *msg;
	struct ldb_request *down_req = NULL;

	/* call the normal callback for success */
	if (ares->error == LDB_SUCCESS) {
		return callback(req, ares);
	}

	/*
	 * we have a conflict, and need to decide if we will keep the
	 * new record or the old record
	 */

	msg = ar->objs->objects[ar->index_current].msg;
	conflict_dn = msg->dn;

	/* For failures other than conflicts, fail the whole operation here */
	if (ares->error != LDB_ERR_ENTRY_ALREADY_EXISTS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ar->module), "Failed to locally apply remote add of %s: %s",
				       ldb_dn_get_linearized(conflict_dn),
				       ldb_errstring(ldb_module_get_ctx(ar->module)));

		return ldb_module_done(ar->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}


	ret = incoming_dn_should_be_renamed(req, ar, conflict_dn, &res,
					    &rename_incoming_record);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (rename_incoming_record) {
		struct GUID guid;
		struct ldb_dn *new_dn;

		guid = samdb_result_guid(msg, "objectGUID");
		if (GUID_all_zero(&guid)) {
			DEBUG(0,(__location__ ": Failed to find objectGUID for conflicting incoming record %s\n",
				 ldb_dn_get_linearized(conflict_dn)));
			goto failed;
		}
		new_dn = replmd_conflict_dn(req,
					    ldb_module_get_ctx(ar->module),
					    conflict_dn, &guid);
		if (new_dn == NULL) {
			DEBUG(0,(__location__ ": Failed to form conflict DN for %s\n",
				 ldb_dn_get_linearized(conflict_dn)));
			goto failed;
		}

		DEBUG(2,(__location__ ": Resolving conflict record via incoming rename '%s' -> '%s'\n",
			 ldb_dn_get_linearized(conflict_dn), ldb_dn_get_linearized(new_dn)));

		/* re-submit the request, but with the new DN */
		callback = replmd_op_name_modify_callback;
		msg->dn = new_dn;
	} else {
		/* we are renaming the existing record */
		struct GUID guid;
		struct ldb_dn *new_dn;

		guid = samdb_result_guid(res->msgs[0], "objectGUID");
		if (GUID_all_zero(&guid)) {
			DEBUG(0,(__location__ ": Failed to find objectGUID for existing conflict record %s\n",
				 ldb_dn_get_linearized(conflict_dn)));
			goto failed;
		}

		new_dn = replmd_conflict_dn(req,
					    ldb_module_get_ctx(ar->module),
					    conflict_dn, &guid);
		if (new_dn == NULL) {
			DEBUG(0,(__location__ ": Failed to form conflict DN for %s\n",
				 ldb_dn_get_linearized(conflict_dn)));
			goto failed;
		}

		DEBUG(2,(__location__ ": Resolving conflict record via existing-record rename '%s' -> '%s'\n",
			 ldb_dn_get_linearized(conflict_dn), ldb_dn_get_linearized(new_dn)));

		ret = dsdb_module_rename(ar->module, conflict_dn, new_dn,
					 DSDB_FLAG_OWN_MODULE, req);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to rename conflict dn '%s' to '%s' - %s\n",
				 ldb_dn_get_linearized(conflict_dn),
				 ldb_dn_get_linearized(new_dn),
				 ldb_errstring(ldb_module_get_ctx(ar->module))));
			goto failed;
		}

		/*
		 * now we need to ensure that the rename is seen as an
		 * originating update. We do that with a modify.
		 */
		ret = replmd_name_modify(ar, req, new_dn);
		if (ret != LDB_SUCCESS) {
			goto failed;
		}

		DEBUG(2,(__location__ ": With conflicting record renamed, re-apply replicated creation of '%s'\n",
			 ldb_dn_get_linearized(req->op.add.message->dn)));
	}

	ret = ldb_build_add_req(&down_req,
				ldb_module_get_ctx(ar->module),
				req,
				msg,
				ar->controls,
				ar,
				callback,
				req);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}
	LDB_REQ_SET_LOCATION(down_req);

	/* current partition control needed by "repmd_op_callback" */
	ret = ldb_request_add_control(down_req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	if (ar->objs->dsdb_repl_flags & DSDB_REPL_FLAG_PARTIAL_REPLICA) {
		/* this tells the partition module to make it a
		   partial replica if creating an NC */
		ret = ldb_request_add_control(down_req,
					      DSDB_CONTROL_PARTIAL_REPLICA,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			return replmd_replicated_request_error(ar, ret);
		}
	}

	/*
	 * Finally we re-run the add, otherwise the new record won't
	 * exist, as we are here because of that exact failure!
	 */
	return ldb_next_request(ar->module, down_req);
failed:

	/* on failure make the caller get the error. This means
	 * replication will stop with an error, but there is not much
	 * else we can do.
	 */
	if (ret == LDB_SUCCESS) {
		ret = LDB_ERR_OPERATIONS_ERROR;
	}
	return ldb_module_done(ar->req, NULL, NULL,
			       ret);
}

/*
  callback for replmd_replicated_apply_add()
  This copes with the creation of conflict records in the case where
  the DN exists, but with a different objectGUID
 */
static int replmd_op_add_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar =
		talloc_get_type_abort(req->context, struct replmd_replicated_request);

	if (ar->objs->objects[ar->index_current].last_known_parent) {
		/* This is like a conflict DN, where we put the object in LostAndFound
		   see MS-DRSR 4.1.10.6.10 FindBestParentObject */
		return replmd_op_possible_conflict_callback(req, ares, replmd_op_name_modify_callback);
	}

	return replmd_op_possible_conflict_callback(req, ares, replmd_op_callback);
}

/*
  this is called when a new object comes in over DRS
 */
static int replmd_replicated_apply_add(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *md;
	struct ldb_val md_value;
	unsigned int i;
	int ret;
	bool remote_isDeleted = false;
	bool is_schema_nc;
	NTTIME now;
	time_t t = time(NULL);
	const struct ldb_val *rdn_val;
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(ar->module),
				struct replmd_private);
	unix_to_nt_time(&now, t);

	ldb = ldb_module_get_ctx(ar->module);
	msg = ar->objs->objects[ar->index_current].msg;
	md = ar->objs->objects[ar->index_current].meta_data;
	is_schema_nc = ldb_dn_compare_base(replmd_private->schema_dn, msg->dn) == 0;

	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &ar->seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = dsdb_msg_add_guid(msg,
				&ar->objs->objects[ar->index_current].object_guid,
				"objectGUID");
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = ldb_msg_add_string(msg, "whenChanged", ar->objs->objects[ar->index_current].when_changed);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNCreated", ar->seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", ar->seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/* remove any message elements that have zero values */
	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];

		if (el->num_values == 0) {
			if (ldb_attr_cmp(msg->elements[i].name, "objectClass") == 0) {
				ldb_asprintf_errstring(ldb, __location__
						       ": empty objectClass sent on %s, aborting replication\n",
						       ldb_dn_get_linearized(msg->dn));
				return replmd_replicated_request_error(ar, LDB_ERR_OBJECT_CLASS_VIOLATION);
			}

			DEBUG(4,(__location__ ": Removing attribute %s with num_values==0\n",
				 el->name));
			ldb_msg_remove_element(msg, &msg->elements[i]);
			i--;
			continue;
		}
	}

	if (DEBUGLVL(8)) {
		struct GUID_txt_buf guid_txt;

		char *s = ldb_ldif_message_redacted_string(ldb, ar,
							   LDB_CHANGETYPE_ADD,
							   msg);
		DEBUG(8, ("DRS replication add message of %s:\n%s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid, &guid_txt),
			  s));
		talloc_free(s);
	} else if (DEBUGLVL(4)) {
		struct GUID_txt_buf guid_txt;
		DEBUG(4, ("DRS replication add DN of %s is %s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid, &guid_txt),
			  ldb_dn_get_linearized(msg->dn)));
	}
	remote_isDeleted = ldb_msg_find_attr_as_bool(msg,
						     "isDeleted", false);

	/*
	 * the meta data array is already sorted by the caller, except
	 * for the RDN, which needs to be added.
	 */


	rdn_val = ldb_dn_get_rdn_val(msg->dn);
	ret = replmd_update_rpmd_rdn_attr(ldb, msg, rdn_val, NULL,
					  md, ar, now, is_schema_nc,
					  false);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "%s: error during DRS repl ADD: %s", __func__, ldb_errstring(ldb));
		return replmd_replicated_request_error(ar, ret);
	}

	ret = replmd_replPropertyMetaDataCtr1_sort_and_verify(ldb, &md->ctr.ctr1, msg->dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "%s: error during DRS repl ADD: %s", __func__, ldb_errstring(ldb));
		return replmd_replicated_request_error(ar, ret);
	}

	for (i=0; i < md->ctr.ctr1.count; i++) {
		md->ctr.ctr1.array[i].local_usn = ar->seq_num;
	}
	ndr_err = ndr_push_struct_blob(&md_value, msg, md,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &md_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	replmd_ldb_message_sort(msg, ar->schema);

	if (!remote_isDeleted) {
		/*
		 * Ensure any local ACL inheritence is applied from
		 * the parent object.
		 *
		 * This is needed because descriptor is above
		 * repl_meta_data in the module stack, so this will
		 * not be trigered 'naturally' by the flow of
		 * operations.
		 */
		ret = dsdb_module_schedule_sd_propagation(ar->module,
							  ar->objs->partition_dn,
							  ar->objs->objects[ar->index_current].object_guid,
							  true);
		if (ret != LDB_SUCCESS) {
			return replmd_replicated_request_error(ar, ret);
		}
	}

	ar->isDeleted = remote_isDeleted;

	ret = ldb_build_add_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				replmd_op_add_callback,
				ar->req);
	LDB_REQ_SET_LOCATION(change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	/* current partition control needed by "repmd_op_callback" */
	ret = ldb_request_add_control(change_req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	if (ar->objs->dsdb_repl_flags & DSDB_REPL_FLAG_PARTIAL_REPLICA) {
		/* this tells the partition module to make it a
		   partial replica if creating an NC */
		ret = ldb_request_add_control(change_req,
					      DSDB_CONTROL_PARTIAL_REPLICA,
					      false, NULL);
		if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);
	}

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replicated_apply_search_for_parent_callback(struct ldb_request *req,
							      struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	/*
	 * The error NO_SUCH_OBJECT is not expected, unless the search
	 * base is the partition DN, and that case doesn't happen here
	 * because then we wouldn't get a parent_guid_value in any
	 * case.
	 */
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		struct ldb_message *parent_msg = ares->message;
		struct ldb_message *msg = ar->objs->objects[ar->index_current].msg;
		struct ldb_dn *parent_dn = NULL;
		int comp_num;

		if (!ldb_msg_check_string_attribute(msg, "isDeleted", "TRUE")
		    && ldb_msg_check_string_attribute(parent_msg, "isDeleted", "TRUE")) {
			/* Per MS-DRSR 4.1.10.6.10
			 * FindBestParentObject we need to move this
			 * new object under a deleted object to
			 * lost-and-found */
			struct ldb_dn *nc_root;

			ret = dsdb_find_nc_root(ldb_module_get_ctx(ar->module), msg, msg->dn, &nc_root);
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
						       "No suitable NC root found for %s.  "
						       "We need to move this object because parent object %s "
						       "is deleted, but this object is not.",
						       ldb_dn_get_linearized(msg->dn),
						       ldb_dn_get_linearized(parent_msg->dn));
				return ldb_module_done(ar->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			} else if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
						       "Unable to find NC root for %s: %s. "
						       "We need to move this object because parent object %s "
						       "is deleted, but this object is not.",
						       ldb_dn_get_linearized(msg->dn),
						       ldb_errstring(ldb_module_get_ctx(ar->module)),
						       ldb_dn_get_linearized(parent_msg->dn));
				return ldb_module_done(ar->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}

			ret = dsdb_wellknown_dn(ldb_module_get_ctx(ar->module), msg,
						nc_root,
						DS_GUID_LOSTANDFOUND_CONTAINER,
						&parent_dn);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
						       "Unable to find LostAndFound Container for %s "
						       "in partition %s: %s. "
						       "We need to move this object because parent object %s "
						       "is deleted, but this object is not.",
						       ldb_dn_get_linearized(msg->dn), ldb_dn_get_linearized(nc_root),
						       ldb_errstring(ldb_module_get_ctx(ar->module)),
						       ldb_dn_get_linearized(parent_msg->dn));
				return ldb_module_done(ar->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}
			ar->objs->objects[ar->index_current].last_known_parent
				= talloc_steal(ar->objs->objects[ar->index_current].msg, parent_msg->dn);

		} else {
			parent_dn
				= talloc_steal(ar->objs->objects[ar->index_current].msg, parent_msg->dn);

		}
		ar->objs->objects[ar->index_current].local_parent_dn = parent_dn;

		comp_num = ldb_dn_get_comp_num(msg->dn);
		if (comp_num > 1) {
			if (!ldb_dn_remove_base_components(msg->dn, comp_num - 1)) {
				talloc_free(ares);
				return ldb_module_done(ar->req, NULL, NULL, ldb_module_operr(ar->module));
			}
		}
		if (!ldb_dn_add_base(msg->dn, parent_dn)) {
			talloc_free(ares);
			return ldb_module_done(ar->req, NULL, NULL, ldb_module_operr(ar->module));
		}
		break;
	}
	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;

	case LDB_REPLY_DONE:

		if (ar->objs->objects[ar->index_current].local_parent_dn == NULL) {
			struct GUID_txt_buf str_buf;
			if (ar->search_msg != NULL) {
				ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
						       "No parent with GUID %s found for object locally known as %s",
						       GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid, &str_buf),
						       ldb_dn_get_linearized(ar->search_msg->dn));
			} else {
				ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
						       "No parent with GUID %s found for object remotely known as %s",
						       GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid, &str_buf),
						       ldb_dn_get_linearized(ar->objs->objects[ar->index_current].msg->dn));
			}

			/*
			 * This error code is really important, as it
			 * is the flag back to the callers to retry
			 * this with DRSUAPI_DRS_GET_ANC, and so get
			 * the parent objects before the child
			 * objects
			 */
			return ldb_module_done(ar->req, NULL, NULL,
					       replmd_replicated_request_werror(ar, WERR_DS_DRA_MISSING_PARENT));
		}

		if (ar->search_msg != NULL) {
			ret = replmd_replicated_apply_merge(ar);
		} else {
			ret = replmd_replicated_apply_add(ar);
		}
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ar->req, NULL, NULL, ret);
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

/*
 * Look for the parent object, so we put the new object in the right
 * place This is akin to NameObject in MS-DRSR - this routine and the
 * callbacks find the right parent name, and correct name for this
 * object
 */

static int replmd_replicated_apply_search_for_parent(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	int ret;
	char *tmp_str;
	char *filter;
	struct ldb_request *search_req;
	static const char *attrs[] = {"isDeleted", NULL};
	struct GUID_txt_buf guid_str_buf;

	ldb = ldb_module_get_ctx(ar->module);

	if (ar->objs->objects[ar->index_current].parent_guid == NULL) {
		if (ar->search_msg != NULL) {
			return replmd_replicated_apply_merge(ar);
		} else {
			return replmd_replicated_apply_add(ar);
		}
	}

	tmp_str = GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid,
				  &guid_str_buf);

	filter = talloc_asprintf(ar, "(objectGUID=%s)", tmp_str);
	if (!filter) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);

	ret = ldb_build_search_req(&search_req,
				   ldb,
				   ar,
				   ar->objs->partition_dn,
				   LDB_SCOPE_SUBTREE,
				   filter,
				   attrs,
				   NULL,
				   ar,
				   replmd_replicated_apply_search_for_parent_callback,
				   ar->req);
	LDB_REQ_SET_LOCATION(search_req);

	ret = dsdb_request_add_controls(search_req,
					DSDB_SEARCH_SHOW_RECYCLED|
					DSDB_SEARCH_SHOW_DELETED|
					DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ar->module, search_req);
}

/*
  handle renames that come in over DRS replication
 */
static int replmd_replicated_handle_rename(struct replmd_replicated_request *ar,
					   struct ldb_message *msg,
					   struct ldb_request *parent,
					   bool *renamed_to_conflict)
{
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(msg);
	struct ldb_result *res;
	struct ldb_dn *conflict_dn;
	bool rename_incoming_record;
	struct ldb_dn *new_dn;
	struct GUID guid;

	DEBUG(4,("replmd_replicated_request rename %s => %s\n",
		 ldb_dn_get_linearized(ar->search_msg->dn),
		 ldb_dn_get_linearized(msg->dn)));


	ret = dsdb_module_rename(ar->module, ar->search_msg->dn, msg->dn,
				 DSDB_FLAG_NEXT_MODULE, ar->req);
	if (ret == LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (ret != LDB_ERR_ENTRY_ALREADY_EXISTS) {
		talloc_free(tmp_ctx);
		ldb_asprintf_errstring(ldb_module_get_ctx(ar->module), "Failed to locally apply remote rename from %s to %s: %s",
				       ldb_dn_get_linearized(ar->search_msg->dn),
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb_module_get_ctx(ar->module)));
		return ret;
	}

	conflict_dn = msg->dn;


	ret = incoming_dn_should_be_renamed(tmp_ctx, ar, conflict_dn, &res,
					    &rename_incoming_record);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (rename_incoming_record) {

		new_dn = replmd_conflict_dn(msg,
					    ldb_module_get_ctx(ar->module),
					    msg->dn,
					    &ar->objs->objects[ar->index_current].object_guid);
		if (new_dn == NULL) {
			ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
								  "Failed to form conflict DN for %s\n",
								  ldb_dn_get_linearized(msg->dn));

			talloc_free(tmp_ctx);
			return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);
		}

		ret = dsdb_module_rename(ar->module, ar->search_msg->dn, new_dn,
					 DSDB_FLAG_NEXT_MODULE, ar->req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(ar->module),
					       "Failed to rename incoming conflicting dn '%s' (was '%s') to '%s' - %s\n",
					       ldb_dn_get_linearized(conflict_dn),
					       ldb_dn_get_linearized(ar->search_msg->dn),
					       ldb_dn_get_linearized(new_dn),
					       ldb_errstring(ldb_module_get_ctx(ar->module)));
			talloc_free(tmp_ctx);
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_DB_ERROR);
		}

		msg->dn = new_dn;
		*renamed_to_conflict = true;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* we are renaming the existing record */

	guid = samdb_result_guid(res->msgs[0], "objectGUID");
	if (GUID_all_zero(&guid)) {
		DEBUG(0,(__location__ ": Failed to find objectGUID for existing conflict record %s\n",
			 ldb_dn_get_linearized(conflict_dn)));
		goto failed;
	}

	new_dn = replmd_conflict_dn(tmp_ctx,
				    ldb_module_get_ctx(ar->module),
				    conflict_dn, &guid);
	if (new_dn == NULL) {
		DEBUG(0,(__location__ ": Failed to form conflict DN for %s\n",
			 ldb_dn_get_linearized(conflict_dn)));
		goto failed;
	}

	DEBUG(2,(__location__ ": Resolving conflict record via existing-record rename '%s' -> '%s'\n",
		 ldb_dn_get_linearized(conflict_dn), ldb_dn_get_linearized(new_dn)));

	ret = dsdb_module_rename(ar->module, conflict_dn, new_dn,
				 DSDB_FLAG_OWN_MODULE, ar->req);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to rename conflict dn '%s' to '%s' - %s\n",
			 ldb_dn_get_linearized(conflict_dn),
			 ldb_dn_get_linearized(new_dn),
			 ldb_errstring(ldb_module_get_ctx(ar->module))));
		goto failed;
	}

	/*
	 * now we need to ensure that the rename is seen as an
	 * originating update. We do that with a modify.
	 */
	ret = replmd_name_modify(ar, ar->req, new_dn);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	DEBUG(2,(__location__ ": With conflicting record renamed, re-apply replicated rename '%s' -> '%s'\n",
		 ldb_dn_get_linearized(ar->search_msg->dn),
		 ldb_dn_get_linearized(msg->dn)));

	/*
	 * With the other record out of the way, do the rename we had
	 * at the top again
	 */
	ret = dsdb_module_rename(ar->module, ar->search_msg->dn, msg->dn,
				 DSDB_FLAG_NEXT_MODULE, ar->req);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": After conflict resolution, failed to rename dn '%s' to '%s' - %s\n",
			 ldb_dn_get_linearized(ar->search_msg->dn),
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb_module_get_ctx(ar->module))));
			goto failed;
	}

	talloc_free(tmp_ctx);
	return ret;
failed:
	/*
	 * On failure make the caller get the error
	 * This means replication will stop with an error,
	 * but there is not much else we can do.  In the
	 * LDB_ERR_ENTRY_ALREADY_EXISTS case this is exactly what is
	 * needed.
	 */
	if (ret == LDB_SUCCESS) {
		ret = LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(tmp_ctx);
	return ret;
}


static int replmd_replicated_apply_merge(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *rmd;
	struct replPropertyMetaDataBlob omd;
	const struct ldb_val *omd_value;
	struct replPropertyMetaDataBlob nmd;
	struct ldb_val nmd_value;
	struct GUID remote_parent_guid;
	unsigned int i;
	uint32_t j,ni=0;
	unsigned int removed_attrs = 0;
	int ret;
	int (*callback)(struct ldb_request *req, struct ldb_reply *ares) = replmd_op_callback;
	bool isDeleted = false;
	bool local_isDeleted = false;
	bool remote_isDeleted = false;
	bool take_remote_isDeleted = false;
	bool sd_updated = false;
	bool renamed = false;
	bool renamed_to_conflict = false;
	bool is_schema_nc = false;
	NTSTATUS nt_status;
	const struct ldb_val *old_rdn, *new_rdn;
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(ar->module),
				struct replmd_private);
	NTTIME now;
	time_t t = time(NULL);
	unix_to_nt_time(&now, t);

	ldb = ldb_module_get_ctx(ar->module);
	msg = ar->objs->objects[ar->index_current].msg;

	is_schema_nc = ldb_dn_compare_base(replmd_private->schema_dn, msg->dn) == 0;

	rmd = ar->objs->objects[ar->index_current].meta_data;
	ZERO_STRUCT(omd);
	omd.version = 1;

	/* find existing meta data */
	omd_value = ldb_msg_find_ldb_val(ar->search_msg, "replPropertyMetaData");
	if (omd_value) {
		ndr_err = ndr_pull_struct_blob(omd_value, ar, &omd,
					       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			nt_status = ndr_map_error2ntstatus(ndr_err);
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (omd.version != 1) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	if (DEBUGLVL(8)) {
		struct GUID_txt_buf guid_txt;

		char *s = ldb_ldif_message_redacted_string(ldb, ar,
							   LDB_CHANGETYPE_MODIFY, msg);
		DEBUG(8, ("Initial DRS replication modify message of %s is:\n%s\n"
			  "%s\n"
			  "%s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid, &guid_txt),
			  s,
			  ndr_print_struct_string(s,
						  (ndr_print_fn_t)ndr_print_replPropertyMetaDataBlob,
						  "existing replPropertyMetaData",
						  &omd),
			  ndr_print_struct_string(s,
						  (ndr_print_fn_t)ndr_print_replPropertyMetaDataBlob,
						  "incoming replPropertyMetaData",
						  rmd)));
		talloc_free(s);
	} else if (DEBUGLVL(4)) {
		struct GUID_txt_buf guid_txt;

		DEBUG(4, ("Initial DRS replication modify DN of %s is: %s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid,
					  &guid_txt),
			  ldb_dn_get_linearized(msg->dn)));
	}
		
	local_isDeleted = ldb_msg_find_attr_as_bool(ar->search_msg,
						    "isDeleted", false);
	remote_isDeleted = ldb_msg_find_attr_as_bool(msg,
						     "isDeleted", false);

	/*
	 * Fill in the remote_parent_guid with the GUID or an all-zero
	 * GUID.
	 */
	if (ar->objs->objects[ar->index_current].parent_guid != NULL) {
		remote_parent_guid = *ar->objs->objects[ar->index_current].parent_guid;
	} else {
		remote_parent_guid = GUID_zero();
	}

	/*
	 * To ensure we follow a complex rename chain around, we have
	 * to confirm that the DN is the same (mostly to confirm the
	 * RDN) and the parentGUID is the same.
	 *
	 * This ensures we keep things under the correct parent, which
	 * replmd_replicated_handle_rename() will do.
	 */

	if (strcmp(ldb_dn_get_linearized(msg->dn), ldb_dn_get_linearized(ar->search_msg->dn)) == 0
	    && GUID_equal(&remote_parent_guid, &ar->local_parent_guid)) {
		ret = LDB_SUCCESS;
	} else {
		/*
		 * handle renames, even just by case that come in over
		 * DRS.  Changes in the parent DN don't hit us here,
		 * because the search for a parent will clean up those
		 * components.
		 *
		 * We also have already filtered out the case where
		 * the peer has an older name to what we have (see
		 * replmd_replicated_apply_search_callback())
		 */
		ret = replmd_replicated_handle_rename(ar, msg, ar->req, &renamed_to_conflict);

		/*
		 * This looks strange, but we must set this after any
		 * rename, otherwise the SD propegation will not
		 * happen (which might matter if we have a new parent)
		 *
		 * The additional case of calling
		 * replmd_op_name_modify_callback (below) is
		 * controlled by renamed_to_conflict.
		 */
		renamed = true;
	}

	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "replmd_replicated_request rename %s => %s failed - %s\n",
			  ldb_dn_get_linearized(ar->search_msg->dn),
			  ldb_dn_get_linearized(msg->dn),
			  ldb_errstring(ldb));
		return replmd_replicated_request_werror(ar, WERR_DS_DRA_DB_ERROR);
	}

	if (renamed_to_conflict == true) {
		/*
		 * Set the callback to one that will fix up the name
		 * metadata on the new conflict DN
		 */
		callback = replmd_op_name_modify_callback;
	}

	ZERO_STRUCT(nmd);
	nmd.version = 1;
	nmd.ctr.ctr1.count = omd.ctr.ctr1.count + rmd->ctr.ctr1.count;
	nmd.ctr.ctr1.array = talloc_array(ar,
					  struct replPropertyMetaData1,
					  nmd.ctr.ctr1.count);
	if (!nmd.ctr.ctr1.array) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);

	/* first copy the old meta data */
	for (i=0; i < omd.ctr.ctr1.count; i++) {
		nmd.ctr.ctr1.array[ni]	= omd.ctr.ctr1.array[i];
		ni++;
	}

	ar->seq_num = 0;
	/* now merge in the new meta data */
	for (i=0; i < rmd->ctr.ctr1.count; i++) {
		bool found = false;

		for (j=0; j < ni; j++) {
			bool cmp;

			if (rmd->ctr.ctr1.array[i].attid != nmd.ctr.ctr1.array[j].attid) {
				continue;
			}

			cmp = replmd_replPropertyMetaData1_new_should_be_taken(
				ar->objs->dsdb_repl_flags,
				&nmd.ctr.ctr1.array[j],
				&rmd->ctr.ctr1.array[i]);
			if (cmp) {
				/* replace the entry */
				nmd.ctr.ctr1.array[j] = rmd->ctr.ctr1.array[i];
				if (ar->seq_num == 0) {
					ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &ar->seq_num);
					if (ret != LDB_SUCCESS) {
						return replmd_replicated_request_error(ar, ret);
					}
				}
				nmd.ctr.ctr1.array[j].local_usn = ar->seq_num;
				switch (nmd.ctr.ctr1.array[j].attid) {
				case DRSUAPI_ATTID_ntSecurityDescriptor:
					sd_updated = true;
					break;
				case DRSUAPI_ATTID_isDeleted:
					take_remote_isDeleted = true;
					break;
				default:
					break;
				}
				found = true;
				break;
			}

			if (rmd->ctr.ctr1.array[i].attid != DRSUAPI_ATTID_instanceType) {
				DEBUG(3,("Discarding older DRS attribute update to %s on %s from %s\n",
					 msg->elements[i-removed_attrs].name,
					 ldb_dn_get_linearized(msg->dn),
					 GUID_string(ar, &rmd->ctr.ctr1.array[i].originating_invocation_id)));
			}

			/* we don't want to apply this change so remove the attribute */
			ldb_msg_remove_element(msg, &msg->elements[i-removed_attrs]);
			removed_attrs++;

			found = true;
			break;
		}

		if (found) continue;

		nmd.ctr.ctr1.array[ni] = rmd->ctr.ctr1.array[i];
		if (ar->seq_num == 0) {
			ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &ar->seq_num);
			if (ret != LDB_SUCCESS) {
				return replmd_replicated_request_error(ar, ret);
			}
		}
		nmd.ctr.ctr1.array[ni].local_usn = ar->seq_num;
		switch (nmd.ctr.ctr1.array[ni].attid) {
		case DRSUAPI_ATTID_ntSecurityDescriptor:
			sd_updated = true;
			break;
		case DRSUAPI_ATTID_isDeleted:
			take_remote_isDeleted = true;
			break;
		default:
			break;
		}
		ni++;
	}

	/*
	 * finally correct the size of the meta_data array
	 */
	nmd.ctr.ctr1.count = ni;

	new_rdn = ldb_dn_get_rdn_val(msg->dn);
	old_rdn = ldb_dn_get_rdn_val(ar->search_msg->dn);

	if (renamed) {
		ret = replmd_update_rpmd_rdn_attr(ldb, msg, new_rdn, old_rdn,
						  &nmd, ar, now, is_schema_nc,
						  false);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "%s: error during DRS repl merge: %s", __func__, ldb_errstring(ldb));
			return replmd_replicated_request_error(ar, ret);
		}
	}
	/*
	 * sort the new meta data array
	 */
	ret = replmd_replPropertyMetaDataCtr1_sort_and_verify(ldb, &nmd.ctr.ctr1, msg->dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "%s: error during DRS repl merge: %s", __func__, ldb_errstring(ldb));
		return ret;
	}

	/*
	 * Work out if this object is deleted, so we can prune any extra attributes.  See MS-DRSR 4.1.10.6.9
	 * UpdateObject.
	 *
	 * This also controls SD propagation below
	 */
	if (take_remote_isDeleted) {
		isDeleted = remote_isDeleted;
	} else {
		isDeleted = local_isDeleted;
	}

	ar->isDeleted = isDeleted;

	/*
	 * check if some replicated attributes left, otherwise skip the ldb_modify() call
	 */
	if (msg->num_elements == 0) {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: skip replace\n",
			  ar->index_current);

		return replmd_replicated_apply_isDeleted(ar);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: replace %u attributes\n",
		  ar->index_current, msg->num_elements);

	if (renamed) {
		/*
		 * This is an new name for this object, so we must
		 * inherit from the parent
		 *
		 * This is needed because descriptor is above
		 * repl_meta_data in the module stack, so this will
		 * not be trigered 'naturally' by the flow of
		 * operations.
		 */
		ret = dsdb_module_schedule_sd_propagation(ar->module,
							  ar->objs->partition_dn,
							  ar->objs->objects[ar->index_current].object_guid,
							  true);
		if (ret != LDB_SUCCESS) {
			return ldb_operr(ldb);
		}
	}

	if (sd_updated && !isDeleted) {
		/*
		 * This is an existing object, so there is no need to
		 * inherit from the parent, but we must inherit any
		 * incoming changes to our child objects.
		 *
		 * This is needed because descriptor is above
		 * repl_meta_data in the module stack, so this will
		 * not be trigered 'naturally' by the flow of
		 * operations.
		 */
		ret = dsdb_module_schedule_sd_propagation(ar->module,
							  ar->objs->partition_dn,
							  ar->objs->objects[ar->index_current].object_guid,
							  false);
		if (ret != LDB_SUCCESS) {
			return ldb_operr(ldb);
		}
	}

	/* create the meta data value */
	ndr_err = ndr_push_struct_blob(&nmd_value, msg, &nmd,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/*
	 * when we know that we'll modify the record, add the whenChanged, uSNChanged
	 * and replPopertyMetaData attributes
	 */
	ret = ldb_msg_add_string(msg, "whenChanged", ar->objs->objects[ar->index_current].when_changed);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", ar->seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &nmd_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	replmd_ldb_message_sort(msg, ar->schema);

	/* we want to replace the old values */
	for (i=0; i < msg->num_elements; i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
		if (ldb_attr_cmp(msg->elements[i].name, "objectClass") == 0) {
			if (msg->elements[i].num_values == 0) {
				ldb_asprintf_errstring(ldb, __location__
						       ": objectClass removed on %s, aborting replication\n",
						       ldb_dn_get_linearized(msg->dn));
				return replmd_replicated_request_error(ar, LDB_ERR_OBJECT_CLASS_VIOLATION);
			}
		}
	}

	if (DEBUGLVL(8)) {
		struct GUID_txt_buf guid_txt;

		char *s = ldb_ldif_message_redacted_string(ldb, ar,
							   LDB_CHANGETYPE_MODIFY,
							   msg);
		DEBUG(8, ("Final DRS replication modify message of %s:\n%s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid,
					  &guid_txt),
			  s));
		talloc_free(s);
	} else if (DEBUGLVL(4)) {
		struct GUID_txt_buf guid_txt;

		DEBUG(4, ("Final DRS replication modify DN of %s is %s\n",
			  GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid,
					  &guid_txt),
			  ldb_dn_get_linearized(msg->dn)));
	}

	ret = ldb_build_mod_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				callback,
				ar->req);
	LDB_REQ_SET_LOCATION(change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	/* current partition control needed by "repmd_op_callback" */
	ret = ldb_request_add_control(change_req,
				      DSDB_CONTROL_CURRENT_PARTITION_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replicated_apply_search_callback(struct ldb_request *req,
						   struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->search_msg = talloc_steal(ar, ares->message);
		break;

	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;

	case LDB_REPLY_DONE:
	{
		struct replPropertyMetaData1 *md_remote;
		struct replPropertyMetaData1 *md_local;

		struct replPropertyMetaDataBlob omd;
		const struct ldb_val *omd_value;
		struct replPropertyMetaDataBlob *rmd;
		struct ldb_message *msg;
		int instanceType;
		ar->objs->objects[ar->index_current].local_parent_dn = NULL;
		ar->objs->objects[ar->index_current].last_known_parent = NULL;

		/*
		 * This is the ADD case, find the appropriate parent,
		 * as this object doesn't exist locally:
		 */
		if (ar->search_msg == NULL) {
			ret = replmd_replicated_apply_search_for_parent(ar);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ar->req, NULL, NULL, ret);
			}
			talloc_free(ares);
			return LDB_SUCCESS;
		}

		/*
		 * Otherwise, in the MERGE case, work out if we are
		 * attempting a rename, and if so find the parent the
		 * newly renamed object wants to belong under (which
		 * may not be the parent in it's attached string DN
		 */
		rmd = ar->objs->objects[ar->index_current].meta_data;
		ZERO_STRUCT(omd);
		omd.version = 1;

		/* find existing meta data */
		omd_value = ldb_msg_find_ldb_val(ar->search_msg, "replPropertyMetaData");
		if (omd_value) {
			enum ndr_err_code ndr_err;
			ndr_err = ndr_pull_struct_blob(omd_value, ar, &omd,
						       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
				return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
			}

			if (omd.version != 1) {
				return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
			}
		}

		ar->local_parent_guid = samdb_result_guid(ar->search_msg, "parentGUID");

		instanceType = ldb_msg_find_attr_as_int(ar->search_msg, "instanceType", 0);
		if (((instanceType & INSTANCE_TYPE_IS_NC_HEAD) == 0)
		    && GUID_all_zero(&ar->local_parent_guid)) {
			DEBUG(0, ("Refusing to replicate new version of %s "
				  "as local object has an all-zero parentGUID attribute, "
				  "despite not being an NC root\n",
				  ldb_dn_get_linearized(ar->search_msg->dn)));
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}

		/*
		 * now we need to check for double renames. We could have a
		 * local rename pending which our replication partner hasn't
		 * received yet. We choose which one wins by looking at the
		 * attribute stamps on the two objects, the newer one wins.
		 *
		 * This also simply applies the correct algorithms for
		 * determining if a change was made to name at all, or
		 * if the object has just been renamed under the same
		 * parent.
		 */
		md_remote = replmd_replPropertyMetaData1_find_attid(rmd, DRSUAPI_ATTID_name);
		md_local = replmd_replPropertyMetaData1_find_attid(&omd, DRSUAPI_ATTID_name);
		if (!md_local) {
			DEBUG(0,(__location__ ": Failed to find name attribute in local LDB replPropertyMetaData for %s\n",
				 ldb_dn_get_linearized(ar->search_msg->dn)));
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_DB_ERROR);
		}

		/*
		 * if there is no name attribute given then we have to assume the
		 *  object we've received has the older name
		 */
		if (replmd_replPropertyMetaData1_new_should_be_taken(
			    ar->objs->dsdb_repl_flags & DSDB_REPL_FLAG_PRIORITISE_INCOMING,
			    md_local, md_remote)) {
			struct GUID_txt_buf p_guid_local;
			struct GUID_txt_buf p_guid_remote;
			msg = ar->objs->objects[ar->index_current].msg;

			/* Merge on the existing object, with rename */

			DEBUG(4,(__location__ ": Looking for new parent for object %s currently under %s "
				 "as incoming object changing to %s under %s\n",
				 ldb_dn_get_linearized(ar->search_msg->dn),
				 GUID_buf_string(&ar->local_parent_guid, &p_guid_local),
				 ldb_dn_get_linearized(msg->dn),
				 GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid,
						 &p_guid_remote)));
			ret = replmd_replicated_apply_search_for_parent(ar);
		} else {
			struct GUID_txt_buf p_guid_local;
			struct GUID_txt_buf p_guid_remote;
			msg = ar->objs->objects[ar->index_current].msg;

			/*
			 * Merge on the existing object, force no
			 * rename (code below just to explain why in
			 * the DEBUG() logs)
			 */

			if (strcmp(ldb_dn_get_linearized(ar->search_msg->dn),
				   ldb_dn_get_linearized(msg->dn)) == 0) {
				if (ar->objs->objects[ar->index_current].parent_guid != NULL &&
				    GUID_equal(&ar->local_parent_guid,
					       ar->objs->objects[ar->index_current].parent_guid)
				    == false) {
					DEBUG(4,(__location__ ": Keeping object %s at under %s "
						 "despite incoming object changing parent to %s\n",
						 ldb_dn_get_linearized(ar->search_msg->dn),
						 GUID_buf_string(&ar->local_parent_guid, &p_guid_local),
						 GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid,
								 &p_guid_remote)));
				}
			} else {
				DEBUG(4,(__location__ ": Keeping object %s at under %s "
					 " and rejecting older rename to %s under %s\n",
					 ldb_dn_get_linearized(ar->search_msg->dn),
					 GUID_buf_string(&ar->local_parent_guid, &p_guid_local),
					 ldb_dn_get_linearized(msg->dn),
					 GUID_buf_string(ar->objs->objects[ar->index_current].parent_guid,
							 &p_guid_remote)));
			}
			/*
			 * This assignment ensures that the strcmp()
			 * and GUID_equal() calls in
			 * replmd_replicated_apply_merge() avoids the
			 * rename call
			 */
			ar->objs->objects[ar->index_current].parent_guid =
				&ar->local_parent_guid;

			msg->dn = ar->search_msg->dn;
			ret = replmd_replicated_apply_merge(ar);
		}
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ar->req, NULL, NULL, ret);
		}
	}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

/**
 * Returns true if we can group together processing this link attribute,
 * i.e. it has the same source-object and attribute ID as other links
 * already in the group
 */
static bool la_entry_matches_group(struct la_entry *la_entry,
				   struct la_group *la_group)
{
	struct la_entry *prev = la_group->la_entries;

	return (la_entry->la->attid == prev->la->attid &&
		GUID_equal(&la_entry->la->identifier->guid,
			   &prev->la->identifier->guid));
}

/**
 * Creates a new la_entry to store replication info for a single
 * linked attribute.
 */
static struct la_entry *
create_la_entry(struct replmd_private *replmd_private,
		struct drsuapi_DsReplicaLinkedAttribute *la,
		uint32_t dsdb_repl_flags)
{
	struct la_entry *la_entry;

	if (replmd_private->la_ctx == NULL) {
		replmd_private->la_ctx = talloc_new(replmd_private);
	}
	la_entry = talloc(replmd_private->la_ctx, struct la_entry);
	if (la_entry == NULL) {
		return NULL;
	}
	la_entry->la = talloc(la_entry,
			      struct drsuapi_DsReplicaLinkedAttribute);
	if (la_entry->la == NULL) {
		talloc_free(la_entry);
		return NULL;
	}
	*la_entry->la = *la;
	la_entry->dsdb_repl_flags = dsdb_repl_flags;

	/*
	 * we need to steal the non-scalars so they stay
	 * around until the end of the transaction
	 */
	talloc_steal(la_entry->la, la_entry->la->identifier);
	talloc_steal(la_entry->la, la_entry->la->value.blob);

	return la_entry;
}

/**
 * Stores the linked attributes received in the replication chunk - these get
 * applied at the end of the transaction. We also check that each linked
 * attribute is valid, i.e. source and target objects are known.
 */
static int replmd_store_linked_attributes(struct replmd_replicated_request *ar)
{
	int ret = LDB_SUCCESS;
	uint32_t i;
	struct ldb_module *module = ar->module;
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(module), struct replmd_private);
	struct la_group *la_group = NULL;
	struct ldb_context *ldb;
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_message *src_msg = NULL;
	const struct dsdb_attribute *attr = NULL;

	ldb = ldb_module_get_ctx(module);

	DEBUG(4,("linked_attributes_count=%u\n", ar->objs->linked_attributes_count));

	/* save away the linked attributes for the end of the transaction */
	for (i = 0; i < ar->objs->linked_attributes_count; i++) {
		struct la_entry *la_entry;
		bool new_srcobj;

		/* create an entry to store the received link attribute info */
		la_entry = create_la_entry(replmd_private,
					   &ar->objs->linked_attributes[i],
					   ar->objs->dsdb_repl_flags);
		if (la_entry == NULL) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/*
		 * check if we're still dealing with the same source object
		 * as the last link
		 */
		new_srcobj = (la_group == NULL ||
			      !la_entry_matches_group(la_entry, la_group));

		if (new_srcobj) {

			/* get a new mem_ctx to lookup the source object */
			TALLOC_FREE(tmp_ctx);
			tmp_ctx = talloc_new(ar);
			if (tmp_ctx == NULL) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/* verify the link source exists */
			ret = replmd_get_la_entry_source(module, la_entry,
							 tmp_ctx, &attr,
							 &src_msg);

			/*
			 * When we fail to find the source object, the error
			 * code we pass back here is really important. It flags
			 * back to the callers to retry this request with
			 * DRSUAPI_DRS_GET_ANC. This case should never happen
			 * if we're replicating from a Samba DC, but it is
			 * needed to talk to a Windows DC
			 */
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				WERROR err = WERR_DS_DRA_MISSING_PARENT;
				ret = replmd_replicated_request_werror(ar,
								       err);
				break;
			}
		}

		ret = replmd_verify_link_target(ar, tmp_ctx, la_entry,
						src_msg->dn, attr);
		if (ret != LDB_SUCCESS) {
			break;
		}

		/* group the links together by source-object for efficiency */
		if (new_srcobj) {
			la_group = talloc_zero(replmd_private->la_ctx,
					       struct la_group);
			if (la_group == NULL) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			DLIST_ADD(replmd_private->la_list, la_group);
		}
		DLIST_ADD(la_group->la_entries, la_entry);
		replmd_private->total_links++;
	}

	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int replmd_replicated_uptodate_vector(struct replmd_replicated_request *ar);

static int replmd_replicated_apply_next(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	int ret;
	char *tmp_str;
	char *filter;
	struct ldb_request *search_req;
	static const char *attrs[] = { "repsFrom", "replUpToDateVector",
				       "parentGUID", "instanceType",
				       "replPropertyMetaData", "nTSecurityDescriptor",
				       "isDeleted", NULL };
	struct GUID_txt_buf guid_str_buf;

	if (ar->index_current >= ar->objs->num_objects) {

		/*
		 * Now that we've applied all the objects, check the new linked
		 * attributes and store them (we apply them in .prepare_commit)
		 */
		ret = replmd_store_linked_attributes(ar);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* done applying objects, move on to the next stage */
		return replmd_replicated_uptodate_vector(ar);
	}

	ldb = ldb_module_get_ctx(ar->module);
	ar->search_msg = NULL;
	ar->isDeleted = false;

	tmp_str = GUID_buf_string(&ar->objs->objects[ar->index_current].object_guid,
				  &guid_str_buf);

	filter = talloc_asprintf(ar, "(objectGUID=%s)", tmp_str);
	if (!filter) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);

	ret = ldb_build_search_req(&search_req,
				   ldb,
				   ar,
				   ar->objs->partition_dn,
				   LDB_SCOPE_SUBTREE,
				   filter,
				   attrs,
				   NULL,
				   ar,
				   replmd_replicated_apply_search_callback,
				   ar->req);
	LDB_REQ_SET_LOCATION(search_req);

	/*
	 * We set DSDB_SEARCH_SHOW_EXTENDED_DN to get the GUID on the
	 * DN.  This in turn helps our operational module find the
	 * record by GUID, not DN lookup which is more error prone if
	 * DN indexing changes.  We prefer to keep chasing GUIDs
	 * around if possible, even within a transaction.
	 *
	 * The aim here is to keep replication moving and allow a
	 * reindex later.
	 */
	ret = dsdb_request_add_controls(search_req, DSDB_SEARCH_SHOW_RECYCLED
					|DSDB_SEARCH_SHOW_EXTENDED_DN);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ar->module, search_req);
}

/*
 * Returns true if we need to do extra processing to handle deleted object
 * changes received via replication
 */
static bool replmd_should_apply_isDeleted(struct replmd_replicated_request *ar,
					  struct ldb_message *msg)
{
	struct ldb_dn *deleted_objects_dn;
	int ret;

	if (!ar->isDeleted) {

		/* not a deleted object, so don't set isDeleted */
		return false;
	}

	ret = dsdb_get_deleted_objects_dn(ldb_module_get_ctx(ar->module),
					  msg, msg->dn,
					  &deleted_objects_dn);

	/*
	 * if the Deleted Object container lookup failed, then just apply
	 * isDeleted (note that it doesn't exist for the Schema partition)
	 */
	if (ret != LDB_SUCCESS) {
		return true;
	}

	/*
	 * the Deleted Objects container has isDeleted set but is not entirely
	 * a deleted object, so DON'T re-apply isDeleted to it
	 */
	if (ldb_dn_compare(msg->dn, deleted_objects_dn) == 0) {
		return false;
	}

	return true;
}

/*
 * This is essentially a wrapper for replmd_replicated_apply_next()
 *
 * This is needed to ensure that both codepaths call this handler.
 */
static int replmd_replicated_apply_isDeleted(struct replmd_replicated_request *ar)
{
	struct ldb_message *msg = ar->objs->objects[ar->index_current].msg;
	int ret;
	bool apply_isDeleted;
	struct ldb_request *del_req = NULL;
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	apply_isDeleted = replmd_should_apply_isDeleted(ar, msg);

	if (!apply_isDeleted) {

		/* nothing to do */
		ar->index_current++;
		return replmd_replicated_apply_next(ar);
	}

	/*
	 * Do a delete here again, so that if there is
	 * anything local that conflicts with this
	 * object being deleted, it is removed.  This
	 * includes links.  See MS-DRSR 4.1.10.6.9
	 * UpdateObject.
	 *
	 * If the object is already deleted, and there
	 * is no more work required, it doesn't do
	 * anything.
	 */

	/* This has been updated to point to the DN we eventually did the modify on */

	tmp_ctx = talloc_new(ar);
	if (!tmp_ctx) {
		ret = ldb_oom(ldb_module_get_ctx(ar->module));
		return ret;
	}

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		ret = ldb_oom(ldb_module_get_ctx(ar->module));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Build a delete request, which hopefully will artually turn into nothing */
	ret = ldb_build_del_req(&del_req, ldb_module_get_ctx(ar->module), tmp_ctx,
				msg->dn,
				NULL,
				res,
				ldb_modify_default_callback,
				ar->req);
	LDB_REQ_SET_LOCATION(del_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/*
	 * This is the guts of the call, call back
	 * into our delete code, but setting the
	 * re_delete flag so we delete anything that
	 * shouldn't be there on a deleted or recycled
	 * object
	 */
	ret = replmd_delete_internals(ar->module, del_req, true);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(del_req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ar->index_current++;
	return replmd_replicated_apply_next(ar);
}

static int replmd_replicated_uptodate_modify_callback(struct ldb_request *req,
						      struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	ldb = ldb_module_get_ctx(ar->module);

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_asprintf_errstring(ldb, "Invalid LDB reply type %d", ares->type);
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);

	return ldb_module_done(ar->req, NULL, NULL, LDB_SUCCESS);
}

static int replmd_replicated_uptodate_modify(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
	struct ldb_message *msg;
	struct replUpToDateVectorBlob ouv;
	const struct ldb_val *ouv_value;
	const struct drsuapi_DsReplicaCursor2CtrEx *ruv;
	struct replUpToDateVectorBlob nuv;
	struct ldb_val nuv_value;
	struct ldb_message_element *nuv_el = NULL;
	struct ldb_message_element *orf_el = NULL;
	struct repsFromToBlob nrf;
	struct ldb_val *nrf_value = NULL;
	struct ldb_message_element *nrf_el = NULL;
	unsigned int i;
	uint32_t j,ni=0;
	bool found = false;
	time_t t = time(NULL);
	NTTIME now;
	int ret;
	uint32_t instanceType;

	ldb = ldb_module_get_ctx(ar->module);
	ruv = ar->objs->uptodateness_vector;
	ZERO_STRUCT(ouv);
	ouv.version = 2;
	ZERO_STRUCT(nuv);
	nuv.version = 2;

	unix_to_nt_time(&now, t);

	if (ar->search_msg == NULL) {
		/* this happens for a REPL_OBJ call where we are
		   creating the target object by replicating it. The
		   subdomain join code does this for the partition DN
		*/
		DEBUG(4,(__location__ ": Skipping UDV and repsFrom update as no target DN\n"));
		return ldb_module_done(ar->req, NULL, NULL, LDB_SUCCESS);
	}

	instanceType = ldb_msg_find_attr_as_uint(ar->search_msg, "instanceType", 0);
	if (! (instanceType & INSTANCE_TYPE_IS_NC_HEAD)) {
		DEBUG(4,(__location__ ": Skipping UDV and repsFrom update as not NC root: %s\n",
			 ldb_dn_get_linearized(ar->search_msg->dn)));
		return ldb_module_done(ar->req, NULL, NULL, LDB_SUCCESS);
	}

	/*
	 * first create the new replUpToDateVector
	 */
	ouv_value = ldb_msg_find_ldb_val(ar->search_msg, "replUpToDateVector");
	if (ouv_value) {
		ndr_err = ndr_pull_struct_blob(ouv_value, ar, &ouv,
					       (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (ouv.version != 2) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	/*
	 * the new uptodateness vector will at least
	 * contain 1 entry, one for the source_dsa
	 *
	 * plus optional values from our old vector and the one from the source_dsa
	 */
	nuv.ctr.ctr2.count = ouv.ctr.ctr2.count;
	if (ruv) nuv.ctr.ctr2.count += ruv->count;
	nuv.ctr.ctr2.cursors = talloc_array(ar,
					    struct drsuapi_DsReplicaCursor2,
					    nuv.ctr.ctr2.count);
	if (!nuv.ctr.ctr2.cursors) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);

	/* first copy the old vector */
	for (i=0; i < ouv.ctr.ctr2.count; i++) {
		nuv.ctr.ctr2.cursors[ni] = ouv.ctr.ctr2.cursors[i];
		ni++;
	}

	/* merge in the source_dsa vector is available */
	for (i=0; (ruv && i < ruv->count); i++) {
		found = false;

		if (GUID_equal(&ruv->cursors[i].source_dsa_invocation_id,
			       &ar->our_invocation_id)) {
			continue;
		}

		for (j=0; j < ni; j++) {
			if (!GUID_equal(&ruv->cursors[i].source_dsa_invocation_id,
					&nuv.ctr.ctr2.cursors[j].source_dsa_invocation_id)) {
				continue;
			}

			found = true;

			if (ruv->cursors[i].highest_usn > nuv.ctr.ctr2.cursors[j].highest_usn) {
				nuv.ctr.ctr2.cursors[j] = ruv->cursors[i];
			}
			break;
		}

		if (found) continue;

		/* if it's not there yet, add it */
		nuv.ctr.ctr2.cursors[ni] = ruv->cursors[i];
		ni++;
	}

	/*
	 * finally correct the size of the cursors array
	 */
	nuv.ctr.ctr2.count = ni;

	/*
	 * sort the cursors
	 */
	TYPESAFE_QSORT(nuv.ctr.ctr2.cursors, nuv.ctr.ctr2.count, drsuapi_DsReplicaCursor2_compare);

	/*
	 * create the change ldb_message
	 */
	msg = ldb_msg_new(ar);
	if (!msg) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);
	msg->dn = ar->search_msg->dn;

	ndr_err = ndr_push_struct_blob(&nuv_value, msg, &nuv,
				       (ndr_push_flags_fn_t)ndr_push_replUpToDateVectorBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}
	ret = ldb_msg_add_value(msg, "replUpToDateVector", &nuv_value, &nuv_el);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	nuv_el->flags = LDB_FLAG_MOD_REPLACE;

	/*
	 * now create the new repsFrom value from the given repsFromTo1 structure
	 */
	ZERO_STRUCT(nrf);
	nrf.version					= 1;
	nrf.ctr.ctr1					= *ar->objs->source_dsa;
	nrf.ctr.ctr1.last_attempt			= now;
	nrf.ctr.ctr1.last_success			= now;
	nrf.ctr.ctr1.result_last_attempt 		= WERR_OK;

	/*
	 * first see if we already have a repsFrom value for the current source dsa
	 * if so we'll later replace this value
	 */
	orf_el = ldb_msg_find_element(ar->search_msg, "repsFrom");
	if (orf_el) {
		for (i=0; i < orf_el->num_values; i++) {
			struct repsFromToBlob *trf;

			trf = talloc(ar, struct repsFromToBlob);
			if (!trf) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);

			ndr_err = ndr_pull_struct_blob(&orf_el->values[i], trf, trf,
						       (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
				return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
			}

			if (trf->version != 1) {
				return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
			}

			/*
			 * we compare the source dsa objectGUID not the invocation_id
			 * because we want only one repsFrom value per source dsa
			 * and when the invocation_id of the source dsa has changed we don't need
			 * the old repsFrom with the old invocation_id
			 */
			if (!GUID_equal(&trf->ctr.ctr1.source_dsa_obj_guid,
					&ar->objs->source_dsa->source_dsa_obj_guid)) {
				talloc_free(trf);
				continue;
			}

			talloc_free(trf);
			nrf_value = &orf_el->values[i];
			break;
		}

		/*
		 * copy over all old values to the new ldb_message
		 */
		ret = ldb_msg_add_empty(msg, "repsFrom", 0, &nrf_el);
		if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);
		*nrf_el = *orf_el;
	}

	/*
	 * if we haven't found an old repsFrom value for the current source dsa
	 * we'll add a new value
	 */
	if (!nrf_value) {
		struct ldb_val zero_value;
		ZERO_STRUCT(zero_value);
		ret = ldb_msg_add_value(msg, "repsFrom", &zero_value, &nrf_el);
		if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

		nrf_value = &nrf_el->values[nrf_el->num_values - 1];
	}

	/* we now fill the value which is already attached to ldb_message */
	ndr_err = ndr_push_struct_blob(nrf_value, msg,
				       &nrf,
				       (ndr_push_flags_fn_t)ndr_push_repsFromToBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/*
	 * the ldb_message_element for the attribute, has all the old values and the new one
	 * so we'll replace the whole attribute with all values
	 */
	nrf_el->flags = LDB_FLAG_MOD_REPLACE;

	if (CHECK_DEBUGLVL(4)) {
		char *s = ldb_ldif_message_redacted_string(ldb, ar,
							   LDB_CHANGETYPE_MODIFY,
							   msg);
		DEBUG(4, ("DRS replication uptodate modify message:\n%s\n", s));
		talloc_free(s);
	}

	/* prepare the ldb_modify() request */
	ret = ldb_build_mod_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				replmd_replicated_uptodate_modify_callback,
				ar->req);
	LDB_REQ_SET_LOCATION(change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replicated_uptodate_search_callback(struct ldb_request *req,
						      struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->search_msg = talloc_steal(ar, ares->message);
		break;

	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;

	case LDB_REPLY_DONE:
		ret = replmd_replicated_uptodate_modify(ar);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ar->req, NULL, NULL, ret);
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}


static int replmd_replicated_uptodate_vector(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ar->module);
	struct replmd_private *replmd_private =
		talloc_get_type_abort(ldb_module_get_private(ar->module),
		struct replmd_private);
	int ret;
	static const char *attrs[] = {
		"replUpToDateVector",
		"repsFrom",
		"instanceType",
		NULL
	};
	struct ldb_request *search_req;

	ar->search_msg = NULL;

	/*
	 * Let the caller know that we did an originating updates
	 */
	ar->objs->originating_updates = replmd_private->originating_updates;

	ret = ldb_build_search_req(&search_req,
				   ldb,
				   ar,
				   ar->objs->partition_dn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL,
				   ar,
				   replmd_replicated_uptodate_search_callback,
				   ar->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, search_req);
}



static int replmd_extended_replicated_objects(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct dsdb_extended_replicated_objects *objs;
	struct replmd_replicated_request *ar;
	struct ldb_control **ctrls;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_extended_replicated_objects\n");

	objs = talloc_get_type(req->op.extended.data, struct dsdb_extended_replicated_objects);
	if (!objs) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (objs->version != DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: extended data invalid version [%u != %u]\n",
			  objs->version, DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ar = replmd_ctx_init(module, req);
	if (!ar)
		return LDB_ERR_OPERATIONS_ERROR;

	/* Set the flags to have the replmd_op_callback run over the full set of objects */
	ar->apply_mode = true;
	ar->objs = objs;
	ar->schema = dsdb_get_schema(ldb, ar);
	if (!ar->schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL, "replmd_ctx_init: no loaded schema found\n");
		talloc_free(ar);
		DEBUG(0,(__location__ ": %s\n", ldb_errstring(ldb)));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ctrls = req->controls;

	if (req->controls) {
		req->controls = talloc_memdup(ar, req->controls,
					      talloc_get_size(req->controls));
		if (!req->controls) return replmd_replicated_request_werror(ar, WERR_NOT_ENOUGH_MEMORY);
	}

	ret = ldb_request_add_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID, false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* If this change contained linked attributes in the body
	 * (rather than in the links section) we need to update
	 * backlinks in linked_attributes */
	ret = ldb_request_add_control(req, DSDB_CONTROL_APPLY_LINKS, false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ar->controls = req->controls;
	req->controls = ctrls;

	return replmd_replicated_apply_next(ar);
}

/**
 * Checks how to handle an missing target - either we need to fail the
 * replication and retry with GET_TGT, ignore the link and continue, or try to
 * add a partial link to an unknown target.
 */
static int replmd_allow_missing_target(struct ldb_module *module,
				       TALLOC_CTX *mem_ctx,
				       struct ldb_dn *target_dn,
				       struct ldb_dn *source_dn,
				       bool is_obj_commit,
				       struct GUID *guid,
				       uint32_t dsdb_repl_flags,
				       bool *ignore_link,
				       const char * missing_str)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	bool is_in_same_nc;

	/*
	 * we may not be able to resolve link targets properly when
	 * dealing with subsets of objects, e.g. the source is a
	 * critical object and the target isn't
	 *
	 * TODO:
	 * When we implement Trusted Domains we need to consider
	 * whether they get treated as an incomplete replica here or not
	 */
	if (dsdb_repl_flags & DSDB_REPL_FLAG_OBJECT_SUBSET) {

		/*
		 * Ignore the link. We don't increase the highwater-mark in
		 * the object subset cases, so subsequent replications should
		 * resolve any missing links
		 */
		DEBUG(2, ("%s target %s linked from %s\n", missing_str,
			  ldb_dn_get_linearized(target_dn),
			  ldb_dn_get_linearized(source_dn)));
		*ignore_link = true;
		return LDB_SUCCESS;
	}

	is_in_same_nc = dsdb_objects_have_same_nc(ldb,
						  mem_ctx,
						  source_dn,
						  target_dn);
	if (is_in_same_nc) {

		/*
		 * if the target is already be up-to-date there's no point in
		 * retrying. This could be due to bad timing, or if a target
		 * on a one-way link was deleted. We ignore the link rather
		 * than failing the replication cycle completely
		 */
		if (dsdb_repl_flags & DSDB_REPL_FLAG_TARGETS_UPTODATE) {
			*ignore_link = true;
			DBG_WARNING("%s is %s "
				    "but up to date. Ignoring link from %s\n",
				    ldb_dn_get_linearized(target_dn), missing_str,
				    ldb_dn_get_linearized(source_dn));
			return LDB_SUCCESS;
		}

		/* otherwise fail the replication and retry with GET_TGT */
		ldb_asprintf_errstring(ldb, "%s target %s GUID %s linked from %s\n",
				       missing_str,
				       ldb_dn_get_linearized(target_dn),
				       GUID_string(mem_ctx, guid),
				       ldb_dn_get_linearized(source_dn));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/*
	 * The target of the cross-partition link is missing. Continue
	 * and try to at least add the forward-link. This isn't great,
	 * but a partial link can be fixed by dbcheck, so it's better
	 * than dropping the link completely.
	 */
	*ignore_link = false;

	if (is_obj_commit) {

		/*
		 * Only log this when we're actually committing the objects.
		 * This avoids spurious logs, i.e. if we're just verifying the
		 * received link during a join.
		 */
		DBG_WARNING("%s cross-partition target %s linked from %s\n",
			    missing_str, ldb_dn_get_linearized(target_dn),
			    ldb_dn_get_linearized(source_dn));
	}
	
	return LDB_SUCCESS;
}

/**
 * Checks that the target object for a linked attribute exists.
 * @param guid returns the target object's GUID (is returned)if it exists)
 * @param ignore_link set to true if the linked attribute should be ignored
 * (i.e. the target doesn't exist, but that it's OK to skip the link)
 */
static int replmd_check_target_exists(struct ldb_module *module,
				      struct dsdb_dn *dsdb_dn,
				      struct la_entry *la_entry,
				      struct ldb_dn *source_dn,
				      bool is_obj_commit,
				      struct GUID *guid,
				      bool *ignore_link)
{
	struct drsuapi_DsReplicaLinkedAttribute *la = la_entry->la;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *target_res;
	TALLOC_CTX *tmp_ctx = talloc_new(la_entry);
	const char *attrs[] = { "isDeleted", "isRecycled", NULL };
	NTSTATUS ntstatus;
	int ret;
	enum deletion_state target_deletion_state = OBJECT_REMOVED;
	bool active = (la->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE) ? true : false;

	*ignore_link = false;
	ntstatus = dsdb_get_extended_dn_guid(dsdb_dn->dn, guid, "GUID");

	if (!NT_STATUS_IS_OK(ntstatus) && !active) {

		/*
		 * This strange behaviour (allowing a NULL/missing
		 * GUID) originally comes from:
		 *
		 * commit e3054ce0fe0f8f62d2f5b2a77893e7a1479128bd
		 * Author: Andrew Tridgell <tridge@samba.org>
		 * Date:   Mon Dec 21 21:21:55 2009 +1100
		 *
		 *  s4-drs: cope better with NULL GUIDS from DRS
		 *
		 *  It is valid to get a NULL GUID over DRS for a deleted forward link. We
		 *  need to match by DN if possible when seeing if we should update an
		 *  existing link.
		 *
		 *  Pair-Programmed-With: Andrew Bartlett <abartlet@samba.org>
		 */
		ret = dsdb_module_search_dn(module, tmp_ctx, &target_res,
					    dsdb_dn->dn, attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_SEARCH_SHOW_RECYCLED |
					    DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
					    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
					    NULL);
	} else if (!NT_STATUS_IS_OK(ntstatus)) {
		ldb_asprintf_errstring(ldb, "Failed to find GUID in linked attribute 0x%x blob for %s from %s",
				       la->attid,
				       ldb_dn_get_linearized(dsdb_dn->dn),
				       ldb_dn_get_linearized(source_dn));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	} else {
		ret = dsdb_module_search(module, tmp_ctx, &target_res,
					 NULL, LDB_SCOPE_SUBTREE,
					 attrs,
					 DSDB_FLAG_NEXT_MODULE |
					 DSDB_SEARCH_SHOW_RECYCLED |
					 DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
					 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
					 NULL,
					 "objectGUID=%s",
					 GUID_string(tmp_ctx, guid));
	}

	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to re-resolve GUID %s: %s\n",
				       GUID_string(tmp_ctx, guid),
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	if (target_res->count == 0) {

		/*
		 * target object is unknown. Check whether to ignore the link,
		 * fail the replication, or add a partial link
		 */
		ret = replmd_allow_missing_target(module, tmp_ctx, dsdb_dn->dn,
						  source_dn, is_obj_commit, guid,
						  la_entry->dsdb_repl_flags,
						  ignore_link, "Unknown");

	} else if (target_res->count != 1) {
		ldb_asprintf_errstring(ldb, "More than one object found matching objectGUID %s\n",
				       GUID_string(tmp_ctx, guid));
		ret = LDB_ERR_OPERATIONS_ERROR;
	} else {
		struct ldb_message *target_msg = target_res->msgs[0];

		dsdb_dn->dn = talloc_steal(dsdb_dn, target_msg->dn);

		/* Get the object's state (i.e. Not Deleted, Tombstone, etc) */
		replmd_deletion_state(module, target_msg,
				      &target_deletion_state, NULL);

		/*
		 * Check for deleted objects as per MS-DRSR 4.1.10.6.14
		 * ProcessLinkValue(). Link updates should not be sent for
		 * recycled and tombstone objects (deleting the links should
		 * happen when we delete the object). This probably means our
		 * copy of the target object isn't up to date.
		 */
		if (target_deletion_state >= OBJECT_RECYCLED) {

			/*
			 * target object is deleted. Check whether to ignore the
			 * link, fail the replication, or add a partial link
			 */
			ret = replmd_allow_missing_target(module, tmp_ctx,
							  dsdb_dn->dn, source_dn,
							  is_obj_commit, guid,
							  la_entry->dsdb_repl_flags,
							  ignore_link, "Deleted");
		}
	}

	talloc_free(tmp_ctx);
	return ret;
}

/**
 * Extracts the key details about the source object for a
 * linked-attribute entry.
 * This returns the following details:
 * @param ret_attr the schema details for the linked attribute
 * @param source_msg the search result for the source object
 */
static int replmd_get_la_entry_source(struct ldb_module *module,
				      struct la_entry *la_entry,
				      TALLOC_CTX *mem_ctx,
				      const struct dsdb_attribute **ret_attr,
				      struct ldb_message **source_msg)
{
	struct drsuapi_DsReplicaLinkedAttribute *la = la_entry->la;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema = dsdb_get_schema(ldb, mem_ctx);
	int ret;
	const struct dsdb_attribute *attr;
	struct ldb_result *res;
	const char *attrs[4];

/*
linked_attributes[0]:
     &objs->linked_attributes[i]: struct drsuapi_DsReplicaLinkedAttribute
        identifier               : *
            identifier: struct drsuapi_DsReplicaObjectIdentifier
                __ndr_size               : 0x0000003a (58)
                __ndr_size_sid           : 0x00000000 (0)
                guid                     : 8e95b6a9-13dd-4158-89db-3220a5be5cc7
                sid                      : S-0-0
                __ndr_size_dn            : 0x00000000 (0)
                dn                       : ''
        attid                    : DRSUAPI_ATTID_member (0x1F)
        value: struct drsuapi_DsAttributeValue
            __ndr_size               : 0x0000007e (126)
            blob                     : *
                blob                     : DATA_BLOB length=126
        flags                    : 0x00000001 (1)
               1: DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE
        originating_add_time     : Wed Sep  2 22:20:01 2009 EST
        meta_data: struct drsuapi_DsReplicaMetaData
            version                  : 0x00000015 (21)
            originating_change_time  : Wed Sep  2 23:39:07 2009 EST
            originating_invocation_id: 794640f3-18cf-40ee-a211-a93992b67a64
            originating_usn          : 0x000000000001e19c (123292)

(for cases where the link is to a normal DN)
     &target: struct drsuapi_DsReplicaObjectIdentifier3
        __ndr_size               : 0x0000007e (126)
        __ndr_size_sid           : 0x0000001c (28)
        guid                     : 7639e594-db75-4086-b0d4-67890ae46031
        sid                      : S-1-5-21-2848215498-2472035911-1947525656-19924
        __ndr_size_dn            : 0x00000022 (34)
        dn                       : 'CN=UOne,OU=TestOU,DC=vsofs8,DC=com'
 */

	/* find the attribute being modified */
	attr = dsdb_attribute_by_attributeID_id(schema, la->attid);
	if (attr == NULL) {
		struct GUID_txt_buf guid_str;
		ldb_asprintf_errstring(ldb, "Unable to find attributeID 0x%x for link on <GUID=%s>",
				       la->attid,
				       GUID_buf_string(&la->identifier->guid,
						       &guid_str));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * All attributes listed here must be dealt with in some way
	 * by replmd_process_linked_attribute() otherwise in the case
	 * of isDeleted: FALSE the modify will fail with:
	 *
	 * Failed to apply linked attribute change 'attribute 'isDeleted':
	 * invalid modify flags on
	 * 'CN=g1_1527570609273,CN=Users,DC=samba,DC=example,DC=com':
	 * 0x0'
	 *
	 * This is becaue isDeleted is a Boolean, so FALSE is a
	 * legitimate value (set by Samba's deletetest.py)
	 */
	attrs[0] = attr->lDAPDisplayName;
	attrs[1] = "isDeleted";
	attrs[2] = "isRecycled";
	attrs[3] = NULL;

	/*
	 * get the existing message from the db for the object with
	 * this GUID, returning attribute being modified. We will then
	 * use this msg as the basis for a modify call
	 */
	ret = dsdb_module_search(module, mem_ctx, &res, NULL, LDB_SCOPE_SUBTREE, attrs,
	                         DSDB_FLAG_NEXT_MODULE |
				 DSDB_SEARCH_SEARCH_ALL_PARTITIONS |
				 DSDB_SEARCH_SHOW_RECYCLED |
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
				 DSDB_SEARCH_REVEAL_INTERNALS,
				 NULL,
				 "objectGUID=%s", GUID_string(mem_ctx, &la->identifier->guid));
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		ldb_asprintf_errstring(ldb, "DRS linked attribute for GUID %s - DN not found",
				       GUID_string(mem_ctx, &la->identifier->guid));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	*source_msg = res->msgs[0];
	*ret_attr = attr;

	return LDB_SUCCESS;
}

/**
 * Verifies the target object is known for a linked attribute
 */
static int replmd_verify_link_target(struct replmd_replicated_request *ar,
				     TALLOC_CTX *mem_ctx,
				     struct la_entry *la_entry,
				     struct ldb_dn *src_dn,
				     const struct dsdb_attribute *attr)
{
	int ret = LDB_SUCCESS;
	struct ldb_module *module = ar->module;
	struct dsdb_dn *tgt_dsdb_dn = NULL;
	struct GUID guid = GUID_zero();
	bool dummy;
	WERROR status;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct drsuapi_DsReplicaLinkedAttribute *la = la_entry->la;
	const struct dsdb_schema *schema = dsdb_get_schema(ldb, mem_ctx);

	/* the value blob for the attribute holds the target object DN */
	status = dsdb_dn_la_from_blob(ldb, attr, schema, mem_ctx,
				      la->value.blob, &tgt_dsdb_dn);
	if (!W_ERROR_IS_OK(status)) {
		ldb_asprintf_errstring(ldb, "Failed to parsed linked attribute blob for %s on %s - %s\n",
				       attr->lDAPDisplayName,
				       ldb_dn_get_linearized(src_dn),
				       win_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * We can skip the target object checks if we're only syncing critical
	 * objects, or we know the target is up-to-date. If either case, we
	 * still continue even if the target doesn't exist
	 */
	if ((la_entry->dsdb_repl_flags & (DSDB_REPL_FLAG_OBJECT_SUBSET |
					  DSDB_REPL_FLAG_TARGETS_UPTODATE)) == 0) {

		ret = replmd_check_target_exists(module, tgt_dsdb_dn, la_entry,
						 src_dn, false, &guid, &dummy);
	}

	/*
	 * When we fail to find the target object, the error code we pass
	 * back here is really important. It flags back to the callers to
	 * retry this request with DRSUAPI_DRS_GET_TGT
	 */
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ret = replmd_replicated_request_werror(ar, WERR_DS_DRA_RECYCLED_TARGET);
	}

	return ret;
}

/**
 * Finds the current active Parsed-DN value for a single-valued linked
 * attribute, if one exists.
 * @param ret_pdn assigned the active Parsed-DN, or NULL if none was found
 * @returns LDB_SUCCESS (regardless of whether a match was found), unless
 * an error occurred
 */
static int replmd_get_active_singleval_link(struct ldb_module *module,
					    TALLOC_CTX *mem_ctx,
					    struct parsed_dn pdn_list[],
					    unsigned int count,
					    const struct dsdb_attribute *attr,
					    struct parsed_dn **ret_pdn)
{
	unsigned int i;

	*ret_pdn = NULL;

	if (!(attr->ldb_schema_attribute->flags & LDB_ATTR_FLAG_SINGLE_VALUE)) {

		/* nothing to do for multi-valued linked attributes */
		return LDB_SUCCESS;
	}

	for (i = 0; i < count; i++) {
		int ret = LDB_SUCCESS;
		struct parsed_dn *pdn = &pdn_list[i];

		/* skip any inactive links */
		if (dsdb_dn_is_deleted_val(pdn->v)) {
			continue;
		}

		/* we've found an active value for this attribute */
		*ret_pdn = pdn;

		if (pdn->dsdb_dn == NULL) {
			struct ldb_context *ldb = ldb_module_get_ctx(module);

			ret = really_parse_trusted_dn(mem_ctx, ldb, pdn,
						      attr->syntax->ldap_oid);
		}

		return ret;
	}

	/* no active link found */
	return LDB_SUCCESS;
}

/**
 * @returns true if the replication linked attribute info is newer than we
 * already have in our DB
 * @param pdn the existing linked attribute info in our DB
 * @param la the new linked attribute info received during replication
 */
static bool replmd_link_update_is_newer(struct parsed_dn *pdn,
					struct drsuapi_DsReplicaLinkedAttribute *la)
{
	/* see if this update is newer than what we have already */
	struct GUID invocation_id = GUID_zero();
	uint32_t version = 0;
	NTTIME change_time = 0;

	if (pdn == NULL) {

		/* no existing info so update is newer */
		return true;
	}

	dsdb_get_extended_dn_guid(pdn->dsdb_dn->dn, &invocation_id, "RMD_INVOCID");
	dsdb_get_extended_dn_uint32(pdn->dsdb_dn->dn, &version, "RMD_VERSION");
	dsdb_get_extended_dn_nttime(pdn->dsdb_dn->dn, &change_time, "RMD_CHANGETIME");

	return replmd_update_is_newer(&invocation_id,
				      &la->meta_data.originating_invocation_id,
				      version,
				      la->meta_data.version,
				      change_time,
				      la->meta_data.originating_change_time);
}

/**
 * Marks an existing linked attribute value as deleted in the DB
 * @param pdn the parsed-DN of the target-value to delete
 */
static int replmd_delete_link_value(struct ldb_module *module,
				    struct replmd_private *replmd_private,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_dn *src_obj_dn,
				    const struct dsdb_schema *schema,
				    const struct dsdb_attribute *attr,
				    uint64_t seq_num,
				    bool is_active,
				    struct GUID *target_guid,
				    struct dsdb_dn *target_dsdb_dn,
				    struct ldb_val *output_val)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	time_t t;
	NTTIME now;
	const struct GUID *invocation_id = NULL;
	int ret;

	t = time(NULL);
	unix_to_nt_time(&now, t);

	invocation_id = samdb_ntds_invocation_id(ldb);
	if (invocation_id == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if the existing link is active, remove its backlink */
	if (is_active) {

		/*
		 * NOTE WELL: After this we will never (at runtime) be
		 * able to find this forward link (for instant
		 * removal) if/when the link target is deleted.
		 *
		 * We have dbcheck rules to cover this and cope otherwise
		 * by filtering at runtime (i.e. in the extended_dn module).
		 */
		ret = replmd_add_backlink(module, replmd_private, schema,
					  src_obj_dn, target_guid, false,
					  attr, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* mark the existing value as deleted */
	ret = replmd_update_la_val(mem_ctx, output_val, target_dsdb_dn,
				   target_dsdb_dn, invocation_id, seq_num,
				   seq_num, now, true);
	return ret;
}

/**
 * Checks for a conflict in single-valued link attributes, and tries to
 * resolve the problem if possible.
 *
 * Single-valued links should only ever have one active value. If we already
 * have an active link value, and during replication we receive an active link
 * value for a different target DN, then we need to resolve this inconsistency
 * and determine which value should be active. If the received info is better/
 * newer than the existing link attribute, then we need to set our existing
 * link as deleted. If the received info is worse/older, then we should continue
 * to add it, but set it as an inactive link.
 *
 * Note that this is a corner-case that is unlikely to happen (but if it does
 * happen, we don't want it to break replication completely).
 *
 * @param pdn_being_modified the parsed DN corresponding to the received link
 * target (note this is NULL if the link does not already exist in our DB)
 * @param pdn_list all the source object's Parsed-DNs for this attribute, i.e.
 * any existing active or inactive values for the attribute in our DB.
 * @param dsdb_dn the target DN for the received link attribute
 * @param add_as_inactive gets set to true if the received link is worse than
 * the existing link - it should still be added, but as an inactive link.
 */
static int replmd_check_singleval_la_conflict(struct ldb_module *module,
					      struct replmd_private *replmd_private,
					      TALLOC_CTX *mem_ctx,
					      struct ldb_dn *src_obj_dn,
					      struct drsuapi_DsReplicaLinkedAttribute *la,
					      struct dsdb_dn *dsdb_dn,
					      struct parsed_dn *pdn_being_modified,
					      struct parsed_dn *pdn_list,
					      struct ldb_message_element *old_el,
					      const struct dsdb_schema *schema,
					      const struct dsdb_attribute *attr,
					      uint64_t seq_num,
					      bool *add_as_inactive)
{
	struct parsed_dn *active_pdn = NULL;
	bool update_is_newer = false;
	int ret;

	/*
	 * check if there's a conflict for single-valued links, i.e. an active
	 * linked attribute already exists, but it has a different target value
	 */
	ret = replmd_get_active_singleval_link(module, mem_ctx, pdn_list,
					       old_el->num_values, attr,
					       &active_pdn);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * If no active value exists (or the received info is for the currently
	 * active value), then no conflict exists
	 */
	if (active_pdn == NULL || active_pdn == pdn_being_modified) {
		return LDB_SUCCESS;
	}

	DBG_WARNING("Link conflict for %s attribute on %s\n",
		    attr->lDAPDisplayName, ldb_dn_get_linearized(src_obj_dn));

	/* Work out how to resolve the conflict based on which info is better */
	update_is_newer = replmd_link_update_is_newer(active_pdn, la);

	if (update_is_newer) {
		DBG_WARNING("Using received value %s, over existing target %s\n",
			    ldb_dn_get_linearized(dsdb_dn->dn),
			    ldb_dn_get_linearized(active_pdn->dsdb_dn->dn));

		/*
		 * Delete our existing active link. The received info will then
		 * be added (through normal link processing) as the active value
		 */
		ret = replmd_delete_link_value(module, replmd_private, old_el,
					       src_obj_dn, schema, attr,
					       seq_num, true, &active_pdn->guid,
					       active_pdn->dsdb_dn,
					       active_pdn->v);

		if (ret != LDB_SUCCESS) {
			return ret;
		}
	} else {
		DBG_WARNING("Using existing target %s, over received value %s\n",
			    ldb_dn_get_linearized(active_pdn->dsdb_dn->dn),
			    ldb_dn_get_linearized(dsdb_dn->dn));

		/*
		 * we want to keep our existing active link and add the
		 * received link as inactive
		 */
		*add_as_inactive = true;
	}

	return LDB_SUCCESS;
}

/**
 * Processes one linked attribute received via replication.
 * @param src_dn the DN of the source object for the link
 * @param attr schema info for the linked attribute
 * @param la_entry the linked attribute info received via DRS
 * @param element_ctx mem context for msg->element[] (when adding a new value
 * we need to realloc old_el->values)
 * @param old_el the corresponding msg->element[] for the linked attribute
 * @param pdn_list a (binary-searchable) parsed DN array for the existing link
 * values in the msg. E.g. for a group, this is the existing members.
 * @param change what got modified: either nothing, an existing link value was
 * modified, or a new link value was added.
 * @returns LDB_SUCCESS if OK, an error otherwise
 */
static int replmd_process_linked_attribute(struct ldb_module *module,
					   TALLOC_CTX *mem_ctx,
					   struct replmd_private *replmd_private,
					   struct ldb_dn *src_dn,
					   const struct dsdb_attribute *attr,
					   struct la_entry *la_entry,
					   struct ldb_request *parent,
					   struct ldb_message_element *old_el,
					   TALLOC_CTX *element_ctx,
					   struct parsed_dn *pdn_list,
					   replmd_link_changed *change)
{
	struct drsuapi_DsReplicaLinkedAttribute *la = la_entry->la;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema = dsdb_get_schema(ldb, mem_ctx);
	int ret;
	struct dsdb_dn *dsdb_dn = NULL;
	uint64_t seq_num = 0;
	struct parsed_dn *pdn, *next;
	struct GUID guid = GUID_zero();
	bool active = (la->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)?true:false;
	bool ignore_link;
	struct dsdb_dn *old_dsdb_dn = NULL;
	struct ldb_val *val_to_update = NULL;
	bool add_as_inactive = false;
	WERROR status;

	*change = LINK_CHANGE_NONE;

	/* the value blob for the attribute holds the target object DN */
	status = dsdb_dn_la_from_blob(ldb, attr, schema, mem_ctx,
				      la->value.blob, &dsdb_dn);
	if (!W_ERROR_IS_OK(status)) {
		ldb_asprintf_errstring(ldb, "Failed to parsed linked attribute blob for %s on %s - %s\n",
				       attr->lDAPDisplayName,
				       ldb_dn_get_linearized(src_dn),
				       win_errstr(status));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = replmd_check_target_exists(module, dsdb_dn, la_entry, src_dn,
					 true, &guid, &ignore_link);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * there are some cases where the target object doesn't exist, but it's
	 * OK to ignore the linked attribute
	 */
	if (ignore_link) {
		return ret;
	}

	/* see if this link already exists */
	ret = parsed_dn_find(ldb, pdn_list, old_el->num_values,
			     &guid,
			     dsdb_dn->dn,
			     dsdb_dn->extra_part, 0,
			     &pdn, &next,
			     attr->syntax->ldap_oid,
			     true);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!replmd_link_update_is_newer(pdn, la)) {
		DEBUG(3,("Discarding older DRS linked attribute update to %s on %s from %s\n",
			 old_el->name, ldb_dn_get_linearized(src_dn),
			 GUID_string(mem_ctx, &la->meta_data.originating_invocation_id)));
		return LDB_SUCCESS;
	}

	/* get a seq_num for this change */
	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * check for single-valued link conflicts, i.e. an active linked
	 * attribute already exists, but it has a different target value
	 */
	if (active) {
		ret = replmd_check_singleval_la_conflict(module, replmd_private,
							 mem_ctx, src_dn, la,
							 dsdb_dn, pdn, pdn_list,
							 old_el, schema, attr,
							 seq_num,
							 &add_as_inactive);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (pdn != NULL) {
		uint32_t rmd_flags = dsdb_dn_rmd_flags(pdn->dsdb_dn->dn);

		if (!(rmd_flags & DSDB_RMD_FLAG_DELETED)) {
			/* remove the existing backlink */
			ret = replmd_add_backlink(module, replmd_private,
						  schema, 
						  src_dn,
						  &pdn->guid, false, attr,
						  parent);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		val_to_update = pdn->v;
		old_dsdb_dn = pdn->dsdb_dn;
		*change = LINK_CHANGE_MODIFIED;

	} else {
		unsigned offset;

		/*
		 * We know where the new one needs to be, from the *next
		 * pointer into pdn_list.
		 */
		if (next == NULL) {
			offset = old_el->num_values;
		} else {
			if (next->dsdb_dn == NULL) {
				ret = really_parse_trusted_dn(mem_ctx, ldb, next,
							      attr->syntax->ldap_oid);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			offset = next - pdn_list;
			if (offset > old_el->num_values) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}

		old_el->values = talloc_realloc(element_ctx, old_el->values,
						struct ldb_val, old_el->num_values+1);
		if (!old_el->values) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (offset != old_el->num_values) {
			memmove(&old_el->values[offset + 1], &old_el->values[offset],
				(old_el->num_values - offset) * sizeof(old_el->values[0]));
		}

		old_el->num_values++;

		val_to_update = &old_el->values[offset];
		old_dsdb_dn = NULL;
		*change = LINK_CHANGE_ADDED;
	}

	/* set the link attribute's value to the info that was received */
	ret = replmd_set_la_val(mem_ctx, val_to_update, dsdb_dn, old_dsdb_dn,
				&la->meta_data.originating_invocation_id,
				la->meta_data.originating_usn, seq_num,
				la->meta_data.originating_change_time,
				la->meta_data.version,
				!active);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (add_as_inactive) {

		/* Set the new link as inactive/deleted to avoid conflicts */
		ret = replmd_delete_link_value(module, replmd_private, old_el,
					       src_dn, schema, attr, seq_num,
					       false, &guid, dsdb_dn,
					       val_to_update);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

	} else if (active) {

		/* if the new link is active, then add the new backlink */
		ret = replmd_add_backlink(module, replmd_private,
					  schema,
					  src_dn,
					  &guid, true, attr,
					  parent);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = dsdb_check_single_valued_link(attr, old_el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	old_el->flags |= LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK;

	return ret;
}

static int replmd_extended(struct ldb_module *module, struct ldb_request *req)
{
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_REPLICATED_OBJECTS_OID) == 0) {
		return replmd_extended_replicated_objects(module, req);
	}

	return ldb_next_request(module, req);
}


/*
  we hook into the transaction operations to allow us to
  perform the linked attribute updates at the end of the whole
  transaction. This allows a forward linked attribute to be created
  before the object is created. During a vampire, w2k8 sends us linked
  attributes before the objects they are part of.
 */
static int replmd_start_transaction(struct ldb_module *module)
{
	/* create our private structure for this transaction */
	struct replmd_private *replmd_private = talloc_get_type(ldb_module_get_private(module),
								struct replmd_private);
	replmd_txn_cleanup(replmd_private);

	/* free any leftover mod_usn records from cancelled
	   transactions */
	while (replmd_private->ncs) {
		struct nc_entry *e = replmd_private->ncs;
		DLIST_REMOVE(replmd_private->ncs, e);
		talloc_free(e);
	}

	replmd_private->originating_updates = false;

	return ldb_next_start_trans(module);
}

/**
 * Processes a group of linked attributes that apply to the same source-object
 * and attribute-ID (and were received in the same replication chunk).
 */
static int replmd_process_la_group(struct ldb_module *module,
				   struct replmd_private *replmd_private,
				   struct la_group *la_group)
{
	struct la_entry *la = NULL;
	struct la_entry *prev = NULL;
	int ret;
	TALLOC_CTX *tmp_ctx = NULL;
	struct la_entry *first_la = DLIST_TAIL(la_group->la_entries);
	struct ldb_message *msg = NULL;
	enum deletion_state deletion_state = OBJECT_NOT_DELETED;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_attribute *attr = NULL;
	struct ldb_message_element *old_el = NULL;
	struct parsed_dn *pdn_list = NULL;
	replmd_link_changed change_type;
	uint32_t num_changes = 0;
	time_t t;
	uint64_t seq_num = 0;

	tmp_ctx = talloc_new(la_group);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	/*
	 * get the attribute being modified and the search result for the
	 * source object
	 */
	ret = replmd_get_la_entry_source(module, first_la, tmp_ctx, &attr,
					 &msg);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * Check for deleted objects per MS-DRSR 4.1.10.6.14
	 * ProcessLinkValue, because link updates are not applied to
	 * recycled and tombstone objects.  We don't have to delete
	 * any existing link, that should have happened when the
	 * object deletion was replicated or initiated.
	 *
	 * This needs isDeleted and isRecycled to be included as
	 * attributes in the search and so in msg if set.
	 */
	replmd_deletion_state(module, msg, &deletion_state, NULL);

	if (deletion_state >= OBJECT_RECYCLED) {
		TALLOC_FREE(tmp_ctx);
		return LDB_SUCCESS;
	}

	/*
	 * Now that we know the deletion_state, remove the extra
	 * attributes added for that purpose.  We need to do this
	 * otherwise in the case of isDeleted: FALSE the modify will
	 * fail with:
	 *
	 * Failed to apply linked attribute change 'attribute 'isDeleted':
	 * invalid modify flags on
	 * 'CN=g1_1527570609273,CN=Users,DC=samba,DC=example,DC=com':
	 * 0x0'
	 *
	 * This is becaue isDeleted is a Boolean, so FALSE is a
	 * legitimate value (set by Samba's deletetest.py)
	 */
	ldb_msg_remove_attr(msg, "isDeleted");
	ldb_msg_remove_attr(msg, "isRecycled");

	/* get the msg->element[] for the link attribute being processed */
	old_el = ldb_msg_find_element(msg, attr->lDAPDisplayName);
	if (old_el == NULL) {
		ret = ldb_msg_add_empty(msg, attr->lDAPDisplayName,
					LDB_FLAG_MOD_REPLACE, &old_el);
		if (ret != LDB_SUCCESS) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		old_el->flags = LDB_FLAG_MOD_REPLACE;
	}

	/*
	 * go through and process the link target value(s) for this particular
	 * source object and attribute. For optimization, the same msg is used
	 * across multiple calls to replmd_process_linked_attribute().
	 * Note that we should not add or remove any msg attributes inside the
	 * loop (we should only add/modify *values* for the attribute being
	 * processed). Otherwise msg->elements is realloc'd and old_el/pdn_list
	 * pointers will be invalidated
	 */
	for (la = DLIST_TAIL(la_group->la_entries); la; la=prev) {
		prev = DLIST_PREV(la);
		DLIST_REMOVE(la_group->la_entries, la);

		/*
		 * parse the existing links (this can be costly for a large
		 * group, so we try to minimize the times we do it)
		 */
		if (pdn_list == NULL) {
			ret = get_parsed_dns_trusted_fallback(module,
							replmd_private,
							tmp_ctx, old_el,
							&pdn_list,
							attr->syntax->ldap_oid,
							NULL);

			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
		ret = replmd_process_linked_attribute(module, tmp_ctx,
						      replmd_private,
						      msg->dn, attr, la, NULL,
						      msg->elements, old_el,
						      pdn_list, &change_type);
		if (ret != LDB_SUCCESS) {
			replmd_txn_cleanup(replmd_private);
			return ret;
		}

		/*
		 * Adding a link reallocs memory, and so invalidates all the
		 * pointers in pdn_list. Reparse the PDNs on the next loop
		 */
		if (change_type == LINK_CHANGE_ADDED) {
			TALLOC_FREE(pdn_list);
		}

		if (change_type != LINK_CHANGE_NONE) {
			num_changes++;
		}

		if ((++replmd_private->num_processed % 8192) == 0) {
			DBG_NOTICE("Processed %u/%u linked attributes\n",
				   replmd_private->num_processed,
				   replmd_private->total_links);
		}
	}

	/*
	 * it's possible we're already up-to-date and so don't need to modify
	 * the object at all (e.g. doing a 'drs replicate --full-sync')
	 */
	if (num_changes == 0) {
		TALLOC_FREE(tmp_ctx);
		return LDB_SUCCESS;
	}

	/*
	 * Note that adding the whenChanged/etc attributes below will realloc
	 * msg->elements, invalidating the existing element/parsed-DN pointers
	 */
	old_el = NULL;
	TALLOC_FREE(pdn_list);

	/* update whenChanged/uSNChanged as the object has changed */
	t = time(NULL);
	ret = ldb_sequence_number(ldb, LDB_SEQ_HIGHEST_SEQ,
				  &seq_num);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = add_time_element(msg, "whenChanged", t);
	if (ret != LDB_SUCCESS) {
		ldb_operr(ldb);
		return ret;
	}

	ret = add_uint64_element(ldb, msg, "uSNChanged", seq_num);
	if (ret != LDB_SUCCESS) {
		ldb_operr(ldb);
		return ret;
	}

	/* apply the link changes to the source object */
	ret = linked_attr_modify(module, msg, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "Failed to apply linked attribute change "
			  "Error: '%s' DN: '%s' Attribute: '%s'\n",
			  ldb_errstring(ldb),
			  ldb_dn_get_linearized(msg->dn),
			  attr->lDAPDisplayName);
		TALLOC_FREE(tmp_ctx);
		return ret;
	}

	TALLOC_FREE(tmp_ctx);
	return LDB_SUCCESS;
}

/*
  on prepare commit we loop over our queued la_context structures and
  apply each of them
 */
static int replmd_prepare_commit(struct ldb_module *module)
{
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(module), struct replmd_private);
	struct la_group *la_group, *prev;
	int ret;

	if (replmd_private->la_list != NULL) {
		DBG_NOTICE("Processing linked attributes\n");
	}

	/*
	 * Walk the list of linked attributes from DRS replication.
	 *
	 * We walk backwards, to do the first entry first, as we
	 * added the entries with DLIST_ADD() which puts them at the
	 * start of the list
	 *
	 * Links are grouped together so we process links for the same
	 * source object in one go.
	 */
	for (la_group = DLIST_TAIL(replmd_private->la_list);
	     la_group != NULL;
	     la_group = prev) {

		prev = DLIST_PREV(la_group);
		DLIST_REMOVE(replmd_private->la_list, la_group);
		ret = replmd_process_la_group(module, replmd_private,
					      la_group);
		if (ret != LDB_SUCCESS) {
			replmd_txn_cleanup(replmd_private);
			return ret;
		}
	}

	replmd_txn_cleanup(replmd_private);

	/* possibly change @REPLCHANGED */
	ret = replmd_notify_store(module, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_prepare_commit(module);
}

static int replmd_del_transaction(struct ldb_module *module)
{
	struct replmd_private *replmd_private =
		talloc_get_type(ldb_module_get_private(module), struct replmd_private);
	replmd_txn_cleanup(replmd_private);

	return ldb_next_del_trans(module);
}


static const struct ldb_module_ops ldb_repl_meta_data_module_ops = {
	.name          = "repl_meta_data",
	.init_context	   = replmd_init,
	.add               = replmd_add,
	.modify            = replmd_modify,
	.rename            = replmd_rename,
	.del	           = replmd_delete,
	.extended          = replmd_extended,
	.start_transaction = replmd_start_transaction,
	.prepare_commit    = replmd_prepare_commit,
	.del_transaction   = replmd_del_transaction,
};

int ldb_repl_meta_data_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_repl_meta_data_module_ops);
}
