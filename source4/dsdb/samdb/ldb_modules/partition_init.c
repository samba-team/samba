/* 
   Partitions ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

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
 *  Component: ldb partitions module
 *
 *  Description: Implement LDAP partitions
 *
 *  Author: Andrew Bartlett
 *  Author: Stefan Metzmacher
 */

#include "dsdb/samdb/ldb_modules/partition.h"
static int partition_sort_compare(const void *v1, const void *v2)
{
	const struct dsdb_partition *p1;
	const struct dsdb_partition *p2;

	p1 = *((struct dsdb_partition * const*)v1);
	p2 = *((struct dsdb_partition * const*)v2);

	return ldb_dn_compare(p1->ctrl->dn, p2->ctrl->dn);
}

/* Load the list of DNs that we must replicate to all partitions */
static int partition_load_replicate_dns(struct ldb_context *ldb, struct partition_private_data *data, struct ldb_message *msg) 
{
	struct ldb_message_element *replicate_attributes = ldb_msg_find_element(msg, "replicateEntries");

	talloc_free(data->replicate);
	if (!replicate_attributes) {
		data->replicate = NULL;
	} else {
		int i;
		data->replicate = talloc_array(data, struct ldb_dn *, replicate_attributes->num_values + 1);
		if (!data->replicate) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		for (i=0; i < replicate_attributes->num_values; i++) {
			data->replicate[i] = ldb_dn_from_ldb_val(data->replicate, ldb, &replicate_attributes->values[i]);
			if (!ldb_dn_validate(data->replicate[i])) {
				ldb_asprintf_errstring(ldb,
							"partition_init: "
							"invalid DN in partition replicate record: %s", 
							replicate_attributes->values[i].data);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}
		data->replicate[i] = NULL;
	}
	return LDB_SUCCESS;
}

/* Load the list of modules for the partitions */
static int partition_load_modules(struct ldb_context *ldb, 
				  struct partition_private_data *data, struct ldb_message *msg) 
{
	int i;
	struct ldb_message_element *modules_attributes = ldb_msg_find_element(msg, "modules");
	talloc_free(data->modules);
	if (!modules_attributes) {
		return LDB_SUCCESS;
	}
	
	data->modules = talloc_array(data, struct partition_module *, modules_attributes->num_values + 1);
	if (!data->modules) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	for (i=0; i < modules_attributes->num_values; i++) {
		char *base;
		char *p;

		data->modules[i] = talloc(data->modules, struct partition_module);
		if (!data->modules[i]) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		base = talloc_strdup(data->partitions, (char *)modules_attributes->values[i].data);
		p = strchr(base, ':');
		if (!p) {
			ldb_asprintf_errstring(ldb, 
					       "partition_load_modules: "
					       "invalid form for partition module record (missing ':'): %s", base);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		p[0] = '\0';
		p++;
		data->modules[i]->modules = ldb_modules_list_from_string(ldb, data->modules[i],
									 p);
		
		if (strcmp(base, "*") == 0) {
			data->modules[i]->dn = NULL;
		} else {
			data->modules[i]->dn = ldb_dn_new(data->modules[i], ldb, base);
			if (!data->modules[i]->dn || !ldb_dn_validate(data->modules[i]->dn)) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
	}
	return LDB_SUCCESS;
}

static int partition_reload_metadata(struct ldb_module *module, struct partition_private_data *data, TALLOC_CTX *mem_ctx, struct ldb_message **_msg) 
{
	int ret;
	struct ldb_message *msg;
	struct ldb_result *res;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const char *attrs[] = { "partition", "replicateEntries", "modules", NULL };
	/* perform search for @PARTITION, looking for module, replicateEntries and ldapBackend */
	ret = dsdb_module_search_dn(module, mem_ctx, &res, 
				    ldb_dn_new(mem_ctx, ldb, DSDB_PARTITION_DN),
				    attrs);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	msg = res->msgs[0];

	ret = partition_load_replicate_dns(ldb, data, msg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = partition_load_modules(ldb, data, msg);			
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	data->ldapBackend = talloc_steal(data, ldb_msg_find_attr_as_string(msg, "ldapBackend", NULL));
	if (_msg) {
		*_msg = msg;
	} else {
		talloc_free(msg);
	}
	return LDB_SUCCESS;
}

int partition_reload_if_required(struct ldb_module *module, 
				 struct partition_private_data *data)
	
{
	uint64_t seq;
	int ret;
	TALLOC_CTX *mem_ctx = talloc_new(data);
	if (!data) {
		/* Not initilised yet */
		return LDB_SUCCESS;
	}
	if (!mem_ctx) {
		ldb_oom(ldb_module_get_ctx(module));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = partition_primary_sequence_number(module, mem_ctx, LDB_SEQ_HIGHEST_SEQ, &seq);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}
	if (seq != data->metadata_seq) {
		ret = partition_reload_metadata(module, data, mem_ctx, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
		data->metadata_seq = seq;
	}
	talloc_free(mem_ctx);
	return LDB_SUCCESS;
}

static const char **find_modules_for_dn(struct partition_private_data *data, struct ldb_dn *dn) 
{
	int i;
	struct partition_module *default_mod = NULL;
	for (i=0; data->modules && data->modules[i]; i++) {
		if (!data->modules[i]->dn) {
			default_mod = data->modules[i];
		} else if (ldb_dn_compare(dn, data->modules[i]->dn) == 0) {
			return data->modules[i]->modules;
		}
	}
	if (default_mod) {
		return default_mod->modules;
	} else {
		return NULL;
	}
}

static int new_partition_from_dn(struct ldb_context *ldb, struct partition_private_data *data, 
				 TALLOC_CTX *mem_ctx, 
				 struct ldb_dn *dn, const char *casefold_dn,
				 struct dsdb_partition **partition) {
	const char *backend_name;
	const char *full_backend;
	struct dsdb_control_current_partition *ctrl;
	struct ldb_module *module;
	const char **modules;
	int ret;

	(*partition) = talloc(mem_ctx, struct dsdb_partition);
	if (!*partition) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	(*partition)->ctrl = ctrl = talloc((*partition), struct dsdb_control_current_partition);
	if (!ctrl) {
		talloc_free(*partition);
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* See if an LDAP backend has been specified */
	if (data->ldapBackend) {
		backend_name = data->ldapBackend;
	} else {

		/* the backend LDB is the DN (base64 encoded if not 'plain') followed by .ldb */
		const char *p;
		char *base64_dn = NULL;
		for (p = casefold_dn; *p; p++) {
			/* We have such a strict check because I don't want shell metacharacters in the file name, nor ../ */
			if (!(isalnum(*p) || *p == ' ' || *p == '=' || *p == ',')) {
				break;
			}
		}
		if (*p) {
			casefold_dn = base64_dn = ldb_base64_encode(data, casefold_dn, strlen(casefold_dn));
		}
		
		backend_name = talloc_asprintf(data, "%s.ldb", casefold_dn); 
		if (base64_dn) {
			talloc_free(base64_dn);
		}
	}

	ctrl->version = DSDB_CONTROL_CURRENT_PARTITION_VERSION;
	ctrl->dn = talloc_steal(ctrl, dn);
	
	full_backend = samdb_relative_path(ldb, 
					   *partition, 
					   backend_name);
	if (!full_backend) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), 
				       "partition_init: unable to determine an relative path for partition: %s", backend_name);
		talloc_free(*partition);
		return LDB_ERR_OPERATIONS_ERROR;		
	}

	ret = ldb_connect_backend(ldb, full_backend, NULL, &module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	modules = find_modules_for_dn(data, dn);

	ret = ldb_load_modules_list(ldb, modules, module, &(*partition)->module);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "partition_init: "
				       "loading backend for %s failed: %s", 
				       ldb_dn_get_linearized(dn), ldb_errstring(ldb));
		talloc_free(*partition);
		return ret;
	}
	ret = ldb_init_module_chain(ldb, (*partition)->module);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
				       "partition_init: "
				       "initialising backend for %s failed: %s", 
				       ldb_dn_get_linearized(dn), ldb_errstring(ldb));
		talloc_free(*partition);
		return ret;
	}

	talloc_steal((*partition), (*partition)->module);

	return ret;
}

/* Copy the metadata (@OPTIONS etc) for the new partition into the partition */

static int new_partition_set_replicated_metadata(struct ldb_context *ldb, 
						 struct ldb_module *module, struct ldb_request *last_req, 
						 struct partition_private_data *data, 
						 struct dsdb_partition *partition)
{
	int i, ret;
	/* for each replicate, copy from main partition.  If we get an error, we report it up the chain */
	for (i=0; data->replicate && data->replicate[i]; i++) {
		struct ldb_result *replicate_res;
		struct ldb_request *add_req;
		ret = dsdb_module_search_dn(module, last_req, &replicate_res, 
					    data->replicate[i],
					    NULL);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			continue;
		}
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb,
					       "Failed to search for %s from " DSDB_PARTITION_DN 
					       " replicateEntries for new partition at %s: %s", 
					       ldb_dn_get_linearized(data->replicate[i]), 
					       ldb_dn_get_linearized(partition->ctrl->dn), 
					       ldb_errstring(ldb));
			return ret;
		}

		/* Build add request */
		ret = ldb_build_add_req(&add_req, ldb, replicate_res, 
					replicate_res->msgs[0], NULL, NULL, 
					ldb_op_default_callback, last_req);
		last_req = add_req;
		if (ret != LDB_SUCCESS) {
			/* return directly, this is a very unlikely error */
			return ret;
		}
		/* do request */
		ret = ldb_next_request(partition->module, add_req);
		/* wait */
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(add_req->handle, LDB_WAIT_ALL);
		}
		
		switch (ret) {
		case LDB_SUCCESS:
			break;

		case LDB_ERR_ENTRY_ALREADY_EXISTS:
			/* Handle this case specially - if the
			 * metadata already exists, replace it */
		{
			struct ldb_request *del_req;
			
			/* Don't leave a confusing string in the ldb_errstring() */
			ldb_reset_err_string(ldb);
			/* Build del request */
			ret = ldb_build_del_req(&del_req, ldb, replicate_res, replicate_res->msgs[0]->dn, NULL, NULL, 
						ldb_op_default_callback, last_req);
			last_req = del_req;
			if (ret != LDB_SUCCESS) {
				/* return directly, this is a very unlikely error */
				return ret;
			}
			/* do request */
			ret = ldb_next_request(partition->module, del_req);
			
			/* wait */
			if (ret == LDB_SUCCESS) {
				ret = ldb_wait(del_req->handle, LDB_WAIT_ALL);
			}
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb,
						       "Failed to delete  (for re-add) %s from " DSDB_PARTITION_DN 
						       " replicateEntries in new partition at %s: %s", 
						       ldb_dn_get_linearized(data->replicate[i]), 
						       ldb_dn_get_linearized(partition->ctrl->dn), 
						       ldb_errstring(ldb));
				return ret;
			}
			
			/* Build add request */
			ret = ldb_build_add_req(&add_req, ldb, replicate_res, replicate_res->msgs[0], NULL, NULL, 
						ldb_op_default_callback, last_req);
			last_req = add_req;
			if (ret != LDB_SUCCESS) {
				/* return directly, this is a very unlikely error */
				return ret;
			}
			
			/* do the add again */
			ret = ldb_next_request(partition->module, add_req);
			
			/* wait */
			if (ret == LDB_SUCCESS) {
				ret = ldb_wait(add_req->handle, LDB_WAIT_ALL);
			}

			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb,
						       "Failed to add (after delete) %s from " DSDB_PARTITION_DN 
						       " replicateEntries to new partition at %s: %s", 
						       ldb_dn_get_linearized(data->replicate[i]), 
						       ldb_dn_get_linearized(partition->ctrl->dn), 
						       ldb_errstring(ldb));
				return ret;
			}
			break;
		}
		default: 
		{
			ldb_asprintf_errstring(ldb,
					       "Failed to add %s from " DSDB_PARTITION_DN 
					       " replicateEntries to new partition at %s: %s", 
					       ldb_dn_get_linearized(data->replicate[i]), 
					       ldb_dn_get_linearized(partition->ctrl->dn), 
					       ldb_errstring(ldb));
			return ret;
		}
		}

		/* And around again, for the next thing we must merge */
	}
	return LDB_SUCCESS;
}

static int partition_register(struct ldb_context *ldb, struct dsdb_control_current_partition *ctrl, TALLOC_CTX *mem_ctx) 
{
	struct ldb_request *req;
	int ret;

	req = talloc_zero(mem_ctx, struct ldb_request);
	if (req == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
		
	req->operation = LDB_REQ_REGISTER_PARTITION;
	req->op.reg_partition.dn = ctrl->dn;
	req->callback = ldb_op_default_callback;

	ldb_set_timeout(ldb, req, 0);
	
	req->handle = ldb_handle_new(req, ldb);
	if (req->handle == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "partition: Unable to register partition with rootdse!\n");
		talloc_free(mem_ctx);
		return LDB_ERR_OTHER;
	}
	talloc_free(req);

	return LDB_SUCCESS;
}

int partition_create(struct ldb_module *module, struct ldb_request *req)
{
	int i, ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *mod_req, *last_req = req;
	struct ldb_message *mod_msg;
	struct partition_private_data *data;
	struct dsdb_partition *partition = NULL;
	const char *casefold_dn;
	bool new_partition = false;

	/* Check if this is already a partition */

	struct dsdb_create_partition_exop *ex_op = talloc_get_type(req->op.extended.data, struct dsdb_create_partition_exop);
	struct ldb_dn *dn = ex_op->new_dn;

	data = talloc_get_type(module->private_data, struct partition_private_data);
	if (!data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	if (!data) {
		/* We are not going to create a partition before we are even set up */
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ret = partition_reload_metadata(module, data, req, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
		
	for (i=0; data->partitions && data->partitions[i]; i++) {
		if (ldb_dn_compare(data->partitions[i]->ctrl->dn, dn) == 0) {
			partition = data->partitions[i];
		}
	}

	if (!partition) {
		new_partition = true;
		mod_msg = ldb_msg_new(req);
		if (!mod_msg) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		mod_msg->dn = ldb_dn_new(mod_msg, ldb, DSDB_PARTITION_DN);
		ret = ldb_msg_add_empty(mod_msg, DSDB_PARTITION_ATTR, LDB_FLAG_MOD_ADD, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		casefold_dn = ldb_dn_get_casefold(dn);
		
		ret = ldb_msg_add_string(mod_msg, DSDB_PARTITION_ATTR, casefold_dn);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* Perform modify on @PARTITION record */
		ret = ldb_build_mod_req(&mod_req, ldb, req, mod_msg, NULL, NULL, 
					ldb_op_default_callback, req);
		
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		last_req = mod_req;

		ret = ldb_next_request(module, mod_req);
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(mod_req->handle, LDB_WAIT_ALL);
		}
		
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* Make a partition structure for this new partition, so we can copy in the template structure */ 
		ret = new_partition_from_dn(ldb, data, req, ldb_dn_copy(req, dn), casefold_dn, &partition);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* Start a transaction on the DB (as it won't be in one being brand new) */
		{
			struct ldb_module *next = partition->module;
			PARTITION_FIND_OP(next, start_transaction);
			
			ret = next->ops->start_transaction(next);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	
	ret = new_partition_set_replicated_metadata(ldb, module, last_req, data, partition);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	if (new_partition) {
		/* Count the partitions */
		for (i=0; data->partitions && data->partitions[i]; i++) { /* noop */};
		
		/* Add partition to list of partitions */
		data->partitions = talloc_realloc(data, data->partitions, struct dsdb_partition *, i + 2);
		if (!data->partitions) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		data->partitions[i] = talloc_steal(data->partitions, partition);
		data->partitions[i+1] = NULL;
		
		/* Sort again (should use binary insert) */
		qsort(data->partitions, i+1,
		      sizeof(*data->partitions), partition_sort_compare);
		
		ret = partition_register(ldb, partition->ctrl, req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* send request done */
	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}


int partition_init(struct ldb_module *module)
{
	int ret, i;
	TALLOC_CTX *mem_ctx = talloc_new(module);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message *msg;
	struct ldb_message_element *partition_attributes;

	struct partition_private_data *data;

	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data = talloc_zero(mem_ctx, struct partition_private_data);
	if (data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = partition_primary_sequence_number(module, mem_ctx, LDB_SEQ_HIGHEST_SEQ, &data->metadata_seq);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = partition_reload_metadata(module, data, mem_ctx, &msg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	partition_attributes = ldb_msg_find_element(msg, "partition");
	if (!partition_attributes) {
		data->partitions = NULL;
	} else {
		data->partitions = talloc_array(data, struct dsdb_partition *, partition_attributes->num_values + 1);
		if (!data->partitions) {
			ldb_oom(ldb_module_get_ctx(module));
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}
	for (i=0; partition_attributes && i < partition_attributes->num_values; i++) {
		struct ldb_dn *dn = ldb_dn_from_ldb_val(mem_ctx, ldb, &partition_attributes->values[i]);
		if (!dn) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module), 
					       "partition_init: invalid DN in partition record: %s", (const char *)partition_attributes->values[i].data);
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	
		/* We call ldb_dn_get_linearized() because the DN in
		 * partition_attributes is already casefolded
		 * correctly.  We don't want to mess that up as the
		 * schema isn't loaded yet */
		ret = new_partition_from_dn(ldb, data, data->partitions, dn, 
					    ldb_dn_get_linearized(dn),
					    &data->partitions[i]);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
	}

	if (data->partitions) {
		data->partitions[i] = NULL;

		/* sort these into order, most to least specific */
		qsort(data->partitions, partition_attributes->num_values,
		      sizeof(*data->partitions), partition_sort_compare);
	}

	for (i=0; data->partitions && data->partitions[i]; i++) {
		ret = partition_register(ldb, data->partitions[i]->ctrl, mem_ctx);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = ldb_mod_register_control(module, LDB_CONTROL_DOMAIN_SCOPE_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb_module_get_ctx(module), LDB_DEBUG_ERROR,
			"partition: Unable to register control with rootdse!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mod_register_control(module, LDB_CONTROL_SEARCH_OPTIONS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb_module_get_ctx(module), LDB_DEBUG_ERROR,
			"partition: Unable to register control with rootdse!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	module->private_data = talloc_steal(module, data);

	talloc_free(mem_ctx);
	return ldb_next_init(module);
}
