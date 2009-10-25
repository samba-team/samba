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

struct part_request {
	struct ldb_module *module;
	struct ldb_request *req;
};

struct partition_context {
	struct ldb_module *module;
	struct ldb_request *req;
	bool got_success;

	struct part_request *part_req;
	int num_requests;
	int finished_requests;
};

static struct partition_context *partition_init_ctx(struct ldb_module *module, struct ldb_request *req)
{
	struct partition_context *ac;

	ac = talloc_zero(req, struct partition_context);
	if (ac == NULL) {
		ldb_set_errstring(ldb_module_get_ctx(module), "Out of Memory");
		return NULL;
	}

	ac->module = module;
	ac->req = req;

	return ac;
}

/*
 *    helper functions to call the next module in chain
 *    */

int partition_request(struct ldb_module *module, struct ldb_request *request)
{
	int ret;
	switch (request->operation) {
	case LDB_SEARCH:
		PARTITION_FIND_OP(module, search);
		ret = module->ops->search(module, request);
		break;
	case LDB_ADD:
		PARTITION_FIND_OP(module, add);
		ret = module->ops->add(module, request);
		break;
	case LDB_MODIFY:
		PARTITION_FIND_OP(module, modify);
		ret = module->ops->modify(module, request);
		break;
	case LDB_DELETE:
		PARTITION_FIND_OP(module, del);
		ret = module->ops->del(module, request);
		break;
	case LDB_RENAME:
		PARTITION_FIND_OP(module, rename);
		ret = module->ops->rename(module, request);
		break;
	case LDB_EXTENDED:
		PARTITION_FIND_OP(module, extended);
		ret = module->ops->extended(module, request);
		break;
	default:
		PARTITION_FIND_OP(module, request);
		ret = module->ops->request(module, request);
		break;
	}
	if (ret == LDB_SUCCESS) {
		return ret;
	}
	if (!ldb_errstring(ldb_module_get_ctx(module))) {
		/* Set a default error string, to place the blame somewhere */
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
					"error in module %s: %s (%d)",
					module->ops->name,
					ldb_strerror(ret), ret);
	}
	return ret;
}

static struct dsdb_partition *find_partition(struct partition_private_data *data,
					     struct ldb_dn *dn,
					     struct ldb_request *req)
{
	int i;
	struct ldb_control *partition_ctrl;

	/* see if the request has the partition DN specified in a
	 * control. The repl_meta_data module can specify this to
	 * ensure that replication happens to the right partition
	 */
	partition_ctrl = ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID);
	if (partition_ctrl) {
		const struct dsdb_control_current_partition *partition;
		partition = talloc_get_type(partition_ctrl->data,
					    struct dsdb_control_current_partition);
		if (partition != NULL) {
			dn = partition->dn;
		}
	}

	if (dn == NULL) {
		return NULL;
	}

	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialisation) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		if (ldb_dn_compare_base(data->partitions[i]->ctrl->dn, dn) == 0) {
			return data->partitions[i];
		}
	}

	return NULL;
}

/**
 * fire the caller's callback for every entry, but only send 'done' once.
 */
static int partition_req_callback(struct ldb_request *req,
				  struct ldb_reply *ares)
{
	struct partition_context *ac;
	struct ldb_module *module;
	struct ldb_request *nreq;
	int ret;
	struct partition_private_data *data;
	struct ldb_control *partition_ctrl;

	ac = talloc_get_type(req->context, struct partition_context);
	data = talloc_get_type(ac->module->private_data, struct partition_private_data);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	partition_ctrl = ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID);
	if (partition_ctrl && (ac->num_requests == 1 || ares->type == LDB_REPLY_ENTRY)) {
		/* If we didn't fan this request out to mulitple partitions,
		 * or this is an individual search result, we can
		 * deterministily tell the caller what partition this was
		 * written to (repl_meta_data likes to know) */
			ret = ldb_reply_add_control(ares,
						    DSDB_CONTROL_CURRENT_PARTITION_OID,
						    false, partition_ctrl->data);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL,
						       ret);
			}
	}

	if (ares->error != LDB_SUCCESS && !ac->got_success) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_REFERRAL:
		/* ignore referrals for now */
		break;

	case LDB_REPLY_ENTRY:
		if (ac->req->operation != LDB_SEARCH) {
			ldb_set_errstring(ldb_module_get_ctx(ac->module),
				"partition_req_callback:"
				" Unsupported reply type for this request");
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}
		
		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_DONE:
		if (ares->error == LDB_SUCCESS) {
			ac->got_success = true;
		}
		if (ac->req->operation == LDB_EXTENDED) {
			/* FIXME: check for ares->response, replmd does not fill it ! */
			if (ares->response) {
				if (strcmp(ares->response->oid, LDB_EXTENDED_START_TLS_OID) != 0) {
					ldb_set_errstring(ldb_module_get_ctx(ac->module),
							  "partition_req_callback:"
							  " Unknown extended reply, "
							  "only supports START_TLS");
					talloc_free(ares);
					return ldb_module_done(ac->req, NULL, NULL,
								LDB_ERR_OPERATIONS_ERROR);
				}
			}
		}

		ac->finished_requests++;
		if (ac->finished_requests == ac->num_requests) {
			/* this was the last one, call callback */
			return ldb_module_done(ac->req, ares->controls,
					       ares->response, 
					       ac->got_success?LDB_SUCCESS:ares->error);
		}

		/* not the last, now call the next one */
		module = ac->part_req[ac->finished_requests].module;
		nreq = ac->part_req[ac->finished_requests].req;

		ret = partition_request(module, nreq);
		if (ret != LDB_SUCCESS) {
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		break;
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int partition_prep_request(struct partition_context *ac,
				  struct dsdb_partition *partition)
{
	int ret;
	struct ldb_request *req;

	ac->part_req = talloc_realloc(ac, ac->part_req,
					struct part_request,
					ac->num_requests + 1);
	if (ac->part_req == NULL) {
		ldb_oom(ldb_module_get_ctx(ac->module));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	switch (ac->req->operation) {
	case LDB_SEARCH:
		ret = ldb_build_search_req_ex(&req, ldb_module_get_ctx(ac->module),
					ac->part_req,
					ac->req->op.search.base,
					ac->req->op.search.scope,
					ac->req->op.search.tree,
					ac->req->op.search.attrs,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	case LDB_ADD:
		ret = ldb_build_add_req(&req, ldb_module_get_ctx(ac->module), ac->part_req,
					ac->req->op.add.message,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	case LDB_MODIFY:
		ret = ldb_build_mod_req(&req, ldb_module_get_ctx(ac->module), ac->part_req,
					ac->req->op.mod.message,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	case LDB_DELETE:
		ret = ldb_build_del_req(&req, ldb_module_get_ctx(ac->module), ac->part_req,
					ac->req->op.del.dn,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	case LDB_RENAME:
		ret = ldb_build_rename_req(&req, ldb_module_get_ctx(ac->module), ac->part_req,
					ac->req->op.rename.olddn,
					ac->req->op.rename.newdn,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	case LDB_EXTENDED:
		ret = ldb_build_extended_req(&req, ldb_module_get_ctx(ac->module),
					ac->part_req,
					ac->req->op.extended.oid,
					ac->req->op.extended.data,
					ac->req->controls,
					ac, partition_req_callback,
					ac->req);
		break;
	default:
		ldb_set_errstring(ldb_module_get_ctx(ac->module),
				  "Unsupported request type!");
		ret = LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->part_req[ac->num_requests].req = req;

	if (ac->req->controls) {
		req->controls = talloc_memdup(req, ac->req->controls,
					talloc_get_size(ac->req->controls));
		if (req->controls == NULL) {
			ldb_oom(ldb_module_get_ctx(ac->module));
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (partition) {
		ac->part_req[ac->num_requests].module = partition->module;

		if (!ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID)) {
			ret = ldb_request_add_control(req,
						      DSDB_CONTROL_CURRENT_PARTITION_OID,
						      false, partition->ctrl);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		if (req->operation == LDB_SEARCH) {
			/* If the search is for 'more' than this partition,
			 * then change the basedn, so a remote LDAP server
			 * doesn't object */
			if (ldb_dn_compare_base(partition->ctrl->dn,
						req->op.search.base) != 0) {
				req->op.search.base = partition->ctrl->dn;
			}
		}

	} else {
		/* make sure you put the NEXT module here, or
		 * partition_request() will simply loop forever on itself */
		ac->part_req[ac->num_requests].module = ac->module->next;
	}

	ac->num_requests++;

	return LDB_SUCCESS;
}

static int partition_call_first(struct partition_context *ac)
{
	return partition_request(ac->part_req[0].module, ac->part_req[0].req);
}

/**
 * Send a request down to all the partitions
 */
static int partition_send_all(struct ldb_module *module, 
			      struct partition_context *ac, 
			      struct ldb_request *req) 
{
	int i;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	int ret = partition_prep_request(ac, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		ret = partition_prep_request(ac, data->partitions[i]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* fire the first one */
	return partition_call_first(ac);
}

/**
 * Figure out which backend a request needs to be aimed at.  Some
 * requests must be replicated to all backends
 */
static int partition_replicate(struct ldb_module *module, struct ldb_request *req, struct ldb_dn *dn) 
{
	struct partition_context *ac;
	unsigned i;
	int ret;
	struct dsdb_partition *partition;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	if (!data || !data->partitions) {
		return ldb_next_request(module, req);
	}

	if (req->operation != LDB_SEARCH) {
		/* Is this a special DN, we need to replicate to every backend? */
		for (i=0; data->replicate && data->replicate[i]; i++) {
			if (ldb_dn_compare(data->replicate[i], 
					   dn) == 0) {
				
				ac = partition_init_ctx(module, req);
				if (!ac) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
				
				return partition_send_all(module, ac, req);
			}
		}
	}

	/* Otherwise, we need to find the partition to fire it to */

	/* Find partition */
	partition = find_partition(data, dn, req);
	if (!partition) {
		/*
		 * if we haven't found a matching partition
		 * pass the request to the main ldb
		 *
		 * TODO: we should maybe return an error here
		 *       if it's not a special dn
		 */

		return ldb_next_request(module, req);
	}

	ac = partition_init_ctx(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we need to add a control but we never touch the original request */
	ret = partition_prep_request(ac, partition);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* fire the first one */
	return partition_call_first(ac);
}

/* search */
static int partition_search(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_control **saved_controls;
	/* Find backend */
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);

	/* issue request */

	/* (later) consider if we should be searching multiple
	 * partitions (for 'invisible' partition behaviour */

	struct ldb_control *search_control = ldb_request_get_control(req, LDB_CONTROL_SEARCH_OPTIONS_OID);
	struct ldb_control *domain_scope_control = ldb_request_get_control(req, LDB_CONTROL_DOMAIN_SCOPE_OID);
	
	struct ldb_search_options_control *search_options = NULL;
	struct dsdb_partition *p;
	
	ret = partition_reload_if_required(module, data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	p = find_partition(data, NULL, req);
	if (p != NULL) {
		/* the caller specified what partition they want the
		 * search - just pass it on
		 */
		return ldb_next_request(p->module, req);		
	}


	if (search_control) {
		search_options = talloc_get_type(search_control->data, struct ldb_search_options_control);
	}

	/* Remove the domain_scope control, so we don't confuse a backend server */
	if (domain_scope_control && !save_controls(domain_scope_control, req, &saved_controls)) {
		ldb_oom(ldb_module_get_ctx(module));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * for now pass down the LDB_CONTROL_SEARCH_OPTIONS_OID control
	 * down as uncritical to make windows 2008 dcpromo happy.
	 */
	if (search_control) {
		search_control->critical = 0;
	}

	/* TODO:
	   Generate referrals (look for a partition under this DN) if we don't have the above control specified
	*/
	
	if (search_options && (search_options->search_options & LDB_SEARCH_OPTION_PHANTOM_ROOT)) {
		int i;
		struct partition_context *ac;
		if ((search_options->search_options & ~LDB_SEARCH_OPTION_PHANTOM_ROOT) == 0) {
			/* We have processed this flag, so we are done with this control now */

			/* Remove search control, so we don't confuse a backend server */
			if (search_control && !save_controls(search_control, req, &saved_controls)) {
				ldb_oom(ldb_module_get_ctx(module));
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		ac = partition_init_ctx(module, req);
		if (!ac) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* Search from the base DN */
		if (!req->op.search.base || ldb_dn_is_null(req->op.search.base)) {
			return partition_send_all(module, ac, req);
		}
		for (i=0; data && data->partitions && data->partitions[i]; i++) {
			bool match = false, stop = false;
			/* Find all partitions under the search base 
			   
			   we match if:

			      1) the DN we are looking for exactly matches the partition
		             or
			      2) the DN we are looking for is a parent of the partition and it isn't
                                 a scope base search
                             or
			      3) the DN we are looking for is a child of the partition
			 */
			if (ldb_dn_compare(data->partitions[i]->ctrl->dn, req->op.search.base) == 0) {
				match = true;
				if (req->op.search.scope == LDB_SCOPE_BASE) {
					stop = true;
				}
			}
			if (!match && 
			    (ldb_dn_compare_base(req->op.search.base, data->partitions[i]->ctrl->dn) == 0 &&
			     req->op.search.scope != LDB_SCOPE_BASE)) {
				match = true;
			}
			if (!match &&
			    ldb_dn_compare_base(data->partitions[i]->ctrl->dn, req->op.search.base) == 0) {
				match = true;
				stop = true; /* note that this relies on partition ordering */
			}
			if (match) {
				ret = partition_prep_request(ac, data->partitions[i]);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			if (stop) break;
		}

		/* Perhaps we didn't match any partitions.  Try the main partition, only */
		if (ac->num_requests == 0) {
			talloc_free(ac);
			return ldb_next_request(module, req);
		}

		/* fire the first one */
		return partition_call_first(ac);

	} else {
		/* Handle this like all other requests */
		if (search_control && (search_options->search_options & ~LDB_SEARCH_OPTION_PHANTOM_ROOT) == 0) {
			/* We have processed this flag, so we are done with this control now */

			/* Remove search control, so we don't confuse a backend server */
			if (search_control && !save_controls(search_control, req, &saved_controls)) {
				ldb_oom(ldb_module_get_ctx(module));
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}

		return partition_replicate(module, req, req->op.search.base);
	}
}

/* add */
static int partition_add(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.add.message->dn);
}

/* modify */
static int partition_modify(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.mod.message->dn);
}

/* delete */
static int partition_delete(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.del.dn);
}

/* rename */
static int partition_rename(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct dsdb_partition *backend, *backend2;
	
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);

	/* Skip the lot if 'data' isn't here yet (initialisation) */
	if (!data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	backend = find_partition(data, req->op.rename.olddn, req);
	backend2 = find_partition(data, req->op.rename.newdn, req);

	if ((backend && !backend2) || (!backend && backend2)) {
		return LDB_ERR_AFFECTS_MULTIPLE_DSAS;
	}

	if (backend != backend2) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), 
				       "Cannot rename from %s in %s to %s in %s: %s",
				       ldb_dn_get_linearized(req->op.rename.olddn),
				       ldb_dn_get_linearized(backend->ctrl->dn),
				       ldb_dn_get_linearized(req->op.rename.newdn),
				       ldb_dn_get_linearized(backend2->ctrl->dn),
				       ldb_strerror(LDB_ERR_AFFECTS_MULTIPLE_DSAS));
		return LDB_ERR_AFFECTS_MULTIPLE_DSAS;
	}

	return partition_replicate(module, req, req->op.rename.olddn);
}

/* start a transaction */
static int partition_start_trans(struct ldb_module *module)
{
	int i, ret;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialization) */
	ret = ldb_next_start_trans(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = partition_reload_if_required(module, data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = data->partitions[i]->module;
		PARTITION_FIND_OP(next, start_transaction);

		ret = next->ops->start_transaction(next);
		if (ret != LDB_SUCCESS) {
			/* Back it out, if it fails on one */
			for (i--; i >= 0; i--) {
				next = data->partitions[i]->module;
				PARTITION_FIND_OP(next, del_transaction);

				next->ops->del_transaction(next);
			}
			ldb_next_del_trans(module);
			return ret;
		}
	}

	data->in_transaction++;

	return LDB_SUCCESS;
}

/* prepare for a commit */
static int partition_prepare_commit(struct ldb_module *module)
{
	int i;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);

	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next_prepare = data->partitions[i]->module;
		int ret;

		PARTITION_FIND_OP_NOERROR(next_prepare, prepare_commit);
		if (next_prepare == NULL) {
			continue;
		}

		ret = next_prepare->ops->prepare_commit(next_prepare);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return ldb_next_prepare_commit(module);
}


/* end a transaction */
static int partition_end_trans(struct ldb_module *module)
{
	int i;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next_end = data->partitions[i]->module;
		int ret;

		PARTITION_FIND_OP(next_end, end_transaction);

		ret = next_end->ops->end_transaction(next_end);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (data->in_transaction == 0) {
		DEBUG(0,("partition end transaction mismatch\n"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	data->in_transaction--;

	return ldb_next_end_trans(module);
}

/* delete a transaction */
static int partition_del_trans(struct ldb_module *module)
{
	int i, ret, final_ret = LDB_SUCCESS;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = data->partitions[i]->module;
		PARTITION_FIND_OP(next, del_transaction);

		ret = next->ops->del_transaction(next);
		if (ret != LDB_SUCCESS) {
			final_ret = ret;
		}
	}	

	if (data->in_transaction == 0) {
		DEBUG(0,("partition del transaction mismatch\n"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	data->in_transaction--;

	ret = ldb_next_del_trans(module);
	if (ret != LDB_SUCCESS) {
		final_ret = ret;
	}
	return final_ret;
}

int partition_primary_sequence_number(struct ldb_module *module, TALLOC_CTX *mem_ctx, 
				     enum ldb_sequence_type type, uint64_t *seq_number) 
{
	int ret;
	struct ldb_result *res;
	struct ldb_seqnum_request *tseq;
	struct ldb_request *treq;
	struct ldb_seqnum_result *seqr;
	res = talloc_zero(mem_ctx, struct ldb_result);
	if (res == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	tseq = talloc_zero(res, struct ldb_seqnum_request);
	if (tseq == NULL) {
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	tseq->type = type;
	
	ret = ldb_build_extended_req(&treq, ldb_module_get_ctx(module), res,
				     LDB_EXTENDED_SEQUENCE_NUMBER,
				     tseq,
				     NULL,
				     res,
				     ldb_extended_default_callback,
				     NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}
	
	ret = ldb_next_request(module, treq);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}
	ret = ldb_wait(treq->handle, LDB_WAIT_ALL);
	if (ret != LDB_SUCCESS) {
		talloc_free(res);
		return ret;
	}
	
	seqr = talloc_get_type(res->extended->data,
			       struct ldb_seqnum_result);
	if (seqr->flags & LDB_SEQ_TIMESTAMP_SEQUENCE) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		ldb_set_errstring(ldb_module_get_ctx(module), "Primary backend in partitions module returned a timestamp based seq number (must return a normal number)");
		talloc_free(res);
		return ret;
	} else {
		*seq_number = seqr->seq_num;
	}
	talloc_free(res);
	return LDB_SUCCESS;
}

/* FIXME: This function is still semi-async */
static int partition_sequence_number(struct ldb_module *module, struct ldb_request *req)
{
	int i, ret;
	uint64_t seq_number = 0;
	uint64_t timestamp_sequence = 0;
	uint64_t timestamp = 0;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	struct ldb_seqnum_request *seq;
	struct ldb_seqnum_result *seqr;
	struct ldb_request *treq;
	struct ldb_seqnum_request *tseq;
	struct ldb_seqnum_result *tseqr;
	struct ldb_extended *ext;
	struct ldb_result *res;
	struct dsdb_partition *p;

	p = find_partition(data, NULL, req);
	if (p != NULL) {
		/* the caller specified what partition they want the
		 * sequence number operation on - just pass it on
		 */
		return ldb_next_request(p->module, req);		
	}

	seq = talloc_get_type(req->op.extended.data, struct ldb_seqnum_request);

	switch (seq->type) {
	case LDB_SEQ_NEXT:
	case LDB_SEQ_HIGHEST_SEQ:

		ret = partition_primary_sequence_number(module, req, seq->type, &seq_number);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* Skip the lot if 'data' isn't here yet (initialisation) */
		for (i=0; data && data->partitions && data->partitions[i]; i++) {

			res = talloc_zero(req, struct ldb_result);
			if (res == NULL) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			tseq = talloc_zero(res, struct ldb_seqnum_request);
			if (tseq == NULL) {
				talloc_free(res);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			tseq->type = seq->type;

			ret = ldb_build_extended_req(&treq, ldb_module_get_ctx(module), res,
						     LDB_EXTENDED_SEQUENCE_NUMBER,
						     tseq,
						     NULL,
						     res,
						     ldb_extended_default_callback,
						     NULL);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}

			if (!ldb_request_get_control(treq, DSDB_CONTROL_CURRENT_PARTITION_OID)) {
				ret = ldb_request_add_control(treq,
							      DSDB_CONTROL_CURRENT_PARTITION_OID,
							      false, data->partitions[i]->ctrl);
				if (ret != LDB_SUCCESS) {
					talloc_free(res);
					return ret;
				}
			}

			ret = partition_request(data->partitions[i]->module, treq);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}
			ret = ldb_wait(treq->handle, LDB_WAIT_ALL);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}
			tseqr = talloc_get_type(res->extended->data,
						struct ldb_seqnum_result);
			if (tseqr->flags & LDB_SEQ_TIMESTAMP_SEQUENCE) {
				timestamp_sequence = MAX(timestamp_sequence,
							 tseqr->seq_num);
			} else {
				seq_number += tseqr->seq_num;
			}
			talloc_free(res);
		}
		/* fall through */
	case LDB_SEQ_HIGHEST_TIMESTAMP:

		res = talloc_zero(req, struct ldb_result);
		if (res == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		tseq = talloc_zero(res, struct ldb_seqnum_request);
		if (tseq == NULL) {
			talloc_free(res);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		tseq->type = LDB_SEQ_HIGHEST_TIMESTAMP;

		ret = ldb_build_extended_req(&treq, ldb_module_get_ctx(module), res,
					     LDB_EXTENDED_SEQUENCE_NUMBER,
					     tseq,
					     NULL,
					     res,
					     ldb_extended_default_callback,
					     NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(res);
			return ret;
		}

		ret = ldb_next_request(module, treq);
		if (ret != LDB_SUCCESS) {
			talloc_free(res);
			return ret;
		}
		ret = ldb_wait(treq->handle, LDB_WAIT_ALL);
		if (ret != LDB_SUCCESS) {
			talloc_free(res);
			return ret;
		}

		tseqr = talloc_get_type(res->extended->data,
					   struct ldb_seqnum_result);
		timestamp = tseqr->seq_num;

		talloc_free(res);

		/* Skip the lot if 'data' isn't here yet (initialisation) */
		for (i=0; data && data->partitions && data->partitions[i]; i++) {

			res = talloc_zero(req, struct ldb_result);
			if (res == NULL) {
				return LDB_ERR_OPERATIONS_ERROR;
			}

			tseq = talloc_zero(res, struct ldb_seqnum_request);
			if (tseq == NULL) {
				talloc_free(res);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			tseq->type = LDB_SEQ_HIGHEST_TIMESTAMP;

			ret = ldb_build_extended_req(&treq, ldb_module_get_ctx(module), res,
						     LDB_EXTENDED_SEQUENCE_NUMBER,
						     tseq,
						     NULL,
						     res,
						     ldb_extended_default_callback,
						     NULL);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}

			if (!ldb_request_get_control(treq, DSDB_CONTROL_CURRENT_PARTITION_OID)) {
				ret = ldb_request_add_control(treq,
							      DSDB_CONTROL_CURRENT_PARTITION_OID,
							      false, data->partitions[i]->ctrl);
				if (ret != LDB_SUCCESS) {
					talloc_free(res);
					return ret;
				}
			}

			ret = partition_request(data->partitions[i]->module, treq);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}
			ret = ldb_wait(treq->handle, LDB_WAIT_ALL);
			if (ret != LDB_SUCCESS) {
				talloc_free(res);
				return ret;
			}

			tseqr = talloc_get_type(res->extended->data,
						  struct ldb_seqnum_result);
			timestamp = MAX(timestamp, tseqr->seq_num);

			talloc_free(res);
		}

		break;
	}

	ext = talloc_zero(req, struct ldb_extended);
	if (!ext) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	seqr = talloc_zero(ext, struct ldb_seqnum_result);
	if (seqr == NULL) {
		talloc_free(ext);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ext->oid = LDB_EXTENDED_SEQUENCE_NUMBER;
	ext->data = seqr;

	switch (seq->type) {
	case LDB_SEQ_NEXT:
	case LDB_SEQ_HIGHEST_SEQ:

		/* Has someone above set a timebase sequence? */
		if (timestamp_sequence) {
			seqr->seq_num = (((unsigned long long)timestamp << 24) | (seq_number & 0xFFFFFF));
		} else {
			seqr->seq_num = seq_number;
		}

		if (timestamp_sequence > seqr->seq_num) {
			seqr->seq_num = timestamp_sequence;
			seqr->flags |= LDB_SEQ_TIMESTAMP_SEQUENCE;
		}

		seqr->flags |= LDB_SEQ_GLOBAL_SEQUENCE;
		break;
	case LDB_SEQ_HIGHEST_TIMESTAMP:
		seqr->seq_num = timestamp;
		break;
	}

	if (seq->type == LDB_SEQ_NEXT) {
		seqr->seq_num++;
	}

	/* send request done */
	return ldb_module_done(req, NULL, ext, LDB_SUCCESS);
}

/* extended */
static int partition_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct partition_private_data *data;
	struct partition_context *ac;
	int ret;

	data = talloc_get_type(module->private_data, struct partition_private_data);
	if (!data) {
		return ldb_next_request(module, req);
	}

	ret = partition_reload_if_required(module, data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	if (strcmp(req->op.extended.oid, LDB_EXTENDED_SEQUENCE_NUMBER) == 0) {
		return partition_sequence_number(module, req);
	}

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_CREATE_PARTITION_OID) == 0) {
		return partition_create(module, req);
	}

	/* 
	 * as the extended operation has no dn
	 * we need to send it to all partitions
	 */

	ac = partition_init_ctx(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return partition_send_all(module, ac, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_partition_module_ops = {
	.name		   = "partition",
	.init_context	   = partition_init,
	.search            = partition_search,
	.add               = partition_add,
	.modify            = partition_modify,
	.del               = partition_delete,
	.rename            = partition_rename,
	.extended          = partition_extended,
	.start_transaction = partition_start_trans,
	.prepare_commit    = partition_prepare_commit,
	.end_transaction   = partition_end_trans,
	.del_transaction   = partition_del_trans,
};
