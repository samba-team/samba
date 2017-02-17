/*
   ldb database library

   Copyright (C) Samuel Cabrero <samuelcabrero@kernevil.me> 2014

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
 *  Component: ldb dns_notify module
 *
 *  Description: Notify the DNS server when zones are changed, either by direct
 *  		 RPC management calls or DRS inbound replication.
 *
 *  Author: Samuel Cabrero <samuelcabrero@kernevil.me>
 */

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/proto.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "param/param.h"
#include "util/dlinklist.h"

struct dns_notify_watched_dn {
	struct dns_notify_watched_dn *next, *prev;
	struct ldb_dn *dn;
};

struct dns_notify_private {
	struct dns_notify_watched_dn *watched;
	bool reload_zones;
};

struct dns_notify_dnssrv_state {
	struct imessaging_context *msg_ctx;
	struct dnssrv_reload_dns_zones r;
};

static void dns_notify_dnssrv_done(struct tevent_req *req)
{
	NTSTATUS status;
	struct dns_notify_dnssrv_state *state;

	state = tevent_req_callback_data(req, struct dns_notify_dnssrv_state);

	status = dcerpc_dnssrv_reload_dns_zones_r_recv(req, state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("%s: Error notifying dns server: %s\n",
		      __func__, nt_errstr(status)));
	}
	imessaging_cleanup(state->msg_ctx);

	talloc_free(req);
	talloc_free(state);
}

static void dns_notify_dnssrv_send(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct loadparm_context *lp_ctx;
	struct dns_notify_dnssrv_state *state;
	struct dcerpc_binding_handle *handle;
	struct tevent_req *req;

	ldb = ldb_module_get_ctx(module);

	lp_ctx = ldb_get_opaque(ldb, "loadparm");
	if (lp_ctx == NULL) {
		return;
	}

	state = talloc_zero(module, struct dns_notify_dnssrv_state);
	if (state == NULL) {
		return;
	}

	/* Initialize messaging client */
	state->msg_ctx = imessaging_client_init(state, lp_ctx,
						ldb_get_event_context(ldb));
	if (state->msg_ctx == NULL) {
		ldb_asprintf_errstring(ldb, "Failed to generate client messaging context in %s",
				       lpcfg_imessaging_path(state, lp_ctx));
		talloc_free(state);
		return;
	}

	/* Get a handle to notify the DNS server */
	handle = irpc_binding_handle_by_name(state, state->msg_ctx,
					     "dnssrv",
					     &ndr_table_irpc);
	if (handle == NULL) {
		imessaging_cleanup(state->msg_ctx);
		talloc_free(state);
		return;
	}

	/* Send the notifications */
	req = dcerpc_dnssrv_reload_dns_zones_r_send(state,
						    ldb_get_event_context(ldb),
						    handle,
						    &state->r);
	if (req == NULL) {
		imessaging_cleanup(state->msg_ctx);
		talloc_free(state);
		return;
	}
	tevent_req_set_callback(req, dns_notify_dnssrv_done, state);
}

static int dns_notify_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct dns_notify_private *data;
	struct dns_notify_watched_dn *w;
	struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	for (w = data->watched; w; w = w->next) {
		if (ldb_dn_compare_base(w->dn, req->op.add.message->dn) == 0) {
			schema = dsdb_get_schema(ldb, req);
			if (schema == NULL) {
				return ldb_operr(ldb);
			}

			objectclass = dsdb_get_structural_oc_from_msg(schema, req->op.add.message);
			if (objectclass == NULL) {
				return ldb_operr(ldb);
			}

			if (ldb_attr_cmp(objectclass->lDAPDisplayName, "dnsZone") == 0) {
				data->reload_zones = true;
				break;
			}
		}
	}

	return ldb_next_request(module, req);
}

static int dns_notify_modify(struct ldb_module *module, struct ldb_request *req)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_context *ldb;
	struct dns_notify_private *data;
	struct dns_notify_watched_dn *w;
	struct ldb_dn *dn;
	struct ldb_result *res;
	struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	const char * const attrs[] = { "objectClass", NULL };
	int ret;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	tmp_ctx = talloc_new(module);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (w = data->watched; w; w = w->next) {
		if (ldb_dn_compare_base(w->dn, req->op.add.message->dn) == 0) {
			dn = ldb_dn_copy(tmp_ctx, req->op.mod.message->dn);

			ret = dsdb_module_search_dn(module, tmp_ctx, &res, dn, attrs,
						    DSDB_FLAG_NEXT_MODULE |
						    DSDB_SEARCH_SHOW_RECYCLED |
						    DSDB_SEARCH_REVEAL_INTERNALS |
						    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT, req);
			if (ret != LDB_SUCCESS) {
				/* 
				 * We want the give the caller the
				 * error from trying the actual
				 * request, below 
				 */
				break;
			}

			schema = dsdb_get_schema(ldb, req);
			if (schema == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			objectclass = dsdb_get_structural_oc_from_msg(schema, res->msgs[0]);
			if (objectclass == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			if (ldb_attr_cmp(objectclass->lDAPDisplayName, "dnsZone") == 0) {
				data->reload_zones = true;
				break;
			}
		}
	}

	talloc_free(tmp_ctx);
	return ldb_next_request(module, req);
}

static int dns_notify_delete(struct ldb_module *module, struct ldb_request *req)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_context *ldb;
	struct dns_notify_private *data;
	struct dns_notify_watched_dn *w;
	struct ldb_dn *old_dn;
	struct ldb_result *res;
	struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	const char * const attrs[] = { "objectClass", NULL };
	int ret;

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	tmp_ctx = talloc_new(module);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (w = data->watched; w; w = w->next) {
		if (ldb_dn_compare_base(w->dn, req->op.add.message->dn) == 0) {
			old_dn = ldb_dn_copy(tmp_ctx, req->op.del.dn);
			ret = dsdb_module_search_dn(module, tmp_ctx, &res, old_dn, attrs,
						    DSDB_FLAG_NEXT_MODULE |
						    DSDB_SEARCH_SHOW_RECYCLED |
						    DSDB_SEARCH_REVEAL_INTERNALS |
						    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT, req);
			if (ret != LDB_SUCCESS) {
				/* 
				 * We want the give the caller the
				 * error from trying the actual
				 * request, below 
				 */
				break;
			}

			schema = dsdb_get_schema(ldb, req);
			if (schema == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			objectclass = dsdb_get_structural_oc_from_msg(schema, res->msgs[0]);
			if (objectclass == NULL) {
				talloc_free(tmp_ctx);
				return ldb_operr(ldb);
			}

			if (ldb_attr_cmp(objectclass->lDAPDisplayName, "dnsZone") == 0) {
				data->reload_zones = true;
				break;
			}
		}
	}

	talloc_free(tmp_ctx);
	return ldb_next_request(module, req);
}

static int dns_notify_start_trans(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct dns_notify_private *data;

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	data->reload_zones = false;

	return ldb_next_start_trans(module);
}

static int dns_notify_end_trans(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct dns_notify_private *data;
	int ret;

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	ret = ldb_next_end_trans(module);
	if (ret == LDB_SUCCESS) {
		if (data->reload_zones) {
			dns_notify_dnssrv_send(module);
		}
	}

	return ret;
}

static int dns_notify_del_trans(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct dns_notify_private *data;

	ldb = ldb_module_get_ctx(module);
	data = talloc_get_type(ldb_module_get_private(module),
			       struct dns_notify_private);
	if (data == NULL) {
		return ldb_operr(ldb);
	}

	data->reload_zones = false;

	return ldb_next_del_trans(module);
}

static int dns_notify_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct dns_notify_private *data;
	struct dns_notify_watched_dn *watched;
	struct ldb_dn *domain_dn;
	struct ldb_dn *forest_dn;

	ldb = ldb_module_get_ctx(module);

	data = talloc_zero(module, struct dns_notify_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	domain_dn = ldb_get_default_basedn(ldb);
	forest_dn = ldb_get_root_basedn(ldb);

	/* Register hook on domain partition */
	watched = talloc_zero(data, struct dns_notify_watched_dn);
	if (watched == NULL) {
		talloc_free(data);
		return ldb_oom(ldb);
	}
	watched->dn = ldb_dn_new_fmt(watched, ldb,
				     "CN=MicrosoftDNS,CN=System,%s",
				     ldb_dn_get_linearized(domain_dn));
	if (watched->dn == NULL) {
		talloc_free(data);
		return ldb_oom(ldb);
	}
	DLIST_ADD(data->watched, watched);

	/* Check for DomainDnsZones partition and register hook */
	watched = talloc_zero(data, struct dns_notify_watched_dn);
	if (watched == NULL) {
		talloc_free(data);
		return ldb_oom(ldb);
	}
	watched->dn = ldb_dn_new_fmt(watched, ldb, "CN=MicrosoftDNS,DC=DomainDnsZones,%s", ldb_dn_get_linearized(forest_dn));
	DLIST_ADD(data->watched, watched);

	/* Check for ForestDnsZones partition and register hook */
	watched = talloc_zero(data, struct dns_notify_watched_dn);
	if (watched == NULL) {
		talloc_free(data);
		return ldb_oom(ldb);
	}
	watched->dn = ldb_dn_new_fmt(watched, ldb, "CN=MicrosoftDNS,DC=ForestDnsZones,%s", ldb_dn_get_linearized(forest_dn));
	DLIST_ADD(data->watched, watched);

	ldb_module_set_private(module, data);

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_dns_notify_module_ops = {
	.name              = "dns_notify",
	.init_context      = dns_notify_init,
	.add               = dns_notify_add,
	.modify            = dns_notify_modify,
	.del               = dns_notify_delete,
	.start_transaction = dns_notify_start_trans,
	.end_transaction   = dns_notify_end_trans,
	.del_transaction   = dns_notify_del_trans,
};

int ldb_dns_notify_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_dns_notify_module_ops);
}
