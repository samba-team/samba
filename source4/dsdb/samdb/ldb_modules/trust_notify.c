/*
   ldb database library

   Copyright (C) Stefan Metzmacher 2025

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
#include "param/param.h"
#include "ldb_module.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/messaging/irpc.h"

struct trust_notify_private {
	bool notify_winbind;
};

static void trust_notify_winbind_server(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *frame = talloc_stackframe();
	struct imessaging_context *imsg_ctx = NULL;
	struct loadparm_context *lp_ctx= NULL;
	struct server_id *server_ids = NULL;
	uint32_t num_server_ids = 0;
	NTSTATUS status;

	lp_ctx = ldb_get_opaque(ldb, "loadparm");
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return;
	}

	imsg_ctx = imessaging_client_init(frame, lp_ctx,
					  ldb_get_event_context(ldb));
	if (imsg_ctx == NULL) {
		ldb_asprintf_errstring(ldb,
				       "imessaging_client_init failed in %s",
				       lpcfg_imessaging_path(frame, lp_ctx));
		TALLOC_FREE(frame);
		return;
	}

	status = irpc_servers_byname(imsg_ctx,
				     frame,
				     "winbind_server",
				     &num_server_ids,
				     &server_ids);
	if (NT_STATUS_IS_OK(status) && num_server_ids >= 1) {
		imessaging_send(imsg_ctx,
				server_ids[0],
				MSG_WINBIND_RELOAD_TRUSTED_DOMAINS,
				NULL);
	}
	TALLOC_FREE(frame);
}

static bool trust_notify_has_watched_attrs(const struct ldb_message *msg)
{
	static const char * const trust_attrs[] = {
		/*
		 * We only use attributes used
		 * and cached by winbindd.
		 */

		/*
		 * These are from the trustedDomain objects
		 */
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"msDS-TrustForestTrustInfo",
		"trustAuthIncoming",
		"trustAuthOutgoing",
		"msDS-SupportedEncryptionTypes",
		"msDS-IngressClaimsTransformationPolicy",
		"msDS-EgressClaimsTransformationPolicy",

		/*
		 * These are from the crossRefContainer object
		 */
		"uPNSuffixes",
		"msDS-SPNSuffixes",

		/*
		 * These are from the crossRef objects
		 *
		 * Very unlikely to ever change
		 */
		"dnsRoot",
		"nETBIOSName",

		NULL
	};
	size_t ti;

	for (ti = 0; trust_attrs[ti] != NULL; ti++) {
		const struct ldb_message_element *el = NULL;

		el = ldb_msg_find_element(msg, trust_attrs[ti]);
		if (el != NULL) {
			return true;
		}
	}

	return false;
}

static int trust_notify_add(struct ldb_module *module, struct ldb_request *req)
{
	struct trust_notify_private *data = NULL;
	bool found = false;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct trust_notify_private);

	found = trust_notify_has_watched_attrs(req->op.add.message);
	if (found) {
		data->notify_winbind = true;
	}

	return ldb_next_request(module, req);
}

static int trust_notify_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct trust_notify_private *data = NULL;
	bool found = false;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct trust_notify_private);

	found = trust_notify_has_watched_attrs(req->op.add.message);
	if (found) {
		data->notify_winbind = true;
	}

	return ldb_next_request(module, req);
}

static int trust_notify_delete(struct ldb_module *module, struct ldb_request *req)
{
	TALLOC_CTX *frame = NULL;
	struct trust_notify_private *data = NULL;
	struct ldb_result *res = NULL;
	const char * const attrs[] = { "objectClass", NULL };
	const char * const classes[] = {
		/*
		 * these must be in the correct spelling
		 * as in the schema!
		 */
		"trustedDomain",
		"crossRef",
		NULL
	};
	size_t ci;
	int ret;

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct trust_notify_private);

	frame = talloc_stackframe();

	ret = dsdb_module_search_dn(module, frame, &res, req->op.del.dn,
				    attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_SEARCH_SHOW_RECYCLED |
				    DSDB_SEARCH_REVEAL_INTERNALS |
				    DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				    req);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return ret;
	}

	for (ci = 0; classes[ci] != NULL; ci++) {
		ret = ldb_msg_check_string_attribute(res->msgs[0],
						     "objectClass",
						     classes[ci]);
		if (ret == 0) {
			continue;
		}
		data->notify_winbind = true;
		break;
	}

	TALLOC_FREE(frame);
	return ldb_next_request(module, req);
}

static int trust_notify_start_trans(struct ldb_module *module)
{
	struct trust_notify_private *data =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct trust_notify_private);

	data->notify_winbind = false;

	return ldb_next_start_trans(module);
}

static int trust_notify_end_trans(struct ldb_module *module)
{
	struct trust_notify_private *data =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct trust_notify_private);
	int ret;

	ret = ldb_next_end_trans(module);
	if (ret == LDB_SUCCESS) {
		if (data->notify_winbind) {
			trust_notify_winbind_server(module);
		}
	}

	return ret;
}

static int trust_notify_del_trans(struct ldb_module *module)
{
	struct trust_notify_private *data =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct trust_notify_private);

	data->notify_winbind = false;

	return ldb_next_del_trans(module);
}

static int trust_notify_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct trust_notify_private *data = NULL;

	data = talloc_zero(module, struct trust_notify_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	ldb_module_set_private(module, data);

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_trust_notify_module_ops = {
	.name              = "trust_notify",
	.init_context      = trust_notify_init,
	.add               = trust_notify_add,
	.modify            = trust_notify_modify,
	.del               = trust_notify_delete,
	.start_transaction = trust_notify_start_trans,
	.end_transaction   = trust_notify_end_trans,
	.del_transaction   = trust_notify_del_trans,
};

int ldb_trust_notify_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_trust_notify_module_ops);
}
