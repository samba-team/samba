/*
   Unix SMB/CIFS implementation.
   KCC service periodic handling

   Copyright (C) Crístian Deives

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
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/messaging/irpc.h"
#include "dsdb/kcc/kcc_service.h"
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"

void kccsrv_apply_connections(struct ldb_dn **connections)
{
}

void kccsrv_create_connection(struct kccsrv_service *s, struct repsFromTo1 *r1)
{
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *new_dn, *server_dn;
	struct GUID guid;
	const struct GUID *invocation_id;
	struct ldb_val schedule_val;
	int ret;
	bool ok;

	tmp_ctx = talloc_new(s);
	new_dn = samdb_ntds_settings_dn(s->samdb);
	if (!new_dn) {
		DEBUG(0, ("failed to find NTDS settings\n"));
		goto done;
	}
	invocation_id = samdb_ntds_invocation_id(s->samdb);
	guid = GUID_random();
	ok = ldb_dn_add_child_fmt(new_dn, "CN=%s", GUID_string(tmp_ctx, &guid));
	if (!ok) {
		DEBUG(0, ("failed to create nTDSConnection DN\n"));
		goto done;
	}
	ret = dsdb_find_dn_by_guid(s->samdb, tmp_ctx, GUID_string(tmp_ctx,
				   &r1->source_dsa_obj_guid), &server_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("failed to find fromServer DN '%s'\n",
			  GUID_string(tmp_ctx, &r1->source_dsa_obj_guid)));
		goto done;
	}
	schedule_val = data_blob_const(r1->schedule, sizeof(r1->schedule));

	msg = ldb_msg_new(tmp_ctx);
	msg->dn = new_dn;
	ldb_msg_add_string(msg, "invocationID",
			   GUID_string(tmp_ctx, invocation_id));
	ldb_msg_add_string(msg, "objectClass", "nTDSConnection");
	ldb_msg_add_string(msg, "showInAdvancedViewOnly", "TRUE");
	ldb_msg_add_string(msg, "enabledConnection", "TRUE");
	/* ldb_msg_add_dn(msg, "fromServer", server_dn); */
	ldb_msg_add_string(msg, "fromServer", ldb_dn_get_linearized(server_dn));
	ldb_msg_add_value(msg, "schedule", &schedule_val, NULL);
	ldb_msg_add_string(msg, "options", "1");

	ret = ldb_add(s->samdb, msg);
	if (ret == LDB_SUCCESS) {
		DEBUG(2, ("added nTDSConnection object '%s'\n",
			  ldb_dn_get_linearized(new_dn)));
	} else {
		DEBUG(0, ("failed to add an nTDSConnection object: %s\n",
			  ldb_strerror(ret)));
	}

done:
	talloc_free(tmp_ctx);
}

struct ldb_dn **kccsrv_find_connections(struct kccsrv_service *s,
					TALLOC_CTX *mem_ctx)
{
	struct ldb_result *res;
	int ret, i;
	const char *attrs[] = { "distinguishedName", NULL };
	struct ldb_dn **connections;

	ret = ldb_search(s->samdb, mem_ctx, &res, s->config_dn,
			 LDB_SCOPE_ONELEVEL, attrs, "objectClass=nTDSDSA");
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("failed nTDSDSA search: %s\n", ldb_strerror(ret)));
		return NULL;
	}

	for (i = 0; i < res->count; i++) {
		connections = talloc_realloc(mem_ctx, connections,
					     struct ldb_dn *, i + 1);
		connections[i] = samdb_result_dn(s->samdb, mem_ctx,
						 res->msgs[i],
						 "distinguishedName", NULL);
	}
	connections = talloc_realloc(mem_ctx, connections, struct ldb_dn *,
				     i + 1);
	connections[i] = NULL;
	return connections;
}
