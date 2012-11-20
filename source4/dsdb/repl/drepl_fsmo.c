/*
   Unix SMB/CIFS mplementation.

   DSDB replication service - FSMO role change

   Copyright (C) Nadezhda Ivanova 2010
   Copyright (C) Andrew Tridgell 2010
   Copyright (C) Andrew Bartlett 2010
   Copyright (C) Anatoliy Atanasov 2010

   based on drepl_ridalloc.c

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
#include "smbd/service.h"
#include "dsdb/repl/drepl_service.h"
#include "param/param.h"

struct fsmo_role_state {
	struct irpc_message *msg;
	struct drepl_takeFSMORole *r;
};

static void drepl_role_callback(struct dreplsrv_service *service,
				WERROR werr,
				enum drsuapi_DsExtendedError ext_err,
				void *cb_data)
{
	struct fsmo_role_state *fsmo = talloc_get_type_abort(cb_data, struct fsmo_role_state);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(2,(__location__ ": Failed role transfer - %s - extended_ret[0x%X]\n",
			 win_errstr(werr), ext_err));
	} else {
		DEBUG(2,(__location__ ": Successful role transfer\n"));
	}
	fsmo->r->out.result = werr;
	irpc_send_reply(fsmo->msg, NT_STATUS_OK);
}

/*
  see which role is we are asked to assume, initialize data and send request
 */
NTSTATUS drepl_take_FSMO_role(struct irpc_message *msg,
			      struct drepl_takeFSMORole *r)
{
	struct dreplsrv_service *service = talloc_get_type(msg->private_data,
							   struct dreplsrv_service);
	struct ldb_dn *role_owner_dn, *fsmo_role_dn;
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	uint64_t fsmo_info = 0;
	enum drsuapi_DsExtendedOperation extended_op = DRSUAPI_EXOP_NONE;
	WERROR werr;
	enum drepl_role_master role = r->in.role;
	struct fsmo_role_state *fsmo;
	bool is_us;
	int ret;

	werr = dsdb_get_fsmo_role_info(tmp_ctx, service->samdb, role,
				       &fsmo_role_dn, &role_owner_dn);
	if (!W_ERROR_IS_OK(werr)) {
		talloc_free(tmp_ctx);
		r->out.result = werr;
		return NT_STATUS_OK;
	}

	switch (role) {
	case DREPL_NAMING_MASTER:
	case DREPL_INFRASTRUCTURE_MASTER:
	case DREPL_SCHEMA_MASTER:
		extended_op = DRSUAPI_EXOP_FSMO_REQ_ROLE;
		break;
	case DREPL_RID_MASTER:
		extended_op = DRSUAPI_EXOP_FSMO_RID_REQ_ROLE;
		break;
	case DREPL_PDC_MASTER:
		extended_op = DRSUAPI_EXOP_FSMO_REQ_PDC;
		break;
	default:
		DEBUG(2,("Unknown role %u in role transfer\n",
			 (unsigned)role));
		r->out.result = WERR_DS_DRA_INTERNAL_ERROR;
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	ret = samdb_dn_is_our_ntdsa(service->samdb, role_owner_dn, &is_us);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("FSMO role check failed (failed to confirm if our ntdsDsa) for DN %s and owner %s \n",
			 ldb_dn_get_linearized(fsmo_role_dn),
			 ldb_dn_get_linearized(role_owner_dn)));
		talloc_free(tmp_ctx);
		r->out.result = WERR_DS_DRA_INTERNAL_ERROR;
		return NT_STATUS_OK;
	}
	
	if (is_us) {
		DEBUG(5,("FSMO role check failed, we already own DN %s with %s\n",
			 ldb_dn_get_linearized(fsmo_role_dn),
			 ldb_dn_get_linearized(role_owner_dn)));
		r->out.result = WERR_OK;
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	fsmo = talloc(msg, struct fsmo_role_state);
	NT_STATUS_HAVE_NO_MEMORY(fsmo);

	fsmo->msg = msg;
	fsmo->r   = r;

	werr = drepl_request_extended_op(service,
					 fsmo_role_dn,
					 role_owner_dn,
					 extended_op,
					 fsmo_info,
					 0,
					 drepl_role_callback,
					 fsmo);
	if (!W_ERROR_IS_OK(werr)) {
		r->out.result = werr;
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	/* mark this message to be answered later */
	msg->defer_reply = true;
	dreplsrv_run_pending_ops(service);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}
