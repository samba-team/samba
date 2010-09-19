/*
   Unix SMB/CIFS mplementation.

   DSDB replication service - FSMO role change

   Copyright (C) Nadezhda Ivanova 2010
   Copyright (C) Andrew Tridgell 2010
   Copyright (C) Andrew Bartlett 2010

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
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"

static void drepl_role_callback(struct dreplsrv_service *service,
				WERROR werr,
				enum drsuapi_DsExtendedError ext_err,
				void *cb_data)
{
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,(__location__ ": Failed role transfer - %s - extended_ret[0x%X]\n",
			 win_errstr(werr), ext_err));
	} else {
		DEBUG(0,(__location__ ": Successful role transfer\n"));
	}
}

static bool fsmo_master_cmp(struct ldb_dn *ntds_dn, struct ldb_dn *role_owner_dn)
{
	if (ldb_dn_compare(ntds_dn, role_owner_dn) == 0) {
		DEBUG(0,("\nWe are the FSMO master.\n"));
		return true;
	}
	return false;
}

/*
  see which role is we are asked to assume, initialize data and send request
 */
WERROR dreplsrv_fsmo_role_check(struct dreplsrv_service *service,
				uint32_t role)
{
	struct ldb_dn *role_owner_dn, *fsmo_role_dn, *ntds_dn;
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	struct ldb_context *ldb = service->samdb;
	int ret;
	uint64_t fsmo_info = 0;
	enum drsuapi_DsExtendedOperation extended_op = DRSUAPI_EXOP_NONE;
	WERROR werr;

	ntds_dn = samdb_ntds_settings_dn(ldb);
	if (!ntds_dn) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	switch (role) {
	case DREPL_NAMING_MASTER:
		fsmo_role_dn = samdb_partitions_dn(ldb, tmp_ctx);
		ret = samdb_reference_dn(ldb, tmp_ctx, fsmo_role_dn, "fSMORoleOwner", &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Naming Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		extended_op = DRSUAPI_EXOP_FSMO_REQ_ROLE;
		break;
	case DREPL_INFRASTRUCTURE_MASTER:
		fsmo_role_dn = samdb_infrastructure_dn(ldb, tmp_ctx);
		ret = samdb_reference_dn(ldb, tmp_ctx, fsmo_role_dn, "fSMORoleOwner", &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		extended_op = DRSUAPI_EXOP_FSMO_REQ_ROLE;
		break;
	case DREPL_RID_MASTER:
		ret = samdb_rid_manager_dn(ldb, tmp_ctx, &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, (__location__ ": Failed to find RID Manager object - %s", ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(ldb, tmp_ctx, fsmo_role_dn, "fSMORoleOwner", &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in RID Manager object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		extended_op = DRSUAPI_EXOP_FSMO_RID_REQ_ROLE;
		break;
	case DREPL_SCHEMA_MASTER:
		fsmo_role_dn = ldb_get_schema_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, fsmo_role_dn, "fSMORoleOwner", &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		extended_op = DRSUAPI_EXOP_FSMO_REQ_ROLE;
		break;
	case DREPL_PDC_MASTER:
		fsmo_role_dn = ldb_get_default_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, fsmo_role_dn, "fSMORoleOwner", &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Pd Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		extended_op = DRSUAPI_EXOP_FSMO_REQ_PDC;
		break;
	default:
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (fsmo_master_cmp(ntds_dn, role_owner_dn) ||
	    (extended_op == DRSUAPI_EXOP_NONE)) {
		DEBUG(0,("FSMO role check failed for DN %s and owner %s ",
			 ldb_dn_get_linearized(fsmo_role_dn),
			 ldb_dn_get_linearized(role_owner_dn)));
		return WERR_OK;
	}

	werr = drepl_request_extended_op(service,
					 fsmo_role_dn,
					 role_owner_dn,
					 extended_op,
					 fsmo_info,
					 0,
					 drepl_role_callback,
					 NULL);
	if (W_ERROR_IS_OK(werr)) {
		dreplsrv_run_pending_ops(service);
	} else {
		DEBUG(0,("%s: drepl_request_extended_op() failed with %s",
			 __FUNCTION__, win_errstr(werr)));
	}
	return werr;
}
