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
	talloc_free(service->ncchanges_extended.role_owner_source_dsa);
	service->ncchanges_extended.role_owner_source_dsa = NULL;
	service->ncchanges_extended.in_progress = false;
}

static bool fsmo_master_cmp(struct ldb_dn *ntds_dn, struct ldb_dn *fsmo_role_dn)
{
	if (ldb_dn_compare(ntds_dn, fsmo_role_dn) == 0) {
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
	uint64_t alloc_pool = 0;

	if (service->ncchanges_extended.in_progress) {
		talloc_free(tmp_ctx);
		return WERR_OK;
	}

	ntds_dn = samdb_ntds_settings_dn(ldb);
	if (!ntds_dn) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	/* work out who is the current owner */
	switch (role) {
	case DREPL_NAMING_MASTER:
		role_owner_dn = samdb_partitions_dn(ldb, tmp_ctx),
		ret = samdb_reference_dn(ldb, tmp_ctx, role_owner_dn, "fSMORoleOwner", &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Naming Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_INFRASTRUCTURE_MASTER:
		role_owner_dn = samdb_infrastructure_dn(ldb, tmp_ctx);
		ret = samdb_reference_dn(ldb, tmp_ctx, role_owner_dn, "fSMORoleOwner", &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_RID_MASTER:
		ret = samdb_rid_manager_dn(ldb, tmp_ctx, &role_owner_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, (__location__ ": Failed to find RID Manager object - %s", ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* find the DN of the RID Manager */
		ret = samdb_reference_dn(ldb, tmp_ctx, role_owner_dn, "fSMORoleOwner", &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in RID Manager object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	case DREPL_SCHEMA_MASTER:
		role_owner_dn = ldb_get_schema_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, role_owner_dn, "fSMORoleOwner", &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Schema Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		if (!fsmo_master_cmp(ntds_dn, fsmo_role_dn)) {
			WERROR werr;
			werr = drepl_request_extended_op(service,
							 role_owner_dn,
							 fsmo_role_dn,
							 DRSUAPI_EXOP_FSMO_REQ_ROLE,
							 alloc_pool,
							 drepl_role_callback);
			if (W_ERROR_IS_OK(werr)) {
				dreplsrv_run_pending_ops(service);
			} else {
				DEBUG(0,("%s: drepl_request_extended_op() failed with %s",
						 __FUNCTION__, win_errstr(werr)));
			}
			return werr;
		}
		break;
	case DREPL_PDC_MASTER:
		role_owner_dn = ldb_get_default_basedn(ldb);
		ret = samdb_reference_dn(ldb, tmp_ctx, role_owner_dn, "fSMORoleOwner", &fsmo_role_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in Pd Master object - %s",
				 ldb_errstring(ldb)));
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		break;
	default:
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	return WERR_OK;
}
