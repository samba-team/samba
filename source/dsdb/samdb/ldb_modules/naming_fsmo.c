/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Domain Naming FSMO Role Owner
   checkings
   
   Copyright (C) Stefan Metzmacher 2007
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/util/dlinklist.h"

static int naming_fsmo_init(struct ldb_module *module)
{
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *naming_dn;
	struct dsdb_naming_fsmo *naming_fsmo;
	struct ldb_result *naming_res;
	int ret;
	static const char *naming_attrs[] = {
		"fSMORoleOwner",
		NULL
	};

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	naming_dn = samdb_partitions_dn(module->ldb, mem_ctx);
	if (!naming_dn) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "naming_fsmo_init: no partitions dn present: (skip loading of naming contexts details)\n");
		talloc_free(mem_ctx);
		return ldb_next_init(module);
	}

	naming_fsmo = talloc_zero(mem_ctx, struct dsdb_naming_fsmo);
	if (!naming_fsmo) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	module->private_data = naming_fsmo;

	ret = ldb_search(module->ldb, naming_dn,
			 LDB_SCOPE_BASE,
			 NULL, naming_attrs,
			 &naming_res);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "naming_fsmo_init: failed to search the cross-ref container: %d:%s\n",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, naming_res);
	if (naming_res->count == 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "naming_fsmo_init: no cross-ref container present: (skip loading of naming contexts details)\n");
		talloc_free(mem_ctx);
		return ldb_next_init(module);
	} else if (naming_res->count > 1) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "naming_fsmo_init: [%u] cross-ref containers found on a base search\n",
			      naming_res->count);
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	naming_fsmo->master_dn = ldb_msg_find_attr_as_dn(module->ldb, naming_fsmo, naming_res->msgs[0], "fSMORoleOwner");
	if (ldb_dn_compare(samdb_ntds_settings_dn(module->ldb), naming_fsmo->master_dn) == 0) {
		naming_fsmo->we_are_master = true;
	} else {
		naming_fsmo->we_are_master = false;
	}

	if (ldb_set_opaque(module->ldb, "dsdb_naming_fsmo", naming_fsmo) != LDB_SUCCESS) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_steal(module, naming_fsmo);

	ldb_debug(module->ldb, LDB_DEBUG_TRACE,
			  "naming_fsmo_init: we are master: %s\n",
			  (naming_fsmo->we_are_master?"yes":"no"));

	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static const struct ldb_module_ops naming_fsmo_ops = {
	.name		= "naming_fsmo",
	.init_context	= naming_fsmo_init
};

int naming_fsmo_module_init(void)
{
	return ldb_register_module(&naming_fsmo_ops);
}
