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
#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_module.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "system/locale.h"

struct dsdb_partition {
	struct ldb_module *module;
	struct dsdb_control_current_partition *ctrl;
	const char *backend_url;
};

struct partition_module {
	const char **modules;
	struct ldb_dn *dn;
};

struct partition_private_data {
	struct dsdb_partition **partitions;
	struct ldb_dn **replicate;
	
	struct partition_module **modules;
	const char *ldapBackend;

	uint64_t metadata_seq;
	uint32_t in_transaction;
};

#define PARTITION_FIND_OP_NOERROR(module, op) do { \
        while (module && module->ops->op == NULL) module = module->next; \
} while (0)

#define PARTITION_FIND_OP(module, op) do { \
	PARTITION_FIND_OP_NOERROR(module, op); \
        if (module == NULL) { \
                ldb_asprintf_errstring(ldb_module_get_ctx(module), \
			"Unable to find backend operation for " #op ); \
                return LDB_ERR_OPERATIONS_ERROR; \
        } \
} while (0)

#include "dsdb/samdb/ldb_modules/partition_proto.h"
