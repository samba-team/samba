/*
   Unix SMB/CIFS implementation.

   DNS tombstoning routines

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dns_server/dnsserver_common.h"

NTSTATUS dns_tombstone_records(TALLOC_CTX *mem_ctx,
			       struct ldb_context *samdb,
			       char **error_string);

NTSTATUS dns_delete_tombstones(TALLOC_CTX *mem_ctx,
			       struct ldb_context *samdb,
			       char **error_string);
NTSTATUS remove_expired_records(TALLOC_CTX *mem_ctx,
				struct ldb_message_element *el,
				NTTIME t);
NTSTATUS dns_tombstone_records_zone(TALLOC_CTX *mem_ctx,
				    struct ldb_context *samdb,
				    struct dns_server_zone *zone,
				    struct ldb_val *true_struct,
				    struct ldb_val *tombstone_blob,
				    NTTIME t,
				    char **error_string);

NTSTATUS copy_current_records(TALLOC_CTX *mem_ctx,
			      struct ldb_message_element *old_el,
			      struct ldb_message_element *el,
			      NTTIME t);
