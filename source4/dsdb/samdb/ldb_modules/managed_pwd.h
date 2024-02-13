/*
   Unix SMB/CIFS implementation.
   msDS-ManagedPassword attribute for Group Managed Service Accounts

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef DSDB_SAMDB_LDB_MODULES_MANAGED_PWD_H
#define DSDB_SAMDB_LDB_MODULES_MANAGED_PWD_H

#include <ldb.h>

struct ldb_module;
int constructed_msds_managed_password(struct ldb_module *module,
				      struct ldb_message *msg,
				      enum ldb_scope scope,
				      struct ldb_request *parent,
				      struct ldb_reply *ares);

#endif /* DSDB_SAMDB_LDB_MODULES_MANAGED_PWD_H */
