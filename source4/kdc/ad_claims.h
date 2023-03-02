/*
   Unix SMB/CIFS implementation.
   Samba Active Directory claims utility functions

   Copyright (C) Catalyst.Net Ltd 2023

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

#ifndef KDC_AD_CLAIMS_H
#define KDC_AD_CLAIMS_H

#include "lib/util/data_blob.h"
#include "ldb.h"

int get_claims_for_principal(struct ldb_context *ldb,
			     TALLOC_CTX *mem_ctx,
			     struct ldb_dn *principal_dn,
			     DATA_BLOB *claims_blob);

#endif
