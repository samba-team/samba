/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

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

#include "lib/replace/replace.h"

#include <stddef.h>
#include <stdint.h>

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include <krb5/krb5.h>

#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"

struct type_data {
	uint32_t type;
	const DATA_BLOB *data;
};

struct pac_blobs {
	size_t type_index[PAC_TYPE_COUNT];
	struct type_data *type_blobs;
	size_t num_types;
};

krb5_error_code pac_blobs_from_krb5_pac(TALLOC_CTX *mem_ctx,
					krb5_context context,
					const krb5_const_pac pac,
					struct pac_blobs **pac_blobs);

#define pac_blobs_ensure_exists(pac_blobs, type) \
	_pac_blobs_ensure_exists(pac_blobs, \
				 type, \
				 #type, \
				 __location__, \
				 __func__)

krb5_error_code _pac_blobs_ensure_exists(struct pac_blobs *pac_blobs,
					 const uint32_t type,
					 const char *name,
					 const char *location,
					 const char *function);

#define pac_blobs_replace_existing(pac_blobs, type, blob) \
	_pac_blobs_replace_existing(pac_blobs, \
				    type, \
				    #type, \
				    blob, \
				    __location__, \
				    __func__)

krb5_error_code _pac_blobs_replace_existing(struct pac_blobs *pac_blobs,
					    const uint32_t type,
					    const char *name,
					    const DATA_BLOB *blob,
					    const char *location,
					    const char *function);

krb5_error_code pac_blobs_add_blob(struct pac_blobs *pac_blobs,
				   const uint32_t type,
				   const DATA_BLOB *blob);

void pac_blobs_remove_blob(struct pac_blobs *pac_blobs,
			   const uint32_t type);
