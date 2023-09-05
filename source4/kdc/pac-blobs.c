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

#include "source4/kdc/pac-blobs.h"

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

static inline size_t *pac_blobs_get_index(struct pac_blobs *pac_blobs, size_t type)
{
	/* Ensure the type is valid. */
	SMB_ASSERT(type >= PAC_TYPE_BEGIN);
	SMB_ASSERT(type < PAC_TYPE_END);

	return &pac_blobs->type_index[type - PAC_TYPE_BEGIN];
}

static inline struct type_data *pac_blobs_get(struct pac_blobs *pac_blobs, size_t type)
{
	size_t index = *pac_blobs_get_index(pac_blobs, type);
	SMB_ASSERT(index < pac_blobs->num_types);

	return &pac_blobs->type_blobs[index];
}

krb5_error_code pac_blobs_from_krb5_pac(TALLOC_CTX *mem_ctx,
					krb5_context context,
					const krb5_const_pac pac,
					struct pac_blobs **pac_blobs)
{
	krb5_error_code code = 0;
	uint32_t *types = NULL;
	struct pac_blobs *blobs = NULL;
	size_t i;

	SMB_ASSERT(pac_blobs != NULL);
	*pac_blobs = NULL;

	blobs = talloc(mem_ctx, struct pac_blobs);
	if (blobs == NULL) {
		code = ENOMEM;
		goto out;
	}

	*blobs = (struct pac_blobs) {};

	/* Initialize the array indices. */
	for (i = 0; i < ARRAY_SIZE(blobs->type_index); ++i) {
		blobs->type_index[i] = SIZE_MAX;
	}

	code = krb5_pac_get_types(context, pac, &blobs->num_types, &types);
	if (code != 0) {
		DBG_ERR("krb5_pac_get_types failed\n");
		goto out;
	}

	blobs->type_blobs = talloc_array(blobs, struct type_data, blobs->num_types);
	if (blobs->type_blobs == NULL) {
		DBG_ERR("Out of memory\n");
		code = ENOMEM;
		goto out;
	}

	for (i = 0; i < blobs->num_types; ++i) {
		uint32_t type = types[i];
		size_t *type_index = NULL;

		blobs->type_blobs[i] = (struct type_data) {
			.type = type,
			.data = NULL,
		};

		switch (type) {
			/* PAC buffer types that we support. */
		case PAC_TYPE_LOGON_INFO:
		case PAC_TYPE_CREDENTIAL_INFO:
		case PAC_TYPE_SRV_CHECKSUM:
		case PAC_TYPE_KDC_CHECKSUM:
		case PAC_TYPE_LOGON_NAME:
		case PAC_TYPE_CONSTRAINED_DELEGATION:
		case PAC_TYPE_UPN_DNS_INFO:
		case PAC_TYPE_CLIENT_CLAIMS_INFO:
		case PAC_TYPE_DEVICE_INFO:
		case PAC_TYPE_DEVICE_CLAIMS_INFO:
		case PAC_TYPE_TICKET_CHECKSUM:
		case PAC_TYPE_ATTRIBUTES_INFO:
		case PAC_TYPE_REQUESTER_SID:
		case PAC_TYPE_FULL_CHECKSUM:
			type_index = pac_blobs_get_index(blobs, type);
			if (*type_index != SIZE_MAX) {
				DBG_WARNING("PAC buffer type[%"PRIu32"] twice\n", type);
				code = EINVAL;
				goto out;
			}
			*type_index = i;

			break;
		default:
			break;
		}
	}

	*pac_blobs = blobs;
	blobs = NULL;

out:
	SAFE_FREE(types);
	TALLOC_FREE(blobs);
	return code;
}

krb5_error_code _pac_blobs_ensure_exists(struct pac_blobs *pac_blobs,
					 const uint32_t type,
					 const char *name,
					 const char *location,
					 const char *function)
{
	if (*pac_blobs_get_index(pac_blobs, type) == SIZE_MAX) {
		DEBUGLF(DBGLVL_ERR, ("%s: %s missing\n", function, name), location, function);
		return EINVAL;
	}

	return 0;
}

krb5_error_code _pac_blobs_replace_existing(struct pac_blobs *pac_blobs,
					    const uint32_t type,
					    const char *name,
					    const DATA_BLOB *blob,
					    const char *location,
					    const char *function)
{
	krb5_error_code code;

	code = _pac_blobs_ensure_exists(pac_blobs,
					type,
					name,
					location,
					function);
	if (code != 0) {
		return code;
	}

	pac_blobs_get(pac_blobs, type)->data = blob;

	return 0;
}

krb5_error_code pac_blobs_add_blob(struct pac_blobs *pac_blobs,
				   const uint32_t type,
				   const DATA_BLOB *blob)
{
	size_t *index = NULL;

	if (blob == NULL) {
		return 0;
	}

	index = pac_blobs_get_index(pac_blobs, type);
	if (*index == SIZE_MAX) {
		struct type_data *type_blobs = NULL;

		type_blobs = talloc_realloc(pac_blobs,
					    pac_blobs->type_blobs,
					    struct type_data,
					    pac_blobs->num_types + 1);
		if (type_blobs == NULL) {
			DBG_ERR("Out of memory\n");
			return ENOMEM;
		}

		pac_blobs->type_blobs = type_blobs;
		*index = pac_blobs->num_types++;
	}

	*pac_blobs_get(pac_blobs, type) = (struct type_data) {
		.type = type,
		.data = blob,
	};

	return 0;
}

void pac_blobs_remove_blob(struct pac_blobs *pac_blobs,
			   const uint32_t type)
{
	struct type_data *type_blobs = NULL;
	size_t found_index;
	size_t i;

	/* Get the index of this PAC buffer type. */
	found_index = *pac_blobs_get_index(pac_blobs, type);
	if (found_index == SIZE_MAX) {
		/* We don't have a PAC buffer of this type, so we're done. */
		return;
	}

	/* Since the PAC buffer is present, there will be at least one type in the array. */
	SMB_ASSERT(pac_blobs->num_types > 0);

	/* The index should be valid. */
	SMB_ASSERT(found_index < pac_blobs->num_types);

	/*
	 * Even though a consistent ordering of PAC buffers is not to be relied
	 * upon, we must still maintain the ordering we are given.
	 */
	for (i = found_index; i < pac_blobs->num_types - 1; ++i) {
		size_t moved_type;

		/* Shift each following element backwards by one. */
		pac_blobs->type_blobs[i] = pac_blobs->type_blobs[i + 1];

		/* Mark the new position of the moved element in the index. */
		moved_type = pac_blobs->type_blobs[i].type;
		if (moved_type >= PAC_TYPE_BEGIN && moved_type < PAC_TYPE_END) {
			*pac_blobs_get_index(pac_blobs, moved_type) = i;
		}
	}

	/* Mark the removed element as no longer present. */
	*pac_blobs_get_index(pac_blobs, type) = SIZE_MAX;

	/* We do not free the removed data blob, as it may be statically allocated (e.g., a null blob). */

	/* Remove the last element from the array. */
	type_blobs = talloc_realloc(pac_blobs,
				    pac_blobs->type_blobs,
				    struct type_data,
				    --pac_blobs->num_types);
	if (type_blobs != NULL) {
		pac_blobs->type_blobs = type_blobs;
	}
}
