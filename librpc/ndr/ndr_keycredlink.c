/*
   Unix SMB/CIFS implementation.

   Support routines for packing and unpacking of msDS-KeyCredentialLink
   structures.

   See [MS-ADTS] 2.2.20 Key Credential Link Structures

   Copyright (C) Gary Lockyer 2025

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
#include "librpc/gen_ndr/ndr_keycredlink.h"
#include "gen_ndr/keycredlink.h"
#include "libndr.h"
#include <assert.h>

/*
 * The KEYCREDENTIALLINK_BLOB consists of the version and a series of variable
 * length KEYCREDENTIALLINK_ENTRIES.
 */
enum ndr_err_code ndr_pull_KEYCREDENTIALLINK_BLOB(
	struct ndr_pull *ndr,
	ndr_flags_type ndr_flags,
	struct KEYCREDENTIALLINK_BLOB *blob)
{
	libndr_flags _flags_save_STRUCT = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);

	NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &blob->version));
	if (blob->version != 0x0200) {
		return ndr_pull_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid version of (0x%04x) "
				      "should be 0x0200, at byte %zu\n",
				      blob->version,
				      (ndr->offset - sizeof(uint32_t)));
	}
	blob->count = 0;
	blob->entries = talloc_array(ndr->current_mem_ctx,
				     struct KEYCREDENTIALLINK_ENTRY,
				     blob->count);
	if (blob->entries == NULL) {
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Failed to pull KEYCREDENTIALLINK_ENTRY");
	}
	while (ndr->offset < ndr->data_size) {
		blob->entries = talloc_realloc(ndr->current_mem_ctx,
					       blob->entries,
					       struct KEYCREDENTIALLINK_ENTRY,
					       blob->count + 1);
		if (blob->entries == NULL) {
			return ndr_pull_error(
				ndr,
				NDR_ERR_ALLOC,
				"Failed to pull KEYCREDENTIALLINK_ENTRY");
		}
		NDR_CHECK(ndr_pull_KEYCREDENTIALLINK_ENTRY(
			ndr, ndr_flags, &blob->entries[blob->count]));
		blob->count++;
	}
	ndr->flags = _flags_save_STRUCT;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_KEYCREDENTIALLINK_BLOB(
	struct ndr_push *ndr,
	ndr_flags_type ndr_flags,
	const struct KEYCREDENTIALLINK_BLOB *blob)
{
	int i = 0;

	if (blob->version != 0x0200) {
		return ndr_push_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid version of (0x%04x) "
				      "should be 0x0200, at byte %zu\n",
				      blob->version,
				      (ndr->offset - sizeof(uint32_t)));
	}
	NDR_CHECK(ndr_push_uint32(ndr, ndr_flags, blob->version));

	for (i = 0; i < blob->count; i++) {
		NDR_CHECK(ndr_push_KEYCREDENTIALLINK_ENTRY(ndr,
							   ndr_flags,
							   &blob->entries[i]));
	}
	return NDR_ERR_SUCCESS;
}

/*
 * To pull the CUSTOM_KEY_INFORMATION the length from the enclosing
 * KEYCREDENTIALLINK_ENTRY needs to be passed in.
 *
 * CUSTOM_KEY_INFORMATION has two representations based on the size parameter
 *
 * If size is 2 only the version and flags are expected.
 * If the size is greater than 2 then
 *    version, flags, volType, supportsNotification, fekKeyVersion,
 *    keyStrength and the reserved bytes are expected
 *    Optionally followed by a series of EncodedExtendedCKI entries
 *
 */
static enum ndr_err_code pull_cki(struct ndr_pull *ndr,
				  ndr_flags_type ndr_flags,
				  struct CUSTOM_KEY_INFORMATION *info,
				  uint32_t size)
{
	/* Calculate the end of the CUSTOM_KEY_INFORMATION in the raw bytes */
	uint32_t end_offset = ndr->offset + size;

	/*
	 * Initialise the CUSTOM_KEY_INFORMATION, in case this is the
	 * short form.
	 */
	*info = (struct CUSTOM_KEY_INFORMATION){0};

	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &info->version));
	if (info->version != 0x01) {
		return ndr_pull_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid version of (0x%02x) "
				      "should be 0x01, at byte %zu\n",
				      info->version,
				      (ndr->offset - sizeof(uint8_t)));
	}
	NDR_CHECK(ndr_pull_CUSTOM_KEY_INFO_Flags(ndr, ndr_flags, &info->flags));

	if (size == 2) {
		info->isExtended = false;
		return NDR_ERR_SUCCESS;
	}
	info->isExtended = true;
	NDR_CHECK(ndr_pull_CUSTOM_KEY_INFO_VolType(ndr,
						   ndr_flags,
						   &info->volType));
	NDR_CHECK(ndr_pull_CUSTOM_KEY_INFO_SupportsNotification(
		ndr, ndr_flags, &info->supportsNotification));
	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &info->fekKeyVersion));
	if (info->fekKeyVersion != 0x01) {
		return ndr_pull_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid fekKeyVersion of (0x%02x) "
				      "should be 0x01, at byte %zu\n",
				      info->fekKeyVersion,
				      (ndr->offset - sizeof(uint8_t)));
	}
	NDR_CHECK(ndr_pull_CUSTOM_KEY_INFO_KeyStrength(ndr,
						       ndr_flags,
						       &info->keyStrength));
	NDR_CHECK(ndr_pull_array_uint8(ndr, ndr_flags, info->reserved, 10));

	/* Pull the EncodedExtendedCKI values */
	info->count = 0;
	info->cki = talloc_array(ndr->current_mem_ctx,
				 struct EncodedExtendedCKI,
				 info->count);
	if (info->cki == NULL) {
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Failed to pull EncodedExtendCKI");
	}
	while (ndr->offset < end_offset) {
		info->cki = talloc_realloc(ndr->current_mem_ctx,
					   info->cki,
					   struct EncodedExtendedCKI,
					   info->count + 1);
		if (info->cki == NULL) {
			return ndr_pull_error(
				ndr,
				NDR_ERR_ALLOC,
				"Failed to pull EncodedExtendedCKI");
		}
		NDR_CHECK(ndr_pull_EncodedExtendedCKI(ndr,
						      ndr_flags,
						      &info->cki[info->count]));
		info->count++;
	}
	return NDR_ERR_SUCCESS;
}

/*
 * CUSTOM_KEY-INFORMATION has two representations with differing sizes
 * the flag isExtended controls which version is written.
 */
enum ndr_err_code ndr_push_CUSTOM_KEY_INFORMATION(
	struct ndr_push *ndr,
	ndr_flags_type ndr_flags,
	const struct CUSTOM_KEY_INFORMATION *info)
{
	int i = 0;

	if (info->version != 0x01) {
		return ndr_push_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid version of (0x%02x) "
				      "should be 0x01, at byte %zu\n",
				      info->version,
				      (ndr->offset - sizeof(uint8_t)));
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, info->version));
	NDR_CHECK(ndr_push_CUSTOM_KEY_INFO_Flags(ndr, ndr_flags, info->flags));
	if (!info->isExtended) {
		return NDR_ERR_SUCCESS;
	}

	NDR_CHECK(ndr_push_CUSTOM_KEY_INFO_VolType(ndr,
						   ndr_flags,
						   info->volType));
	NDR_CHECK(ndr_push_CUSTOM_KEY_INFO_SupportsNotification(
		ndr, ndr_flags, info->supportsNotification));
	if (info->fekKeyVersion != 0x01) {
		return ndr_push_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid fekKeyVersion of (0x%02x) "
				      "should be 0x01, at byte %zu\n",
				      info->fekKeyVersion,
				      (ndr->offset - sizeof(uint8_t)));
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, info->fekKeyVersion));
	NDR_CHECK(ndr_push_CUSTOM_KEY_INFO_KeyStrength(ndr,
						       ndr_flags,
						       info->keyStrength));
	NDR_CHECK(ndr_push_array_uint8(ndr, ndr_flags, info->reserved, 10));

	for (i = 0; i < info->count; i++) {
		NDR_CHECK(ndr_push_EncodedExtendedCKI(ndr,
						      ndr_flags,
						      &info->cki[i]));
	}
	return NDR_ERR_SUCCESS;
}

/*
 * To pull a KEYCREDENTIALLINK_Value the length from the enclosing
 * KEYCREDENTIALLINK_ENTRY needs to be passed in.
 *
 */
static enum ndr_err_code ndr_pull_value(struct ndr_pull *ndr,
					ndr_flags_type ndr_flags,
					union KEYCREDENTIALLINK_ENTRY_Value *r,
					uint32_t size)
{
	uint32_t level;
	const size_t header_len = sizeof(uint16_t) + sizeof(uint8_t);
	const size_t identifier_len = sizeof(uint8_t);
	libndr_flags flags_save = ndr->flags;

	/* this function should only be called if NDR_SCALARS is set */
	assert(ndr_flags & NDR_SCALARS);

	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);

	/* This token is not used again */
	NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));

	switch (level) {
	case KeyID: {
		if (size != 32) {
			return ndr_pull_error(ndr,
					      NDR_ERR_ARRAY_SIZE,
					      "Invalid size of (%" PRIu32
					      ") for KeyID "
					      "should be (32), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(
			ndr_pull_array_uint8(ndr, NDR_SCALARS, r->keyId, size));
		break;
	}

	case KeyHash: {
		if (size != 32) {
			return ndr_pull_error(ndr,
					      NDR_ERR_ARRAY_SIZE,
					      "Invalid size of (%" PRIu32
					      ") for KeyHash "
					      "should be (32), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_array_uint8(
			ndr, NDR_SCALARS, r->keyHash, size));
		break;
	}

	case KeyUsage: {
		if (size != 1) {
			return ndr_pull_error(ndr,
					      NDR_ERR_LENGTH,
					      "Invalid length of (%" PRIu32
					      ") for KeyUsage "
					      "should be (1), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_KEYCREDENTIALLINK_ENTRY_KeyUsage(
			ndr, NDR_SCALARS, &r->keyUsage));
		break;
	}

	case KeySource: {
		if (size != 1) {
			return ndr_pull_error(ndr,
					      NDR_ERR_LENGTH,
					      "Invalid length of (%" PRIu32
					      ") for KeySource "
					      "should be (1), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_KEYCREDENTIALLINK_ENTRY_KeySource(
			ndr, NDR_SCALARS, &r->keySource));
		break;
	}

	case KeyMaterial: {
		if (size == 0) {
			return ndr_pull_error(
				ndr,
				NDR_ERR_LENGTH,
				"Invalid length of (%" PRIu32
				") for keyMaterial "
				"should be non zero, at byte %zu\n",
				size,
				(ndr->offset - header_len));
		}
		NDR_PULL_NEED_BYTES(ndr, size);
		r->keyMaterial = data_blob_talloc(ndr->current_mem_ctx,
						  ndr->data + ndr->offset,
						  size);
		if (r->keyMaterial.data == NULL) {
			return ndr_pull_error(ndr,
					      NDR_ERR_ALLOC,
					      "Failed to pull keyMaterial");
		}
		ndr->offset += size;
		break;
	}

	case DeviceId: {
		if (size != 16) {
			return ndr_pull_error(ndr,
					      NDR_ERR_ARRAY_SIZE,
					      "Invalid size of (%" PRIu32
					      ") for KeySource "
					      "should be (1), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_array_uint8(
			ndr, NDR_SCALARS, r->deviceId, size));
		break;
	}

	case CustomKeyInformation: {
		NDR_CHECK(pull_cki(
			ndr, NDR_SCALARS, &r->customKeyInformation, size));
		break;
	}

	case KeyApproximateLastLogonTimeStamp: {
		if (size != 8) {
			return ndr_pull_error(
				ndr,
				NDR_ERR_LENGTH,
				"Invalid length of (%" PRIu32 ") for "
				"KeyApproximateLastLogonTimeStamp "
				"should be (8), at byte %zu\n",
				size,
				(ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_NTTIME(ndr, NDR_SCALARS, &r->lastLogon));
		break;
	}

	case KeyCreationTime: {
		if (size != 8) {
			return ndr_pull_error(ndr,
					      NDR_ERR_RANGE,
					      "Invalid size of (%" PRIu32
					      ") for "
					      "KeyCreationTime "
					      "should be (8), at byte %zu\n",
					      size,
					      (ndr->offset - header_len));
		}
		NDR_CHECK(ndr_pull_NTTIME(ndr, NDR_SCALARS, &r->created));
		break;
	}

	default:
		return ndr_pull_error(ndr,
				      NDR_ERR_BAD_SWITCH,
				      "Bad switch value %02x at byte %zu",
				      level,
				      ndr->offset - identifier_len);
	}
	ndr->flags = flags_save;
	return NDR_ERR_SUCCESS;
}

/*
 * Need to pass the length element of the KEYCREDENTIALLINK_ENTRY down to
 * ndr_pull_value, the code that pulls the KEYCREDENTIALLINK_ENTRY_Value.
 */
enum ndr_err_code ndr_pull_KEYCREDENTIALLINK_ENTRY(
	struct ndr_pull *ndr,
	ndr_flags_type ndr_flags,
	struct KEYCREDENTIALLINK_ENTRY *r)
{
	libndr_flags _flags_save_STRUCT = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->length));
		NDR_CHECK(ndr_pull_KEYCREDENTIALLINK_ENTRY_Identifier(
			ndr, NDR_SCALARS, &r->identifier));
		NDR_CHECK(ndr_pull_set_switch_value(ndr,
						    &r->value,
						    r->identifier));
		NDR_CHECK(
			ndr_pull_value(ndr, NDR_SCALARS, &r->value, r->length));
	}
	ndr->flags = _flags_save_STRUCT;
	return NDR_ERR_SUCCESS;
}
