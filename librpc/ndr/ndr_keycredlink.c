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

#include "gen_ndr/ndr_keycredlink.h"
#include "lib/util/data_blob.h"
#include "libndr.h"
#include "librpc/gen_ndr/ndr_bcrypt_rsakey_blob.h"
#include "librpc/gen_ndr/ndr_tpm20_rsakey_blob.h"
#include "util/asn1.h"
#include "util/data_blob.h"
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

/* @brief Check that the AlgorithmIdentifier element is correct
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm       OBJECT IDENTIFIER,
 *     parameters      ANY DEFINED BY algorithm OPTIONAL
 *                     -- Should be NULL for RSA
 * }
 *
 * @param[in]     ndr ndr pull context
 * @param[in,out] asn ASN data context
 *
 * @return NDR_ERR_SUCCESS if the element is valid.
 */
static enum ndr_err_code check_algorithm_identifier(struct ndr_pull *ndr,
						    struct asn1_data *asn)
{
	static const char *RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
	uint8_t asn1_null[2];
	if (!asn1_start_tag(asn, ASN1_SEQUENCE(0))) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, expecting SEQUENCE 0x30");
	}
	if (!asn1_check_OID(asn, RSA_ENCRYPTION_OID)) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 algorithm OID, expecting %s",
			RSA_ENCRYPTION_OID);
	}

	/* For an RSA public key, parameters should be null 0x0500 */
	if (!asn1_read(asn, asn1_null, 2)) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Unexpected ASN1 element, expecting NULL 0x05");
	}
	if (!asn1_end_tag(asn)) { /* AlgorithmIdentifier */
		return ndr_pull_error(ndr,
				      NDR_ERR_UNREAD_BYTES,
				      "ASN1 element AlgorithmIdentifier");
	}
	return NDR_ERR_SUCCESS;
}

/**
 * @brief start processing a BIT STRING
 *
 * The caller will need to call asn1_end_tag
 *
 * @param[in]     ndr         ndr pull context
 * @param[in,out] asn         ASN data context
 * @param[out]    unused_bits the number of unused bits in the least
 *                            significant byte (LSB) of the BIT String
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of unused_bits are undefined on an error
 */
static enum ndr_err_code start_bit_string(struct ndr_pull *ndr,
					  struct asn1_data *asn,
					  uint8_t *unused_bits)
{
	if (!asn1_start_tag(asn, ASN1_BIT_STRING)) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, expecting BIT STRING 0x03");
	}

	/*
	 * The first byte of a BIT STRING contains the number of unused bits
	 * in the final byte.
	 */
	if (!asn1_read_uint8(asn, unused_bits)) {
		return ndr_pull_error(ndr,
				      NDR_ERR_VALIDATE,
				      "Invalid ASN1 BIT STRING, unable to read "
				      "number of unused bits");
	}
	if (*unused_bits > 8) {
		return ndr_pull_error(ndr,
				      NDR_ERR_RANGE,
				      "Invalid ASN1 BIT STRING, "
				      "number of unused bits exceeds 9");
	}
	return NDR_ERR_SUCCESS;
}

/**
 * @brief Read a DER encoded INTEGER into a data_blob
 *
 * @param[in]     mem_ctx memory context to allocate the data_blob data on
 * @param[in]     ndr     ndr pull context
 * @param[in,out] asn     ASN data context
 * @param[in]     name    the name of the INTEGER for diagnostic messages
 * @param[out]    blob    the data blob to populate
 *                        using mem_ctx for allocation
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of blob are undefined on an error
 */
static enum ndr_err_code read_integer(TALLOC_CTX *mem_ctx,
				      struct ndr_pull *ndr,
				      struct asn1_data *asn,
				      const char *name,
				      DATA_BLOB *blob)
{
	static const int MAX_SIZE = 2 * 2048; /* 16384 bits */
	uint8_t msb = 0;
	int tag_size = 0;

	if (!asn1_start_tag(asn, ASN1_INTEGER)) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, expecting INTEGER 0x02");
	}
	if (!asn1_peek_uint8(asn, &msb)) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, unable to inspect first byte of %s",
			name);
	}
	/* skip a leading 0 byte if present */
	if (msb == 0) {
		if (!asn1_read_uint8(asn, &msb)) {
			return ndr_pull_error(ndr,
					      NDR_ERR_VALIDATE,
					      "Invalid ASN1 tag, unable to "
					      "read first byte of %s",
					      name);
		}
	}

	tag_size = asn1_tag_remaining(asn);
	if (tag_size > MAX_SIZE) {
		return ndr_pull_error(ndr,
				      NDR_ERR_LENGTH,
				      "INTEGER %s size of %d "
				      "bytes is too large",
				      name,
				      tag_size);
	}
	if (tag_size <= 0) {
		return ndr_pull_error(ndr,
				      NDR_ERR_LENGTH,
				      "INTEGER %s size of %d "
				      "bytes is too small",
				      name,
				      tag_size);
	}
	*blob = data_blob_talloc(mem_ctx, NULL, tag_size);
	if (blob->data == NULL) {
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Unable to allocate DATA_BLOB for %s",
				      name);
	}

	if (!asn1_read(asn, blob->data, tag_size)) {
		return ndr_pull_error(ndr,
				      NDR_ERR_VALIDATE,
				      "Unable to read %s",
				      name);
	}
	if (!asn1_end_tag(asn)) {
		return ndr_pull_error(ndr,
				      NDR_ERR_UNREAD_BYTES,
				      "ASN1 INTEGER element %s",
				      name);
	}
	return NDR_ERR_SUCCESS;
}

/**
 * @brief Convert a DER encoded X509 PublicKey into the Internal public key
 *        representation
 *
 * publicKey BIT STRING -- containing an RSAPublicKey
 * RSAPublicKey ::= SEQUENCE {
 *     modulus            INTEGER,
 *     publicExponent     INTEGER
 * }
 *
 * @param[in,out] ndr       ndr pull context
 * @param[in]     ndr_flags
 * @param[out]    kmi       the KeyMaterialInternal structure to populate
 *			    kmi needs to be a talloc context.
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of kmi are undefined on an error
 */
static enum ndr_err_code read_public_key(struct ndr_pull *ndr,
					 struct asn1_data *asn,
					 struct KeyMaterialInternal *kmi)
{
	uint8_t unused_bits = 0;

	/*
	 * publicKey BIT STRING
	 * The RSAPublicKey is encoded in a BIT STRING
	 */
	NDR_CHECK(start_bit_string(ndr, asn, &unused_bits));

	/* RSAPublicKey ::= SEQUENCE {
	 *     modulus            INTEGER,    -- n
	 *     publicExponent     INTEGER  }  -- e
	 */
	if (!asn1_start_tag(asn, ASN1_SEQUENCE(0))) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, expecting SEQUENCE 0x30");
	}

	/* modulus INTEGER  */
	NDR_CHECK(read_integer(kmi, ndr, asn, "MODULUS", &kmi->modulus));
	kmi->bit_size = (kmi->modulus.length * 8) - unused_bits;

	/* public exponent INTEGER */
	NDR_CHECK(read_integer(kmi, ndr, asn, "EXPONENT", &kmi->exponent));

	if (!asn1_end_tag(asn)) { /* RSAPublicKey */
		return ndr_pull_error(ndr,
				      NDR_ERR_UNREAD_BYTES,
				      "ASN1 element RSAPublicKey");
	}
	if (!asn1_end_tag(asn)) { /* PublicKey */
		return ndr_pull_error(ndr,
				      NDR_ERR_UNREAD_BYTES,
				      "ASN1 element PublicKey");
	}
	return NDR_ERR_SUCCESS;
}

/**
 * @brief Convert a DER encoded X509 public key into the Internal public key
 *        representation
 *
 * @param[in,out] ndr ndr pull context
 * @param[in]     ndr_flags
 * @param[out]    kmi the KeyMaterialInternal structure to populate
 *                    kmi needs to be a talloc context.
 * @param[in]     size number of bytes to process from the ndr context
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of r are undefined on an error
 */
static enum ndr_err_code pull_DER_RSA_KEY(struct ndr_pull *ndr,
					  ndr_flags_type ndr_flags,
					  struct KeyMaterialInternal *kmi,
					  uint32_t size)
{
	enum ndr_err_code ret = NDR_ERR_SUCCESS;
	struct asn1_data *asn = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(ndr->current_mem_ctx);
	if (tmp_ctx == NULL) {
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Unable to allocate temporary memory "
				      "context");
	}
	asn = asn1_init(tmp_ctx, 5);
	if (asn == NULL) {
		TALLOC_FREE(tmp_ctx);
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Unable to initialize ASN1 context");
	}
	asn1_load_nocopy(asn, ndr->data, size);

	/*
	 * PublicKeyInfo  ::=  SEQUENCE  {
	 *     algorithm  AlgorithmIdentifier,
	 *     publicKey  BIT STRING
	 *     }
	 */
	if (!asn1_start_tag(asn, ASN1_SEQUENCE(0))) {
		ret = ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Invalid ASN1 tag, expecting SEQUENCE 0x30");
		goto out;
	}

	ret = check_algorithm_identifier(ndr, asn);
	if (ret != NDR_ERR_SUCCESS) {
		goto out;
	}

	ret = read_public_key(ndr, asn, kmi);
	if (ret != NDR_ERR_SUCCESS) {
		goto out;
	}
	if (!asn1_end_tag(asn)) { /* PublicKeyInfo */
		ret = ndr_pull_error(ndr,
				     NDR_ERR_UNREAD_BYTES,
				     "ASN1 element PublicKeyInfo");
		goto out;
	}

	/* Successfully parsed the key data */
	ret = NDR_ERR_SUCCESS;
	ndr->offset += size; /* signal to NDR that the data has been consumed */

out:
	asn1_free(asn);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/**
 * @brief Convert a TPM20_RSA_KEY_BLOB into the Internal public key
 *        representation
 * @param[in,out] ndr       ndr pull context
 * @param[in]     ndr_flags
 * @param[out]    kmi       the KeyMaterialInternal structure to populate
 *                              kmi needs to be a talloc context.
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of kmi are undefined on an error
 */
static enum ndr_err_code pull_TPM20_RSAKEY_BLOB(struct ndr_pull *ndr,
						ndr_flags_type ndr_flags,
						struct KeyMaterialInternal *kmi)
{
	enum ndr_err_code ret = NDR_ERR_SUCCESS;
	struct TPM20_RSAKEY_BLOB *km = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(ndr->current_mem_ctx);
	if (tmp_ctx == NULL) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate temporary memory context");
	}

	km = talloc_zero(tmp_ctx, struct TPM20_RSAKEY_BLOB);
	if (km == NULL) {
		ret = ndr_pull_error(ndr,
				     NDR_ERR_ALLOC,
				     "Unable to allocate TPM20_RSAKEY_BLOB");
		goto out;
	}

	ret = ndr_pull_TPM20_RSAKEY_BLOB(ndr, ndr_flags, km);
	if (ret != NDR_ERR_SUCCESS) {
		goto out_km;
	}
	kmi->bit_size = km->public_key.rsa_detail.keyBits;
	kmi->modulus = data_blob_talloc(kmi,
					km->public_key.rsa.buffer,
					km->public_key.rsa.size);
	if (kmi->modulus.data == NULL) {
		ret = ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate TPM20_RSAKEY_BLOB modulus");
		goto out_km;
	}

	kmi->exponent = data_blob_talloc(kmi,
					 km->public_key.rsa_detail.exponent,
					 TPM_RSA_EXPONENT_SIZE);
	if (kmi->exponent.data == NULL) {
		ret = ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate TPM20_RSAKEY_BLOB exponent");
		goto out_km;
	}
	ret = NDR_ERR_SUCCESS;

out_km:
	TALLOC_FREE(km);
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}


/**
 * @brief Convert a BCRYPT_RSAPUBLIC_BLOB public key into the Internal public key
 *        representation
 *
 * @param[in,out] ndr       ndr pull context
 * @param[in]     ndr_flags
 * @param[out]    kmi       the KeyMaterialInternal structure to populate
 *                              kmi needs to be a talloc context.
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of kmi are undefined on an error
 */
static enum ndr_err_code pull_BCRYPT_RSAPUBLIC_BLOB(
	struct ndr_pull *ndr,
	ndr_flags_type ndr_flags,
	struct KeyMaterialInternal *kmi)
{
	enum ndr_err_code ret = NDR_ERR_SUCCESS;
	struct BCRYPT_RSAPUBLIC_BLOB *km = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(ndr->current_mem_ctx);
	if (tmp_ctx == NULL) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate temporary memory context");
	}

	km = talloc_zero(tmp_ctx, struct BCRYPT_RSAPUBLIC_BLOB);
	if (km == NULL) {
		ret = ndr_pull_error(ndr,
				     NDR_ERR_ALLOC,
				     "Unable to allocate BCRYPT_RSAPUBLIC_BLOB");
		goto out;
	}

	ret = ndr_pull_BCRYPT_RSAPUBLIC_BLOB(ndr, ndr_flags, km);
	if (ret != NDR_ERR_SUCCESS) {
		goto out_km;
	}

	kmi->bit_size = km->bit_length;

	kmi->modulus = data_blob_talloc(kmi,
					km->modulus,
					km->modulus_len);
	if (kmi->modulus.data == NULL) {
		ret = ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate BCRYPT_RSAPUBLIC_BLOB modulus");
		goto out_km;
	}

	kmi->exponent = data_blob_talloc(kmi,
					 km->public_exponent,
					 km->public_exponent_len);
	if (kmi->exponent.data == NULL) {
		ret = ndr_pull_error(
			ndr,
			NDR_ERR_ALLOC,
			"Unable to allocate BCRYPT_RSAPUBLIC_BLOB exponent");
		goto out_km;
	}

	ret = NDR_ERR_SUCCESS;

out_km:
	TALLOC_FREE(km);
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}


/**
 * @brief Convert a KeyMaterial blob into the Internal public key
 *        representation KeyMaterialInternal
 *
 * @param[in,out] ndr       ndr pull context
 * @param[in]     ndr_flags
 * @param[out]    kmi       the KeyMaterialInternal structure to populate
 *                              kmi needs to be a talloc context.
 *
 * @return NDR_ERR_SUCCESS if successful
 *         The contents of kmi are undefined on an error
 */
enum ndr_err_code ndr_pull_KeyMaterialInternal(struct ndr_pull *ndr,
					       ndr_flags_type ndr_flags,
					       struct KeyMaterialInternal *kmi)
{
	static const uint8_t BCRYPT_HEADER[] = {'R', 'S', 'A', '1'};
	static const uint8_t TPM20_HEADER[] = {'P', 'C', 'P', 'M'};
	static const uint32_t MIN_KEY_MATERIAL_SIZE = 5;
	static const uint32_t MAX_KEY_MATERIAL_SIZE = 64 * 1024;

	uint32_t size = 0;

	if (ndr->offset > ndr->data_size) {
		return ndr_pull_error(ndr,
				      NDR_ERR_LENGTH,
				      "ndr->offset (%" PRIu32
				      ") is greater than "
				      "ndr->data_size (%" PRIu32 ")",
				      ndr->offset,
				      ndr->data_size);
	}
	size = ndr->data_size - ndr->offset;
	if (size < MIN_KEY_MATERIAL_SIZE) {
		return ndr_pull_error(ndr,
				      NDR_ERR_LENGTH,
				      "KeyMaterial size of %" PRIu32
				      " bytes is too small",
				      size);
	}
	if (size > MAX_KEY_MATERIAL_SIZE) {
		return ndr_pull_error(ndr,
				      NDR_ERR_LENGTH,
				      "KeyMaterial size of %" PRIu32
				      " bytes is too large",
				      size);
	}

	if (memcmp(BCRYPT_HEADER, ndr->data, sizeof(BCRYPT_HEADER)) == 0) {
		return pull_BCRYPT_RSAPUBLIC_BLOB(ndr, ndr_flags, kmi);
	} else if (memcmp(TPM20_HEADER, ndr->data, sizeof(TPM20_HEADER)) == 0) {
		return pull_TPM20_RSAKEY_BLOB(ndr, ndr_flags, kmi);
	} else if (*ndr->data == ASN1_SEQUENCE(0)) {
		/*
		 * If the first byte is an ASN1 sequence marker assume that
		 * this is an x509 public key
		 */
		return pull_DER_RSA_KEY(ndr, ndr_flags, kmi, size);
	} else {
		return ndr_pull_error(
			ndr,
			NDR_ERR_VALIDATE,
			"Unknown KeyMaterial type, could not be decoded");
	}
}

/**
 * @brief Push a representation of a KeyMaterialInternal onto the
 *        ndr_push context.
 *
 * @param[in,out] ndr       ndr push context
 * @param[in]     ndr_flags
 * @param[out]    kmi       the KeyMaterialInternal structure to populate
 *                              kmi needs to be a talloc context.
 *
 * @note This is not currently implemented and will always return
 *       NDR_ERR_VALIDATE
 *
 * @return NDR_ERR_VALIDATE
 *
 */
enum ndr_err_code ndr_push_KeyMaterialInternal(
	struct ndr_push *ndr,
	ndr_flags_type ndr_flags,
	const struct KeyMaterialInternal *kmi)
{
	return ndr_push_error(
		ndr,
		NDR_ERR_VALIDATE,
		"NDR Push for KeyMaterialInternal not currently supported");
}
