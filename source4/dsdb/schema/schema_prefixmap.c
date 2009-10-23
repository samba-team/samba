/*
   Unix SMB/CIFS implementation.

   DRS::prefixMap implementation

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "../lib/util/asn1.h"

/**
 * Initial prefixMap creation according to:
 * [MS-DRSR] section 5.12.2
 */
WERROR dsdb_schema_pfm_new(TALLOC_CTX *mem_ctx, struct dsdb_schema_prefixmap **ppfm)
{
	uint32_t i;
	struct dsdb_schema_prefixmap *pfm;
	const struct {
		uint32_t	id;
		const char	*oid_prefix;
	} pfm_init_data[] = {
		{.id=0x00000000, .oid_prefix="2.5.4"},
		{.id=0x00000001, .oid_prefix="2.5.6"},
		{.id=0x00000002, .oid_prefix="1.2.840.113556.1.2"},
		{.id=0x00000003, .oid_prefix="1.2.840.113556.1.3"},
		{.id=0x00000004, .oid_prefix="2.16.840.1.101.2.2.1"},
		{.id=0x00000005, .oid_prefix="2.16.840.1.101.2.2.3"},
		{.id=0x00000006, .oid_prefix="2.16.840.1.101.2.1.5"},
		{.id=0x00000007, .oid_prefix="2.16.840.1.101.2.1.4"},
		{.id=0x00000008, .oid_prefix="2.5.5"},
		{.id=0x00000009, .oid_prefix="1.2.840.113556.1.4"},
		{.id=0x0000000A, .oid_prefix="1.2.840.113556.1.5"},
		{.id=0x00000013, .oid_prefix="0.9.2342.19200300.100"},
		{.id=0x00000014, .oid_prefix="2.16.840.1.113730.3"},
		{.id=0x00000015, .oid_prefix="0.9.2342.19200300.100.1"},
		{.id=0x00000016, .oid_prefix="2.16.840.1.113730.3.1"},
		{.id=0x00000017, .oid_prefix="1.2.840.113556.1.5.7000"},
		{.id=0x00000018, .oid_prefix="2.5.21"},
		{.id=0x00000019, .oid_prefix="2.5.18"},
		{.id=0x0000001A, .oid_prefix="2.5.20"},
	};

	/* allocate mem for prefix map */
	pfm = talloc_zero(mem_ctx, struct dsdb_schema_prefixmap);
	W_ERROR_HAVE_NO_MEMORY(pfm);

	pfm->length = ARRAY_SIZE(pfm_init_data);
	pfm->prefixes = talloc_array(pfm, struct dsdb_schema_prefixmap_oid, pfm->length);
	W_ERROR_HAVE_NO_MEMORY(pfm->prefixes);

	/* build prefixes */
	for (i = 0; i < pfm->length; i++) {
		if (!ber_write_partial_OID_String(pfm, &pfm->prefixes[i].bin_oid, pfm_init_data[i].oid_prefix)) {
			talloc_free(pfm);
			return WERR_INTERNAL_ERROR;
		}
		pfm->prefixes[i].id = pfm_init_data[i].id;
	}

	*ppfm = pfm;

	return WERR_OK;
}


/**
 * Adds oid to prefix map.
 * On success returns ID for newly added index
 * or ID of existing entry that matches oid
 * Reference: [MS-DRSR] section 5.12.2
 *
 * \param pfm prefixMap
 * \param bin_oid OID prefix to be added to prefixMap
 * \param pfm_id Location where to store prefixMap entry ID
 */
static WERROR _dsdb_schema_pfm_add_entry(struct dsdb_schema_prefixmap *pfm, DATA_BLOB bin_oid, uint32_t *_idx)
{
	uint32_t i;
	struct dsdb_schema_prefixmap_oid * pfm_entry;
	struct dsdb_schema_prefixmap_oid * prefixes_new;

	/* dup memory for bin-oid prefix to be added */
	bin_oid = data_blob_dup_talloc(pfm, &bin_oid);
	if (!bin_oid.data) {
		return WERR_NOMEM;
	}

	/* make room for new entry */
	prefixes_new = talloc_realloc(pfm, pfm->prefixes, struct dsdb_schema_prefixmap_oid, pfm->length + 1);
	if (!prefixes_new) {
		talloc_free(bin_oid.data);
		return WERR_NOMEM;
	}
	pfm->prefixes = prefixes_new;

	/* make new unique ID in prefixMap */
	pfm_entry = &pfm->prefixes[pfm->length];
	pfm_entry->id = 0;
	for (i = 0; i < pfm->length; i++) {
		if (pfm_entry->id < pfm->prefixes[i].id)
			pfm_entry->id = pfm->prefixes[i].id;
	}

	/* add new bin-oid prefix */
	pfm_entry->id++;
	pfm_entry->bin_oid = bin_oid;

	*_idx = pfm->length;
	pfm->length++;

	return WERR_OK;
}


/**
 * Make ATTID for given OID
 * Reference: [MS-DRSR] section 5.12.2
 */
WERROR dsdb_schema_pfm_make_attid(struct dsdb_schema_prefixmap *pfm, const char *oid, uint32_t *attid)
{
	uint32_t i;
	uint32_t lo_word, hi_word;
	DATA_BLOB bin_oid;
	const char *last_subid;
	uint32_t last_value;
	struct dsdb_schema_prefixmap_oid *pfm_entry;

	if (!pfm)	return WERR_INVALID_PARAMETER;
	if (!oid)	return WERR_INVALID_PARAMETER;

	/* make last sub-identifier value */
	last_subid = strrchr(oid, '.');
	if (!last_subid) {
		return WERR_INVALID_PARAMETER;
	}
	last_subid++;
	last_value = strtoul(last_subid, NULL, 10);

	/* encode oid in BER format */
	if (!ber_write_OID_String(pfm, &bin_oid, oid)) {
		return WERR_INTERNAL_ERROR;
	}

	/* get the prefix of the OID */
	if (last_value < 128) {
		bin_oid.length -= 1;
	} else {
		bin_oid.length -= 2;
	}

	/* search the prefix in the prefix table, if none found, add
	 * one entry for new prefix.
	 */
	pfm_entry = NULL;
	for (i = 0; i < pfm->length; i++) {
		if (pfm->prefixes[i].bin_oid.length != bin_oid.length)
			continue;

		if (memcmp(pfm->prefixes[i].bin_oid.data, bin_oid.data, bin_oid.length) == 0) {
			pfm_entry = &pfm->prefixes[i];
			break;
		}
	}
	/* add entry in no entry exists */
	if (!pfm_entry) {
		uint32_t idx;
		WERROR werr = _dsdb_schema_pfm_add_entry(pfm, bin_oid, &idx);
		W_ERROR_NOT_OK_RETURN(werr);

		pfm_entry = &pfm->prefixes[idx];
	} else {
		/* free memory allocated for bin_oid */
		data_blob_free(&bin_oid);
	}

	/* compose the attid */
	lo_word = last_value % 16384;	/* actually get lower 14 bits: lo_word & 0x3FFF */
	if (last_value >= 16384) {
		/* mark it so that it is known to not be the whole lastValue
		 * This will raise 16-th bit*/
		lo_word += 32768;
	}
	hi_word = pfm_entry->id;

	/* make ATTID:
	 * HIWORD is prefixMap id
	 * LOWORD is truncated binary-oid */
	*attid = (hi_word * 65536) + lo_word;

	return WERR_OK;
}


/**
 * Make OID for given ATTID.
 * Reference: [MS-DRSR] section 5.12.2
 */
WERROR dsdb_schema_pfm_oid_from_attid(struct dsdb_schema_prefixmap *pfm, uint32_t attid,
				      TALLOC_CTX *mem_ctx, const char **_oid)
{
	int i;
	uint32_t hi_word, lo_word;
	DATA_BLOB bin_oid = {NULL, 0};
	struct dsdb_schema_prefixmap_oid *pfm_entry;
	WERROR werr = WERR_OK;

	/* crack attid value */
	hi_word = attid >> 16;
	lo_word = attid & 0xFFFF;

	/* locate corRespoNding prefixMap entry */
	pfm_entry = NULL;
	for (i = 0; i < pfm->length; i++) {
		if (hi_word == pfm->prefixes[i].id) {
			pfm_entry = &pfm->prefixes[i];
			break;
		}
	}

	if (!pfm_entry) {
		return WERR_INTERNAL_ERROR;
	}

	/* copy oid prefix making enough room */
	bin_oid.length = pfm_entry->bin_oid.length + 2;
	bin_oid.data = talloc_array(mem_ctx, uint8_t, bin_oid.length);
	W_ERROR_HAVE_NO_MEMORY(bin_oid.data);
	memcpy(bin_oid.data, pfm_entry->bin_oid.data, pfm_entry->bin_oid.length);

	if (lo_word < 128) {
		bin_oid.length = bin_oid.length - 1;
		bin_oid.data[bin_oid.length-1] = lo_word;
	}
	else {
		if (lo_word >= 32768) {
			lo_word -= 32768;
		}
		bin_oid.data[bin_oid.length-2] = (0x80 | ((lo_word>>7) & 0x7f));
		bin_oid.data[bin_oid.length-1] = lo_word & 0x7f;
	}

	if (!ber_read_OID_String(mem_ctx, bin_oid, _oid)) {
		werr = WERR_INTERNAL_ERROR;
	}

	/* free locally allocated memory */
	talloc_free(bin_oid.data);

	return werr;
}

