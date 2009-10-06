/*
   Unix SMB/CIFS implementation.

   DRSUAPI utility functions to be used in torture tests

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
#include "torture/torture.h"
#include "torture/rpc/drsuapi.h"
#include "../lib/util/asn1.h"

/**
 * Decode Attribute OID based on MS documentation
 * See MS-DRSR.pdf - 5.16.4
 *
 * On success returns decoded OID and
 * corresponding prefix_map index (if requested)
 */
bool drs_util_oid_from_attid(struct torture_context *tctx,
			     struct drsuapi_DsReplicaOIDMapping_Ctr *prefix_map,
			     uint32_t attid,
			     const char **_oid,
			     int *map_idx)
{
	int i;
	uint32_t hi_word, lo_word;
	DATA_BLOB bin_oid = {NULL, 0};
	struct drsuapi_DsReplicaOIDMapping *map_entry = NULL;
	TALLOC_CTX *mem_ctx = talloc_named(tctx, 0, "util_drsuapi_oid_from_attid");

	/* crack attid value */
	hi_word = attid >> 16;
	lo_word = attid & 0xFFFF;

	/* check last entry in the prefix map is the special one */
	map_entry = &prefix_map->mappings[prefix_map->num_mappings-1];
	torture_assert(tctx,
			(map_entry->id_prefix == 0)
			&& (*map_entry->oid.binary_oid == 0xFF),
			"Last entry in Prefix Map is not the special one!");

	/* locate correspoding prefixMap entry */
	map_entry = NULL;
	for (i = 0; i < prefix_map->num_mappings - 1; i++) {

		if (hi_word == prefix_map->mappings[i].id_prefix) {
			map_entry = &prefix_map->mappings[i];
			if (map_idx)	*map_idx = i;
			break;
		}
	}

	torture_assert(tctx, map_entry, "Unable to locate corresponding Prefix Map entry");

	/* copy partial oid making enough room */
	bin_oid.length = map_entry->oid.length + 2;
	bin_oid.data = talloc_array(mem_ctx, uint8_t, bin_oid.length);
	torture_assert(tctx, bin_oid.data, "Not enough memory");
	memcpy(bin_oid.data, map_entry->oid.binary_oid, map_entry->oid.length);

	if (lo_word < 128) {
		bin_oid.length = bin_oid.length - 1;
		bin_oid.data[bin_oid.length-1] = lo_word;
	}
	else {
		if (lo_word == 32768) {
			lo_word -= 32768;
		}
		bin_oid.data[bin_oid.length-2] = ((lo_word / 128) % 128) + 128; // (0x80 | ((lo_word>>7)&0x7f))
		bin_oid.data[bin_oid.length-1] = lo_word % 128; // lo_word & 0x7f
	}

	torture_assert(tctx,
			ber_read_OID_String(tctx, bin_oid, _oid),
			"Failed to decode binary OID");
	talloc_free(mem_ctx);

	return true;
}
