/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WSP_UTIL_H
#define WSP_UTIL_H

#include "librpc/wsp/wsp_helper.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"

struct memcache;
struct global_handle_record;
/*
 * will try to retrieve already cached id for urn
 * if id is not cached for urn then we create both
 *   urn -> id  &
 *   id -> urn (reverse map)
 * in a tdb database.
 * So, you pass in lcl_cache which is intended to be the first
 * level memory client cache, this is searched first, if the key is found
 * in the first level cache we just return it and are done. If the key is not
 * found in the first level cache we search the tdb database. If the
 * value is not found in the tdb database we create the key and value
 * and populate the cache with key -> value (and also the reverse e.g.
 * value -> key).
 * Additionally the first level cache is populated with pointers to the
 * values stored in the backing store tb database.
 * Thus, each client that exists in a single worker process can hold
 * references to the values stored in the tdb database, when all clients
 * that hold references to the tdb database entries are free'd only then
 * are the entries in the tdb database scanned to see if any are ready
 * to be deleted. If we move to a multi worker process model things will
 * become more complicated as coordination between the workers probably
 * will need to happen.
 */
uint32_t get_or_create_entry_id(struct memcache *lcl_cache,
		const char *index,
		const char *urn);
const char *get_path_for_id(struct memcache *lcl_ctx,
		const char *index,
		uint32_t id);
uint32_t generate_handle(void);
#endif
