/*
   Unix SMB/CIFS implementation.
   Implementation of a reliable server_exists()
   Copyright (C) Volker Lendecke 2010

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

#ifndef __SERVERID_H__
#define __SERVERID_H__

#include "includes.h"
#include "lib/dbwrap/dbwrap.h"

/*
 * Register a server with its unique id
 */
bool serverid_register(const struct server_id id, uint32_t msg_flags);

/*
 * De-register a server with its unique id
 */
bool serverid_deregister(const struct server_id id);

/*
 * Check existence of a server id
 */
bool serverid_exists(const struct server_id *id);

/*
 * Check existence of a list of server ids
 */
bool serverids_exist(const struct server_id *ids, int num_ids, bool *results);

/*
 * Walk the list of server_ids registered
 */
bool serverid_traverse(int (*fn)(struct db_record *rec,
				 const struct server_id *id,
				 uint32_t msg_flags,
				 void *private_data),
		       void *private_data);

/*
 * Walk the list of server_ids registered read-only
 */
bool serverid_traverse_read(int (*fn)(const struct server_id *id,
				      uint32_t msg_flags,
				      void *private_data),
			    void *private_data);
/*
 * Ensure CLEAR_IF_FIRST works fine, to be called from the parent smbd
 */
bool serverid_parent_init(TALLOC_CTX *mem_ctx);

/*
 * Get a random unique_id and make sure that it is not
 * SERVERID_UNIQUE_ID_NOT_TO_VERIFY
 */
uint64_t serverid_get_random_unique_id(void);

#endif
