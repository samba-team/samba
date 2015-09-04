/*
 * Namedb
 *
 * Copyright Volker Lendecke <vl@samba.org> 2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SERVER_ID_DB_H_
#define _SERVER_ID_DB_H_

#include "talloc.h"
#include "librpc/gen_ndr/server_id.h"

struct server_id_db;

struct server_id_db *server_id_db_init(TALLOC_CTX *mem_ctx,
				       struct server_id pid,
				       const char *base_path,
				       int hash_size, int tdb_flags);
void server_id_db_reinit(struct server_id_db *db, struct server_id pid);
struct server_id server_id_db_pid(struct server_id_db *db);
int server_id_db_add(struct server_id_db *db, const char *name);
int server_id_db_remove(struct server_id_db *db, const char *name);
int server_id_db_prune_name(struct server_id_db *db, const char *name,
			    struct server_id server);
int server_id_db_lookup(struct server_id_db *db, const char *name,
			TALLOC_CTX *mem_ctx, unsigned *num_servers,
			struct server_id **servers);
bool server_id_db_lookup_one(struct server_id_db *db, const char *name,
			     struct server_id *server);
int server_id_db_traverse_read(struct server_id_db *db,
			       int (*fn)(const char *name,
					 unsigned num_servers,
					 const struct server_id *servers,
					 void *private_data),
			       void *private_data);

#endif
