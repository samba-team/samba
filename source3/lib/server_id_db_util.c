/*
 * Unix SMB/CIFS implementation.
 * Utils around server_id_db with more dependencies
 * Copyright (C) Volker Lendecke 2014
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

#include "replace.h"
#include "server_id_db_util.h"
#include "lib/util/server_id.h"
#include "serverid.h"
#include "lib/util/samba_util.h"

static int server_id_db_check_exclusive(
	struct server_id_db *db, const char *name,
	unsigned num_servers, struct server_id *servers);

int server_id_db_set_exclusive(struct server_id_db *db, const char *name)
{
	int ret;
	unsigned num_servers;
	struct server_id *servers;

	ret = server_id_db_add(db, name);
	if (ret != 0) {
		return ret;
	}

	ret = server_id_db_lookup(db, name, talloc_tos(),
				  &num_servers, &servers);
	if (ret != 0) {
		goto done;
	}

	/*
	 * Remove entries from the server_id_db for processes that have died
	 * and could not clean up. This is racy, as two processes could
	 * simultaneously try to register a name. Both would succeed in the
	 * server_id_db_add call, and both would see their peer active during
	 * the check_exclusive call. Both would get an EEXIST, and nobody
	 * would be able to register itself. But this is okay, as this is
	 * meant to be a cleanup routine, and normally only one daemon should
	 * start up at a time anyway. Getting this "right" would mean we would
	 * have to add locking to server_id_db, or add a dependency on
	 * serverids_exist to server_id_db. Both are too heavy-weight for my
	 * taste.
	 */

	ret = server_id_db_check_exclusive(db, name, num_servers, servers);
	TALLOC_FREE(servers);

done:
	if (ret != 0) {
		server_id_db_remove(db, name);
	}
	return ret;
}

static int server_id_db_check_exclusive(
	struct server_id_db *db, const char *name,
	unsigned num_servers, struct server_id *servers)
{
	struct server_id me = server_id_db_pid(db);
	unsigned i;

	for (i=0; i<num_servers; i++) {
		int ret;

		if (server_id_same_process(&me, &servers[i])) {
			/*
			 * I am always around ... :-)
			 */
			continue;
		}

		if (serverid_exists(&servers[i])) {
			return EEXIST;
		}

		ret = server_id_db_prune_name(db, name, servers[i]);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}
