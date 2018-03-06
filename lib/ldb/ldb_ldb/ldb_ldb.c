/*
 * ldb connection and module initialisation
 *
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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
 *
 */
#include "ldb_private.h"
#include "../ldb_tdb/ldb_tdb.h"
#ifdef HAVE_LMDB
#include "../ldb_mdb/ldb_mdb.h"
#endif /* HAVE_LMDB */

/*
  connect to the database
*/
static int lldb_connect(struct ldb_context *ldb,
			const char *url,
			unsigned int flags,
			const char *options[],
			struct ldb_module **module)
{
	const char *path;
	int ret;

	/*
	 * Check and remove the url prefix
	 */
	if (strchr(url, ':')) {
		if (strncmp(url, "ldb://", 6) != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid ldb URL '%s'", url);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		path = url+6;
	} else {
		path = url;
	}

	/*
	 * Don't create the database if it's not there
	 */
	flags |= LDB_FLG_DONT_CREATE_DB;
#ifdef HAVE_LMDB
	/*
	 * Try opening the database as an lmdb
	 */
	ret = lmdb_connect(ldb, path, flags, options, module);
	if (ret == LDB_SUCCESS) {
		return ret;
	}
	if (ret != LDB_ERR_UNAVAILABLE) {
		return ret;
	}

	/*
	 * Not mdb so try as tdb
	 */
#endif /* HAVE_LMDB */
	ret = ltdb_connect(ldb, path, flags, options, module);
	return ret;
}

int ldb_ldb_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_backend("ldb", lldb_connect, false);
}
