/*
 *  Unix SMB/CIFS implementation.
 *  cluster utility functions
 *  Copyright (C) Volker Lendecke 2013
 *  Copyright (C) Michael Adam 2013
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

#include "includes.h"
#include "ctdbd_conn.h"
#include "util_cluster.h"
#include "lib/cluster_support.h"

bool cluster_probe_ok(void)
{
	if (lp_clustering()) {
		int ret;

		ret = ctdbd_probe(lp_ctdbd_socket(), lp_ctdb_timeout());
		if (ret != 0) {
			DEBUG(0, ("clustering=yes but ctdbd connect failed: "
				  "%s\n", strerror(ret)));
			return false;
		}
	}

	return true;
}
