/*
   Unix SMB/CIFS implementation.
   cmdline context wrapper.

   Copyright (C) Christof Schmitt <cs@samba.org> 2018

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

#include "cmdline_contexts.h"
#include "includes.h"
#include "messages.h"

struct messaging_context *cmdline_messaging_context(const char *config_file)
{
	struct messaging_context *msg_ctx = NULL;

	/*
	 * Ensure that a config is loaded, in case the underlying
	 * messaging_init needs to create directories or sockets.
	 */
	if (!lp_loaded()) {
		if (!lp_load_initial_only(config_file)) {
			return NULL;
		}
	}

	/*
	 * Clustered Samba can only work as root due to required
	 * access to the registry and ctdb, which in turn requires
	 * messaging access as root.
	 */
	if (lp_clustering() && geteuid() != 0) {
		fprintf(stderr, "Cluster mode requires running as root.\n");
		exit(1);
	}

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		if (geteuid() == 0) {
			fprintf(stderr,
				"Unable to initialize messaging context!\n");
			exit(1);
		} else {
			/*
			 * Non-cluster, non-root: Log error, but leave
			 * it up to the caller how to proceed.
			 */
			DBG_NOTICE("Unable to initialize messaging context.\n");
		}
	}

	return msg_ctx;
}

void cmdline_messaging_context_free(void)
{
	global_messaging_context_free();
}
