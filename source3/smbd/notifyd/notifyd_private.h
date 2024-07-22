/*
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

#ifndef __NOTIFYD_PRIVATE_H__
#define __NOTIFYD_PRIVATE_H__

#include "replace.h"
#include "lib/util/server_id.h"
#include "notifyd.h"


/*
 * Representation of a watcher for a path
 *
 * This will be stored in the db.
 */
struct notifyd_watcher {
	/*
	 * This is an intersections of the filter the watcher is listening for.
	 */
	uint32_t filter;
	uint32_t subdir_filter;

	/*
	 * Those are inout variables passed to the sys_watcher. The sys_watcher
	 * will remove the bits it can't handle.
	 */
	uint32_t sys_filter;
	uint32_t sys_subdir_filter;

	/* The handle for inotify/fam etc. */
	void *sys_watch;
};

/*
 * Representation of a notifyd instance
 *
 * This will be stored in the db.
 */
struct notifyd_instance {
	struct server_id client;
	struct notify_instance instance;
};

/*
 * Parse an entry in the notifyd_context->entries database
 */

bool notifyd_parse_entry(uint8_t *data,
			 size_t data_len,
			 struct notifyd_watcher *watcher,
			 struct notifyd_instance **instances,
			 size_t *num_instances);

#endif
