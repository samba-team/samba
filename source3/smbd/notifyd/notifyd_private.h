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
 * notifyd's representation of a notify instance
 */
struct notifyd_instance {
	struct server_id client;
	struct notify_instance instance;

	void *sys_watch; /* inotify/fam/etc handle */

	/*
	 * Filters after sys_watch took responsibility of some bits
	 */
	uint32_t internal_filter;
	uint32_t internal_subdir_filter;
};

/*
 * Parse an entry in the notifyd_context->entries database
 */

bool notifyd_parse_entry(
	uint8_t *buf,
	size_t buflen,
	struct notifyd_instance **instances,
	size_t *num_instances);

#endif
