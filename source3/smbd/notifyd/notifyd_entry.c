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

#include "replace.h"
#include "lib/util/debug.h"
#include "notifyd_private.h"

/*
 * Parse an entry in the notifyd_context->entries database
 */

bool notifyd_parse_entry(
	uint8_t *buf,
	size_t buflen,
	struct notifyd_instance **instances,
	size_t *num_instances)
{
	if ((buflen % sizeof(struct notifyd_instance)) != 0) {
		DBG_WARNING("invalid buffer size: %zu\n", buflen);
		return false;
	}

	if (instances != NULL) {
		*instances = (struct notifyd_instance *)buf;
	}
	if (num_instances != NULL) {
		*num_instances = buflen / sizeof(struct notifyd_instance);
	}
	return true;
}
