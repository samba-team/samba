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

/**
 * @brief Parse a notifyd database entry.
 *
 * The memory we pass down needs to be aligned. If it isn't aligned we can run
 * into obscure errors as we just point into the data buffer.
 *
 * @param data The data to parse
 * @param data_len The length of the data to parse
 * @param watcher A pointer to store the watcher data or NULL.
 * @param instances A pointer to store the array of notify instances or NULL.
 * @param pnum_instances The number of elements in the array. If you just want
 * the number of elements pass NULL for the watcher and instances pointers.
 *
 * @return true on success, false if an error occurred.
 */
bool notifyd_parse_entry(uint8_t *data,
			 size_t data_len,
			 struct notifyd_watcher *watcher,
			 struct notifyd_instance **instances,
			 size_t *pnum_instances)
{
	size_t ilen;

	if (data_len < sizeof(struct notifyd_watcher)) {
		return false;
	}

	if (watcher != NULL) {
		*watcher = *((struct notifyd_watcher *)(uintptr_t)data);
	}

	ilen = data_len - sizeof(struct notifyd_watcher);
	if ((ilen % sizeof(struct notifyd_instance)) != 0) {
		return false;
	}

	if (pnum_instances != NULL) {
		*pnum_instances = ilen / sizeof(struct notifyd_instance);
	}
	if (instances != NULL) {
		/* The (uintptr_t) cast removes a warning from -Wcast-align. */
		*instances =
			(struct notifyd_instance *)(uintptr_t)
				(data + sizeof(struct notifyd_watcher));
	}

	return true;
}
