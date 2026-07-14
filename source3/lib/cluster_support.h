/*
   Unix SMB/CIFS implementation.
   Copyright (C) 2014 Stefan Metzmacher

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

struct cluster_level_active;
struct cluster_level_ranges;

bool cluster_support_available(void);
const char *cluster_support_features(void);
const char *lp_ctdbd_socket(void);

bool cluster_level_is_valid(const struct cluster_level_active *level);
bool cluster_level_is_valid_update(const struct cluster_level_active *oldl,
				   const struct cluster_level_active *newl);
NTSTATUS cluster_level_compatible(
		const struct cluster_level_ranges *ranges,
		const struct cluster_level_active *level);

const struct cluster_level_ranges *cluster_level_supported_ranges(void);

bool cluster_level_global_is_valid(void);
void cluster_level_activate(const struct cluster_level_active *level);
void cluster_level_activate_latest(void);

/*
 * We use checks like 'if (CLUSTER_LEVEL_ACTIVE(1, 0))' in
 * order to avoid long lines when using the
 * define explicitly.
 *
 * But we use the defines implicitly in order
 * to avoid missing defines in the idl file.
 */
#define CLUSTER_LEVEL_ACTIVE(__major, __minor) \
	_cluster_level_activated( \
		CLUSTER_LEVEL_MAJOR_ ## __major, \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_ ## __minor)
bool _cluster_level_activated(uint32_t major, uint32_t minor);
