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

#include "includes.h"
#include <tdb.h>
#include "cluster_support.h"
#include "librpc/gen_ndr/ndr_cluster_level.h"

#ifdef CLUSTER_SUPPORT
#include <ctdb_protocol.h>
#endif

static void cluster_level_range_asserts(void);

bool cluster_support_available(void)
{
#ifdef CLUSTER_SUPPORT
	return true;
#else
	return false;
#endif
}

/*
 * Add the newer ranges at the beginning
 * CFL_RANGE(__major, __minor_min, __minor_max)
 */
#define CFL_ALL_RANGES \
	CFL_RANGE(1, 0, 0)

/*
 * Cross check for mistakes in the CFL_ALL_RANGES definition
 *
 * For now we limit major and minor levels to UINT8_MAX,
 * but that's not a hard limit as we use uint32_t.
 * This should still last a long time with two
 * major number changes a year. And the developers
 * should think about raising the check...
 *
 * Also note that level 0.0 is not allowed,
 * as it's reserved for unknown level.
 *
 * If we ever want to support upgrades from
 * older versions, the older version needs to
 * begin with level 0.1
 */
#define CFL_RANGE(__major, __minor_min, __minor_max) \
	BUILD_ASSERT( \
		CLUSTER_LEVEL_MAJOR_ ## __major \
		== (__major)); \
	BUILD_ASSERT( \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_ ## __minor_min \
		== (__minor_min)); \
	BUILD_ASSERT((__major) == 0 || \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_MIN \
		== (__minor_min)); \
	BUILD_ASSERT( \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_ ## __minor_max \
		== (__minor_max)); \
	BUILD_ASSERT((__major) == 0 || \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_MAX \
		== (__minor_max)); \
	BUILD_ASSERT((__minor_min)  <= __minor_max); \
	BUILD_ASSERT((__major)     < UINT8_MAX); \
	BUILD_ASSERT((__major) == 0 || (__minor_max) < UINT8_MAX); \
	BUILD_ASSERT((__major) != 0 || (__minor_max) != 0);
	CFL_ALL_RANGES
#undef CFL_RANGE

const char *cluster_support_features(void)
{
#define _LINE_DEF(x) "   " #x "\n"
#define _LINE_STR(x) "   " #x ": " x "\n"
#define _LINE_INT(x) "   " #x ": " __STRINGSTRING(x) "\n"
	static const char *v = "Cluster support features:\n"
#ifdef CLUSTER_SUPPORT
	_LINE_DEF(CLUSTER_SUPPORT)
#else
	"   NONE\n"
#endif
#ifdef CTDB_SOCKET
	_LINE_STR(CTDB_SOCKET)
#endif
#ifdef CTDB_PROTOCOL
	_LINE_INT(CTDB_PROTOCOL)
#endif

#ifdef CLUSTER_SUPPORT
	"   Cluster Functional Levels: \n"
#define CFL_RANGE(__major, __minor_min, __minor_max) \
	"      " \
		__STRINGSTRING(__major) \
		"." \
		__STRINGSTRING(__minor_min) \
		" -> " \
		__STRINGSTRING(__major) \
		"." \
		__STRINGSTRING(__minor_max) \
		"\n"
	CFL_ALL_RANGES
#undef CFL_RANGE
#endif /* CLUSTER_SUPPORT */
	"";

	cluster_level_range_asserts();
	return v;
}

const char *lp_ctdbd_socket(void)
{
	const char *ret;

	ret = lp__ctdbd_socket();
	if (ret != NULL && strlen(ret) > 0) {
		return ret;
	}

#ifdef CTDB_SOCKET
	return CTDB_SOCKET;
#else
	return "";
#endif
}

/*
 * Basic checks of the level
 */
bool cluster_level_is_valid(const struct cluster_level_active *level)
{
	cluster_level_range_asserts();

	if (level == NULL) {
		return false;
	}

	if (level->major == 0 && level->minor == 0) {
		return false;
	}

	return true;
}

/*
 * Verify that old and new cluster levels are compatible when updating
 */
bool cluster_level_is_valid_update(const struct cluster_level_active *oldl,
				   const struct cluster_level_active *newl)
{
	SMB_ASSERT(oldl != NULL);

	if (!cluster_level_is_valid(newl)) {
		return false;
	}

	if (newl->major < oldl->major) {
		return false;
	}

	if (newl->major > oldl->major) {
		return true;
	}

	if (newl->minor < oldl->minor) {
		return false;
	}

	return true;
}

/*
 * Checks the current active level is supported by the ranges of this node
 */
NTSTATUS cluster_level_compatible(
		const struct cluster_level_ranges *ranges,
		const struct cluster_level_active *level)
{
	NTSTATUS error = NT_STATUS_UNKNOWN_REVISION;
	uint32_t i;

	/*
	 * level 0.0 will never be supported,
	 * it's just used to indicate the global
	 * db record is not there yet.
	 */
	if (!cluster_level_is_valid(level)) {
		return NT_STATUS_INVALID_LEVEL;
	}

	for (i = 0; i < ranges->num_ranges; i++) {
		const struct cluster_level_range *range =
			&ranges->ranges[i];

		if (level->major != range->major) {
			continue;
		}

		/*
		 * At least the major number matched,
		 * turn any possible error from
		 * NT_STATUS_UNKNOWN_REVISION into
		 * NT_STATUS_REVISION_MISMATCH.
		 */
		error = NT_STATUS_REVISION_MISMATCH;

		if (level->minor < range->minor_min) {
			continue;
		}

		if (level->minor > range->minor_max) {
			continue;
		}

		return NT_STATUS_OK;
	}

	return error;
}

static const struct cluster_level_range supported_ranges[] = {
#ifdef CLUSTER_SUPPORT
#define CFL_RANGE(__major, __minor_min, __minor_max) \
	{ \
		.major = \
		CLUSTER_LEVEL_MAJOR_ ## __major, \
		.minor_min = \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_ ## __minor_min, \
		.minor_max = \
		CLUSTER_LEVEL_MAJOR_ ## __major  ## _MINOR_ ## __minor_max, \
	},
	CFL_ALL_RANGES
#undef CFL_RANGE
#else /* no CLUSTER_SUPPORT */
	{
		/*
		 * Without cluster support we only support
		 * the latest level.
		 */
		.major = CLUSTER_LEVEL_MAJOR_LATEST,
		.minor_min = CLUSTER_LEVEL_MAJOR_LATEST_MINOR_MAX,
		.minor_max = CLUSTER_LEVEL_MAJOR_LATEST_MINOR_MAX,
	},

#endif /* no CLUSTER_SUPPORT */
};
BUILD_ASSERT(ARRAY_SIZE(supported_ranges) >= 1);

static const struct cluster_level_ranges supported_levels = {
	.num_ranges = ARRAY_SIZE(supported_ranges),
	.ranges = discard_const(supported_ranges),
};

static void cluster_level_range_asserts(void)
{
	static bool checked;
	size_t i;

	if (checked) {
		return;
	}

	/*
	 * The following don't work as BUILD_ASSERT(),
	 * so we use SMB_ASSERT(), so that
	 * any make test fails immediately
	 *
	 * The ranges should be sorted with the
	 * latest level first.
	 */
	SMB_ASSERT(supported_ranges[0].major ==
		   CLUSTER_LEVEL_MAJOR_LATEST);
	SMB_ASSERT(supported_ranges[0].minor_max ==
		   CLUSTER_LEVEL_MAJOR_LATEST_MINOR_MAX);
	for (i = 1; i < ARRAY_SIZE(supported_ranges); i++) {
		if (supported_ranges[i-1].major == 0) {
			/*
			 * For legacy upgrades we use allow
			 * multiple ranges with major level 0.
			 */
			SMB_ASSERT(supported_ranges[i].major == 0);
			SMB_ASSERT(supported_ranges[i-1].minor_min >
				   supported_ranges[i].minor_max);
			continue;
		}

		SMB_ASSERT(supported_ranges[i-1].major >
			   supported_ranges[i].major);
	}

	SMB_ASSERT(supported_levels.num_ranges == ARRAY_SIZE(supported_ranges));
	SMB_ASSERT(supported_levels.ranges == supported_ranges);

	checked = true;
}

/*
 * Returns the cluster_level_ranges supported by this node
 */
const struct cluster_level_ranges *cluster_level_supported_ranges(void)
{
	cluster_level_range_asserts();

	return &supported_levels;
}

/*
 * The global functional level after we've learned it from the cluster_level.db
 */
static struct cluster_level_active global_level_activated;

/*
 * Check the global functional level is valid
 */
bool cluster_level_global_is_valid(void)
{
	return cluster_level_is_valid(&global_level_activated);
}

/*
 * Activate the functional level
 *
 * This gets used by callers after they've learnt the functional level
 * from cluster_level.db. Remembers the level in a local variable.
 */
void cluster_level_activate(const struct cluster_level_active *level)
{
	/*
	 * only upgrades are possible
	 */
	SMB_ASSERT(lp_clustering());
	SMB_ASSERT(cluster_level_is_valid(level));
	SMB_ASSERT(cluster_level_is_valid_update(&global_level_activated, level));

	global_level_activated = *level;

	/*
	 * We should have at least the oldest version we support
	 * for the clustered case.
	 */
	SMB_ASSERT(CLUSTER_LEVEL_ACTIVE(1, 0));
}

/*
 * Can be used to set the active level to the latest supported level
 */
void cluster_level_activate_latest(void)
{
	SMB_ASSERT(!lp_clustering());

	global_level_activated = (struct cluster_level_active) {
		.major = supported_ranges[0].major,
		.minor = supported_ranges[0].minor_max,
	};

	/*
	 * We should have the latest version we support
	 * in the non-clustered case.
	 */
	SMB_ASSERT(CLUSTER_LEVEL_ACTIVE(LATEST, MAX));
}

/*
 * Return the global functional level, even if its
 * not valid yet.
 */
const struct cluster_level_active *cluster_level_global_active(void)
{
	cluster_level_range_asserts();

	return &global_level_activated;
}

/*
 * This will allow code like this:
 *
 * if (CLUSTER_LEVEL_ACTIVATED(5, 2)) {
 *    // handle 5.2
 * } else if (CLUSTER_LEVEL_ACTIVATED(3, 0)) {
 *    // handle 3.0
 * } else if (CLUSTER_LEVEL_ACTIVATED(1, 0)) {
 *    // handle 1.0
 * } else if (CLUSTER_LEVEL_ACTIVATED(0, 1)) {
 *    // handle 0.1
 * } else {
 *    // error!!! 0.0 should never be active
 * }
 */
bool _cluster_level_activated(uint32_t major, uint32_t minor)
{
	/*
	 * cluster_level_activate_latest() or
	 * cluster_level_activate() should be called
	 * already!
	 */
	SMB_ASSERT(cluster_level_global_is_valid());

	if (global_level_activated.major > major) {
		/*
		 * 7.0 is active and the caller
		 * checks if 5.2 features are available.
		 */
		return true;
	}

	if (global_level_activated.major < major) {
		/*
		 * 3.0 is active and the caller
		 * checks if 5.2 features are available.
		 */
		return false;
	}

	if (global_level_activated.minor >= minor) {
		/*
		 * 5.3 is active and the caller
		 * checks if 5.2 features are available.
		 */
		return true;
	}

	return false;
}
