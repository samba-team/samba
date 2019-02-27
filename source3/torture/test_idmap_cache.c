/*
 * Unix SMB/CIFS implementation.
 * Test dbwrap_watch API
 * Copyright (C) Volker Lendecke 2017
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

#include "includes.h"
#include "torture/proto.h"
#include "lib/idmap_cache.h"
#include "librpc/gen_ndr/idmap.h"
#include "libcli/security/dom_sid.h"

bool run_local_idmap_cache1(int dummy)
{
	struct dom_sid sid, found_sid;
	struct unixid xid, found_xid;
	bool ret = false;
	bool expired = false;

	xid = (struct unixid) { .id = 1234, .type = ID_TYPE_UID };
	dom_sid_parse("S-1-5-21-2864185242-3846410404-2398417794-1235", &sid);
	idmap_cache_set_sid2unixid(&sid, &xid);

	ret = idmap_cache_find_sid2unixid(&sid, &found_xid, &expired);
	if (!ret) {
		fprintf(stderr, "idmap_cache_find_sid2unixid failed\n");
		goto done;
	}
	if (expired) {
		fprintf(stderr,
			"idmap_cache_find_sid2unixid returned an expired "
			"value\n");
		goto done;
	}
	if ((xid.type != found_xid.type) || (xid.id != found_xid.id)) {
		fprintf(stderr,
			"idmap_cache_find_sid2unixid returned wrong "
			"values\n");
		goto done;
	}

	ret = idmap_cache_find_xid2sid(&xid, &found_sid, &expired);
	if (!ret) {
		fprintf(stderr, "idmap_cache_find_xid2sid failed\n");
		goto done;
	}
	if (expired) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid returned an expired "
			"value\n");
		goto done;
	}
	if (!dom_sid_equal(&sid, &found_sid)) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid returned wrong sid\n");
		goto done;
	}

	xid.type = ID_TYPE_GID;

	ret = idmap_cache_find_xid2sid(&xid, &found_sid, &expired);
	if (ret) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid found a GID where it "
			"should not\n");
		goto done;
	}

	idmap_cache_del_sid(&sid);

	xid.type = ID_TYPE_UID;
	ret = idmap_cache_find_xid2sid(&xid, &found_sid, &expired);
	if (ret) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid found a UID where it "
			"should not\n");
		goto done;
	}

	/*
	 * Test that negative mappings can also be cached
	 */
	sid = (struct dom_sid) {0};
	xid = (struct unixid) { .id = 1234, .type = ID_TYPE_UID };
	idmap_cache_set_sid2unixid(&sid, &xid);

	ret = idmap_cache_find_xid2sid(&xid, &found_sid, &expired);
	if (!ret) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid failed to find "
			"negative mapping\n");
		goto done;
	}
	if (expired) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid returned an expired "
			"value\n");
		goto done;
	}
	if (!dom_sid_equal(&sid, &found_sid)) {
		fprintf(stderr,
			"idmap_cache_find_xid2sid returned wrong sid\n");
		goto done;
	}

	ret = true;
done:
	return ret;
}
