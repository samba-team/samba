/*
 * Unix SMB/CIFS implementation.
 * namemap_cache.c
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
#include "lib/namemap_cache.h"
#include "libcli/security/dom_sid.h"
#include "lib/gencache.h"

static const struct dom_sid domsid = {
	1, 4, {0,0,0,0,0,5}, {21, 123, 456, 789}
};

static void namemap_cache1_fn1(const char *domain,
			       const char *name,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = strequal(domain, "nt authority");
	ok &= strequal(name, "network");
	ok &= (type == SID_NAME_WKN_GRP);

	*p_ok = ok;
}

static void namemap_cache1_fn2(const struct dom_sid *sid,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = dom_sid_equal(sid, &global_sid_Network);
	ok &= (type == SID_NAME_WKN_GRP);

	*p_ok = ok;
}

static void namemap_cache1_fn3(const char *domain,
			       const char *name,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = strequal(domain, "");
	ok &= strequal(name, "everyone");
	ok &= (type == SID_NAME_WKN_GRP);

	*p_ok = ok;
}

static void namemap_cache1_fn4(const struct dom_sid *sid,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = dom_sid_equal(sid, &global_sid_World);
	ok &= (type == SID_NAME_WKN_GRP);

	*p_ok = ok;
}

static void namemap_cache1_fn5(const char *domain,
			       const char *name,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = strequal(domain, "samba-dom");
	ok &= strequal(name, "");
	ok &= (type == SID_NAME_DOMAIN);

	*p_ok = ok;
}

static void namemap_cache1_fn6(const struct dom_sid *sid,
			       enum lsa_SidType type,
			       bool expired,
			       void *private_data)
{
	bool *p_ok = private_data;
	bool ok;

	ok = dom_sid_equal(sid, &domsid);
	ok &= (type == SID_NAME_DOMAIN);

	*p_ok = ok;
}

bool run_local_namemap_cache1(int dummy)
{
	bool found;
	bool ok;

	ok = gencache_set("SID2NAME/S-1-5-2", "invalid", time(NULL)+60);
	if (!ok) {
		fprintf(stderr, "gencache_set failed\n");
		return false;
	}

	ok = namemap_cache_find_sid(&global_sid_Network, namemap_cache1_fn1,
				    &found);
	if (ok) {
		fprintf(stderr, "namemap_cache_find_sid parsed valid value\n");
		return false;
	}

	ok = namemap_cache_set_sid2name(&global_sid_Network,
					"NT Authority", "Network",
					SID_NAME_WKN_GRP,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set_sid2name failed\n");
		return false;
	}

	ok = namemap_cache_find_sid(&global_sid_Network, namemap_cache1_fn1,
				    &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_sid failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	ok = namemap_cache_set_name2sid("NT Authority", "Network",
					&global_sid_Network,
					SID_NAME_WKN_GRP,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set_name2sid failed\n");
		return false;
	}

	ok = namemap_cache_find_name("nt authority", "network",
				     namemap_cache1_fn2, &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_name failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	ok = namemap_cache_find_name("foo", "bar", namemap_cache1_fn2, &found);
	if (ok) {
		fprintf(stderr,
			"namemap_cache_find_name succeeded unexpectedly\n");
		return false;
	}

	/*
	 * Test "" domain name
	 */

	ok = namemap_cache_set_sid2name(&global_sid_World, "", "Everyone",
					SID_NAME_WKN_GRP,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set_sid2name failed\n");
		return false;
	}

	ok = namemap_cache_find_sid(&global_sid_World, namemap_cache1_fn3,
				    &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_sid failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	ok = namemap_cache_set_name2sid("", "Everyone",
					&global_sid_World, SID_NAME_WKN_GRP,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set failed\n");
		return false;
	}

	ok = namemap_cache_find_name("", "everyone",
				     namemap_cache1_fn4, &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_name failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	/*
	 * Test domain only
	 */

	ok = namemap_cache_set_sid2name(&domsid, "SAMBA-DOM", "",
					SID_NAME_DOMAIN,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set failed\n");
		return false;
	}

	ok = namemap_cache_find_sid(&domsid, namemap_cache1_fn5,
				    &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_sid failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	ok = namemap_cache_set_name2sid("SAMBA-DOM", "",
					&domsid, SID_NAME_DOMAIN,
					time(NULL) + 60);
	if (!ok) {
		fprintf(stderr, "namemap_cache_set failed\n");
		return false;
	}

	ok = namemap_cache_find_name("samba-dom", "",
				     namemap_cache1_fn6, &found);
	if (!ok) {
		fprintf(stderr, "namecache_find_name failed\n");
		return false;
	}
	if (!found) {
		fprintf(stderr, "wrong values found\n");
		return false;
	}

	return true;
}
