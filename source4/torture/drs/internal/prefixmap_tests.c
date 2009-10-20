/*
   Unix SMB/CIFS implementation.

   DRSUAPI prefixMap unit tests

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "torture/smbtorture.h"
#include "torture/rpc/drsuapi.h"
#include "dsdb/samdb/samdb.h"


/**
 * Private data to be shared among all test in Test case
 */
struct drsut_prefixmap_data {
	struct dsdb_schema_prefixmap *prefixmap;
};


/**
 * Initial prefix map creation function
 *
 */
static struct dsdb_schema_prefixmap * _drsut_prefixmap_new(struct torture_context *tctx)
{
	return NULL;
}

/*
 * Setup/Teardown for test case
 */
static bool torture_drs_unit_prefixmap_setup(struct torture_context *tctx, struct drsut_prefixmap_data **priv)
{
	*priv = talloc_zero(tctx, struct drsut_prefixmap_data);
	(*priv)->prefixmap = _drsut_prefixmap_new(tctx);
	return true;
}

static bool torture_drs_unit_prefixmap_teardown(struct torture_context *tctx, struct drsut_prefixmap_data *priv)
{
	return true;
}

/**
 * Test case initialization for
 * DRS-UNIT.prefixMap
 */
struct torture_tcase * torture_drs_unit_prefixmap(struct torture_suite *suite)
{
	typedef bool (*pfn_setup)(struct torture_context *, void **);
	typedef bool (*pfn_teardown)(struct torture_context *, void *);

	struct torture_tcase * tc = torture_suite_add_tcase(suite, "prefixMap");

	torture_tcase_set_fixture(tc,
				  (pfn_setup)torture_drs_unit_prefixmap_setup,
				  (pfn_teardown)torture_drs_unit_prefixmap_teardown);

	tc->description = talloc_strdup(tc, "Unit tests for DRSUAPI::prefixMap implementation");

	return tc;
}
