/*
   Test suite for FSRVP server state

   Copyright (C) David Disseldorp 2012-2015

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
#include <unistd.h>

#include "librpc/gen_ndr/security.h"
#include "lib/param/param.h"
#include "lib/util/dlinklist.h"
#include "libcli/resolve/resolve.h"
#include "librpc/gen_ndr/ndr_fsrvp.h"
#include "librpc/gen_ndr/ndr_fsrvp_c.h"
#include "source3/rpc_server/fss/srv_fss_private.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

static bool test_fsrvp_state_empty(struct torture_context *tctx)
{
	NTSTATUS status;
	struct fss_global fss_global;
	struct stat sbuf;
	char db_dir[] = "fsrvp_torture_XXXXXX";
	char *db_path = talloc_asprintf(NULL, "%s/%s",
					mkdtemp(db_dir), FSS_DB_NAME);

	memset(&fss_global, 0, sizeof(fss_global));
	fss_global.mem_ctx = talloc_new(NULL);
	fss_global.db_path = db_path;

	status = fss_state_store(fss_global.mem_ctx, fss_global.sc_sets,
				 fss_global.sc_sets_count, fss_global.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to store empty fss state");

	torture_assert_int_equal(tctx, stat(fss_global.db_path, &sbuf), 0,
			"failed to stat fss state tdb");
	talloc_free(fss_global.mem_ctx);

	memset(&fss_global, 0, sizeof(fss_global));
	fss_global.mem_ctx = talloc_new(NULL);
	fss_global.db_path = db_path;

	status = fss_state_retrieve(fss_global.mem_ctx, &fss_global.sc_sets,
				    &fss_global.sc_sets_count,
				    fss_global.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to retrieve empty fss state");
	torture_assert_int_equal(tctx, fss_global.sc_sets_count, 0,
				 "sc_sets_count set when it should be zero");
	talloc_free(fss_global.mem_ctx);
	unlink(db_path);
	rmdir(db_dir);
	talloc_free(db_path);

	return true;
}

static bool test_fsrvp_state_sc_set(struct torture_context *tctx,
				    TALLOC_CTX *mem_ctx,
				    struct fss_sc_set **sc_set_out)
{
	struct fss_sc_set *sc_set;

	sc_set = talloc_zero(mem_ctx, struct fss_sc_set);
	sc_set->id = GUID_random();
	sc_set->id_str = GUID_string(sc_set, &sc_set->id);
	sc_set->state = FSS_SC_COMMITED;
	sc_set->context = FSRVP_CTX_FILE_SHARE_BACKUP;
	*sc_set_out = sc_set;

	return true;
}

static bool test_fsrvp_state_sc(struct torture_context *tctx,
				TALLOC_CTX *mem_ctx,
				struct fss_sc **sc_out)
{
	struct fss_sc *sc;

	sc = talloc_zero(mem_ctx, struct fss_sc);
	sc->id = GUID_random();
	sc->id_str = GUID_string(sc, &sc->id);
	sc->volume_name = talloc_strdup(sc, "/this/is/a/path");
	/* keep snap path NULL, i.e. not yet committed */
	sc->create_ts = time(NULL);
	*sc_out = sc;

	return true;
}

static bool test_fsrvp_state_smap(struct torture_context *tctx,
				TALLOC_CTX *mem_ctx,
				const char *base_share_name,
				const char *sc_share_name,
				struct fss_sc_smap **smap_out)
{
	struct fss_sc_smap *smap;

	smap = talloc_zero(mem_ctx, struct fss_sc_smap);
	smap->share_name = talloc_strdup(mem_ctx, base_share_name);
	smap->sc_share_name = talloc_strdup(mem_ctx, sc_share_name);
	smap->sc_share_comment = talloc_strdup(mem_ctx, "test sc share comment");
	smap->is_exposed = false;
	*smap_out = smap;

	return true;
}

static bool test_fsrvp_state_smap_compare(struct torture_context *tctx,
					  struct fss_sc_smap *smap_1,
					  struct fss_sc_smap *smap_2)
{
	/* already confirmed by caller */
	torture_assert_str_equal(tctx, smap_1->sc_share_name,
				 smap_2->sc_share_name,
				 "smap sc share name strings differ");

	torture_assert_str_equal(tctx, smap_1->share_name,
				 smap_2->share_name,
				 "smap share name strings differ");

	torture_assert_str_equal(tctx, smap_1->sc_share_comment,
				 smap_2->sc_share_comment,
				 "smap sc share comment strings differ");

	torture_assert(tctx, (smap_1->is_exposed == smap_2->is_exposed),
		       "smap exposure settings differ");

	return true;
}

static bool test_fsrvp_state_sc_compare(struct torture_context *tctx,
					struct fss_sc *sc_1,
					struct fss_sc *sc_2)
{
	struct fss_sc_smap *smap_1;
	struct fss_sc_smap *smap_2;
	bool ok;

	/* should have already been confirmed by the caller */
	torture_assert(tctx, GUID_equal(&sc_1->id, &sc_2->id),
		       "sc guids differ");

	torture_assert_str_equal(tctx, sc_1->volume_name, sc_2->volume_name,
				 "sc volume_name strings differ");

	/* may be null, assert_str_eq handles null ptrs safely */
	torture_assert_str_equal(tctx, sc_1->sc_path, sc_2->sc_path,
				 "sc path strings differ");

	torture_assert(tctx, difftime(sc_1->create_ts, sc_2->create_ts) == 0,
		       "sc create timestamps differ");

	torture_assert_int_equal(tctx, sc_1->smaps_count, sc_2->smaps_count,
				 "sc smaps counts differ");

	for (smap_1 = sc_1->smaps; smap_1; smap_1 = smap_1->next) {
		bool matched = false;
		for (smap_2 = sc_2->smaps; smap_2; smap_2 = smap_2->next) {
			if (strcmp(smap_1->sc_share_name,
				   smap_2->sc_share_name) == 0) {
				matched = true;
				ok = test_fsrvp_state_smap_compare(tctx,
								   smap_1,
								   smap_2);
				torture_assert(tctx, ok, "");
				break;
			}
		}
		torture_assert(tctx, matched, "no match for smap");
	}

	return true;
}

static bool test_fsrvp_state_sc_set_compare(struct torture_context *tctx,
					    struct fss_sc_set *sc_set_1,
					    struct fss_sc_set *sc_set_2)
{
	struct fss_sc *sc_1;
	struct fss_sc *sc_2;
	bool ok;

	/* should have already been confirmed by the caller */
	torture_assert(tctx, GUID_equal(&sc_set_1->id, &sc_set_2->id),
		       "sc_set guids differ");

	torture_assert_str_equal(tctx, sc_set_1->id_str, sc_set_2->id_str,
				 "sc_set guid strings differ");

	torture_assert_int_equal(tctx, sc_set_1->state, sc_set_2->state,
				 "sc_set state enums differ");

	torture_assert_int_equal(tctx, sc_set_1->context, sc_set_2->context,
				 "sc_set contexts differ");

	torture_assert_int_equal(tctx, sc_set_1->scs_count, sc_set_2->scs_count,
				 "sc_set sc counts differ");

	for (sc_1 = sc_set_1->scs; sc_1; sc_1 = sc_1->next) {
		bool matched = false;
		for (sc_2 = sc_set_2->scs; sc_2; sc_2 = sc_2->next) {
			if (GUID_equal(&sc_1->id, &sc_2->id)) {
				matched = true;
				ok = test_fsrvp_state_sc_compare(tctx, sc_1,
								       sc_2);
				torture_assert(tctx, ok, "");
				break;
			}
		}
		torture_assert(tctx, matched, "no match for sc");
	}
	return true;
}

static bool test_fsrvp_state_compare(struct torture_context *tctx,
				     struct fss_global *fss_1,
				     struct fss_global *fss_2)
{
	struct fss_sc_set *sc_set_1;
	struct fss_sc_set *sc_set_2;
	bool ok;

	torture_assert_int_equal(tctx, fss_1->sc_sets_count,
				 fss_2->sc_sets_count,
				 "sc_sets_count differ");

	for (sc_set_1 = fss_1->sc_sets; sc_set_1; sc_set_1 = sc_set_1->next) {
		bool matched = false;
		for (sc_set_2 = fss_2->sc_sets;
		     sc_set_2;
		     sc_set_2 = sc_set_2->next) {
			if (GUID_equal(&sc_set_1->id, &sc_set_2->id)) {
				matched = true;
				ok = test_fsrvp_state_sc_set_compare(tctx,
								     sc_set_1,
								     sc_set_2);
				torture_assert(tctx, ok, "");
				break;
			}
		}
		torture_assert(tctx, matched, "no match for sc_set");
	}

	return true;
}

/*
 * test a simple hierarchy of:
 *
 *       |
 *     sc_set
 *       |
 *      sc
 *        \
 *       smap
 */
static bool test_fsrvp_state_single(struct torture_context *tctx)
{
	NTSTATUS status;
	bool ok;
	struct fss_global fss_gs;
	struct fss_global fss_gr;
	struct fss_sc_set *sc_set;
	struct fss_sc *sc;
	struct fss_sc_smap *smap;
	char db_dir[] = "fsrvp_torture_XXXXXX";
	char *db_path = talloc_asprintf(NULL, "%s/%s",
					mkdtemp(db_dir), FSS_DB_NAME);

	memset(&fss_gs, 0, sizeof(fss_gs));
	fss_gs.mem_ctx = talloc_new(NULL);
	fss_gs.db_path = db_path;

	ok = test_fsrvp_state_sc_set(tctx, fss_gs.mem_ctx, &sc_set);
	torture_assert(tctx, ok, "failed to create sc set");

	/* use parent as mem ctx */
	ok = test_fsrvp_state_sc(tctx, sc_set, &sc);
	torture_assert(tctx, ok, "failed to create sc");

	ok = test_fsrvp_state_smap(tctx, sc, "base_share", "sc_share", &smap);
	torture_assert(tctx, ok, "failed to create smap");

	DLIST_ADD_END(fss_gs.sc_sets, sc_set);
	fss_gs.sc_sets_count++;
	DLIST_ADD_END(sc_set->scs, sc);
	sc_set->scs_count++;
	sc->sc_set = sc_set;
	DLIST_ADD_END(sc->smaps, smap);
	sc->smaps_count++;

	status = fss_state_store(fss_gs.mem_ctx, fss_gs.sc_sets,
				 fss_gs.sc_sets_count, fss_gs.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to store fss state");

	memset(&fss_gr, 0, sizeof(fss_gr));
	fss_gr.mem_ctx = talloc_new(NULL);
	fss_gr.db_path = db_path;

	status = fss_state_retrieve(fss_gr.mem_ctx, &fss_gr.sc_sets,
				    &fss_gr.sc_sets_count, fss_gr.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to retrieve fss state");

	ok = test_fsrvp_state_compare(tctx, &fss_gs, &fss_gr);
	torture_assert(tctx, ok,
		       "stored and retrieved state comparison failed");

	talloc_free(fss_gs.mem_ctx);
	talloc_free(fss_gr.mem_ctx);
	unlink(db_path);
	rmdir(db_dir);
	talloc_free(db_path);

	return true;
}

/*
 * test a complex hierarchy of:
 *
 *              /\
 *             /  \
 *     sc_set_a    sc_set_b
 *     /     \
 * sc_aa      sc_ab
 * |          |   \
 * smap_aaa   |    \
 *            |     \
 *       smap_aba   smap_abb
 */
static bool test_fsrvp_state_multi(struct torture_context *tctx)
{
	NTSTATUS status;
	bool ok;
	struct fss_global fss_gs;
	struct fss_global fss_gr;
	struct fss_sc_set *sc_set_a;
	struct fss_sc_set *sc_set_b;
	struct fss_sc *sc_aa;
	struct fss_sc *sc_ab;
	struct fss_sc_smap *smap_aaa;
	struct fss_sc_smap *smap_aba;
	struct fss_sc_smap *smap_abb;
	char db_dir[] = "fsrvp_torture_XXXXXX";
	char *db_path = talloc_asprintf(NULL, "%s/%s",
					mkdtemp(db_dir), FSS_DB_NAME);

	memset(&fss_gs, 0, sizeof(fss_gs));
	fss_gs.mem_ctx = talloc_new(NULL);
	fss_gs.db_path = db_path;

	ok = test_fsrvp_state_sc_set(tctx, fss_gs.mem_ctx, &sc_set_a);
	torture_assert(tctx, ok, "failed to create sc set");

	ok = test_fsrvp_state_sc_set(tctx, fss_gs.mem_ctx, &sc_set_b);
	torture_assert(tctx, ok, "failed to create sc set");

	/* use parent as mem ctx */
	ok = test_fsrvp_state_sc(tctx, sc_set_a, &sc_aa);
	torture_assert(tctx, ok, "failed to create sc");

	ok = test_fsrvp_state_sc(tctx, sc_set_a, &sc_ab);
	torture_assert(tctx, ok, "failed to create sc");

	ok = test_fsrvp_state_smap(tctx, sc_ab, "share_aa", "sc_share_aaa",
				   &smap_aaa);
	torture_assert(tctx, ok, "failed to create smap");

	ok = test_fsrvp_state_smap(tctx, sc_ab, "share_ab", "sc_share_aba",
				   &smap_aba);
	torture_assert(tctx, ok, "failed to create smap");

	ok = test_fsrvp_state_smap(tctx, sc_ab, "share_ab", "sc_share_abb",
				   &smap_abb);
	torture_assert(tctx, ok, "failed to create smap");

	DLIST_ADD_END(fss_gs.sc_sets, sc_set_a);
	fss_gs.sc_sets_count++;
	DLIST_ADD_END(fss_gs.sc_sets, sc_set_b);
	fss_gs.sc_sets_count++;

	DLIST_ADD_END(sc_set_a->scs, sc_aa);
	sc_set_a->scs_count++;
	sc_aa->sc_set = sc_set_a;
	DLIST_ADD_END(sc_set_a->scs, sc_ab);
	sc_set_a->scs_count++;
	sc_ab->sc_set = sc_set_a;

	DLIST_ADD_END(sc_aa->smaps, smap_aaa);
	sc_aa->smaps_count++;
	DLIST_ADD_END(sc_ab->smaps, smap_aba);
	sc_ab->smaps_count++;
	DLIST_ADD_END(sc_ab->smaps, smap_abb);
	sc_ab->smaps_count++;

	status = fss_state_store(fss_gs.mem_ctx, fss_gs.sc_sets,
				 fss_gs.sc_sets_count, fss_gs.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to store fss state");

	memset(&fss_gr, 0, sizeof(fss_gr));
	fss_gr.mem_ctx = talloc_new(NULL);
	fss_gr.db_path = db_path;
	status = fss_state_retrieve(fss_gr.mem_ctx, &fss_gr.sc_sets,
				    &fss_gr.sc_sets_count, fss_gr.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to retrieve fss state");

	ok = test_fsrvp_state_compare(tctx, &fss_gs, &fss_gr);
	torture_assert(tctx, ok,
		       "stored and retrieved state comparison failed");

	talloc_free(fss_gs.mem_ctx);
	talloc_free(fss_gr.mem_ctx);
	unlink(db_path);
	rmdir(db_dir);
	talloc_free(db_path);

	return true;
}

static bool test_fsrvp_state_none(struct torture_context *tctx)
{
	NTSTATUS status;
	struct fss_global fss_global;
	char db_dir[] = "fsrvp_torture_XXXXXX";
	char *db_path = talloc_asprintf(NULL, "%s/%s",
					mkdtemp(db_dir), FSS_DB_NAME);

	memset(&fss_global, 0, sizeof(fss_global));
	fss_global.mem_ctx = talloc_new(NULL);
	fss_global.db_path = db_path;

	status = fss_state_retrieve(fss_global.mem_ctx, &fss_global.sc_sets,
				    &fss_global.sc_sets_count,
				    fss_global.db_path);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to retrieve fss state");
	torture_assert_int_equal(tctx, fss_global.sc_sets_count, 0,
				 "sc_sets_count set when it should be zero");
	talloc_free(fss_global.mem_ctx);
	unlink(db_path);
	rmdir(db_dir);
	talloc_free(db_path);

	return true;
}

struct torture_suite *torture_local_fsrvp(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "fsrvp_state");

	/* dbwrap uses talloc_tos(), hence we need a stackframe :( */
	talloc_stackframe();

	torture_suite_add_simple_test(suite,
				      "state_empty",
				      test_fsrvp_state_empty);

	torture_suite_add_simple_test(suite,
				      "state_single",
				      test_fsrvp_state_single);

	torture_suite_add_simple_test(suite,
				      "state_multi",
				      test_fsrvp_state_multi);

	torture_suite_add_simple_test(suite,
				      "state_none",
				      test_fsrvp_state_none);

	return suite;
}
