/*
 * Unix SMB/CIFS implementation.
 *
 * testing of some tevent_req aspects
 *
 * Copyright (C) Volker Lendecke 2018
 *
 *   ** NOTE! The following LGPL license applies to the tevent
 *   ** library. This does NOT imply that all of Samba is released
 *   ** under the LGPL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "tevent.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_req_profile.h"
#include "lib/util/time_basic.h"

struct tevent_req_create_state {
	uint8_t val;
};

static bool test_tevent_req_create(struct torture_context *tctx,
				   const void *test_data)
{
	struct tevent_req *req;
	struct tevent_req_create_state *state;

	req = tevent_req_create(tctx, &state,
				struct tevent_req_create_state);
	torture_assert_not_null(tctx, req, "tevent_req_create failed\n");
	torture_assert_int_equal(tctx, state->val, 0, "state not initialized\n");

	TALLOC_FREE(req);

	return true;
}

struct profile1_state {
	uint8_t dummy;
};

static bool test_tevent_req_profile1(struct torture_context *tctx,
				     const void *test_data)
{
	struct tevent_req *req;
	struct profile1_state *state;
	const struct tevent_req_profile *p1;
	struct tevent_req_profile *p2;
	struct timeval start, stop;
	bool ok;
	int cmp;

	req = tevent_req_create(tctx, &state, struct profile1_state);
	torture_assert_not_null(tctx, req, "tevent_req_create failed\n");

	p1 = tevent_req_get_profile(req);
	torture_assert(tctx, p1 == NULL, "profile not initialized to NULL\n");

	ok = tevent_req_set_profile(req);
	torture_assert(tctx, ok, "set_profile failed\n");

	tevent_req_done(req);

	p2 = tevent_req_move_profile(req, tctx);
	torture_assert_not_null(tctx, p2, "get_profile failed\n");

	/* Demonstrate sure "p2" outlives req */
	TALLOC_FREE(req);

	tevent_req_profile_get_start(p2, NULL, &start);
	tevent_req_profile_get_stop(p2, NULL, &stop);

	cmp = tevent_timeval_compare(&start, &stop);
	torture_assert(tctx, cmp <= 0, "stop before start\n");

	TALLOC_FREE(p2);

	return true;
}

struct profile2_state {
	uint8_t dummy;
};

static void profile2_done(struct tevent_req *subreq);

static struct tevent_req *profile2_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev)
{
	struct tevent_req *req, *subreq;
	struct profile2_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct profile2_state);
	if (req == NULL) {
		return NULL;
	}

	ok = tevent_req_set_profile(req);
	if (!ok) {
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(
		state,
		ev,
		tevent_timeval_current_ofs(0, 1));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, profile2_done, req);

	return req;
}

static void profile2_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}
	tevent_req_done(req);
}

static int profile2_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx,
			  struct tevent_req_profile **profile)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	*profile = tevent_req_move_profile(req, mem_ctx);

	return 0;
}

static bool test_tevent_req_profile2(struct torture_context *tctx,
				     const void *test_data)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	struct tevent_req_profile *p1 = NULL;
	struct tevent_req_profile *p2 = NULL;
	const char *str1, *str2;
	struct timeval tv1, tv2;
	pid_t pid1, pid2;
	enum tevent_req_state state1, state2;
	uint64_t err1, err2;
	char *printstring;
	ssize_t pack_len;
	int err;
	bool ok;

	ev = samba_tevent_context_init(tctx);
	torture_assert_not_null(tctx, ev, "samba_tevent_context_init failed\n");

	req = profile2_send(tctx, ev);
	torture_assert_not_null(tctx, req, "profile2_send failed\n");

	ok = tevent_req_poll_unix(req, ev, &err);
	torture_assert(tctx, ok, "tevent_req_poll_unix failed\n");

	err = profile2_recv(req, tctx, &p1);
	torture_assert_int_equal(tctx, err, 0, "profile2_recv failed\n");

	TALLOC_FREE(req);
	TALLOC_FREE(ev);

	printstring = tevent_req_profile_string(tctx, p1, 0, UINT_MAX);
	torture_assert_not_null(
		tctx,
		printstring,
		"tevent_req_profile_string failed\n");
	printf("%s\n", printstring);

	pack_len = tevent_req_profile_pack(p1, NULL, 0);
	torture_assert(tctx, pack_len>0, "profile_pack failed\n");

	{
		uint8_t buf[pack_len];
		ssize_t unpack_len;

		tevent_req_profile_pack(p1, buf, sizeof(buf));
		dump_data(10, buf, sizeof(buf));

		unpack_len = tevent_req_profile_unpack(
			buf,
			pack_len,
			tctx,
			&p2);
		torture_assert_int_equal(tctx,
					 pack_len,
					 unpack_len,
					 "profile_unpack failed\n");
	}

	printstring = tevent_req_profile_string(tctx, p2, 0, UINT_MAX);
	torture_assert_not_null(
		tctx,
		printstring,
		"tevent_req_profile_string failed\n");
	printf("%s\n", printstring);

	tevent_req_profile_get_name(p1, &str1);
	tevent_req_profile_get_name(p2, &str2);
	torture_assert_str_equal(tctx, str1, str2, "names differ\n");

	tevent_req_profile_get_start(p1, &str1, &tv1);
	tevent_req_profile_get_start(p2, &str2, &tv2);
	torture_assert_str_equal(tctx, str1, str2, "start strings differ\n");
	torture_assert(tctx,
		       tevent_timeval_compare(&tv1, &tv2) == 0,
		       "start times differ\n");

	tevent_req_profile_get_stop(p1, &str1, &tv1);
	tevent_req_profile_get_stop(p2, &str2, &tv2);
	torture_assert_str_equal(tctx, str1, str2, "stop strings differ\n");
	torture_assert(tctx,
		       tevent_timeval_compare(&tv1, &tv2) == 0,
		       "stop times differ\n");

	tevent_req_profile_get_status(p1, &pid1, &state1, &err1);
	tevent_req_profile_get_status(p2, &pid2, &state2, &err2);
	torture_assert_int_equal(tctx, pid1, pid2, "pids differ\n");
	torture_assert_int_equal(tctx, state1, state2, "states differ\n");
	torture_assert_int_equal(tctx, err1, err2, "user errors differ\n");

	str1 = tevent_req_profile_string(p1, p1, 0, UINT_MAX);
	torture_assert_not_null(tctx, str1, "profile_string failed\n");
	str2 = tevent_req_profile_string(p2, p2, 0, UINT_MAX);
	torture_assert_not_null(tctx, str2, "profile_string failed\n");

	torture_assert_str_equal(tctx, str1, str2, "result strings differ\n");

	TALLOC_FREE(p1);
	TALLOC_FREE(p2);

	return true;
}

struct torture_suite *torture_local_tevent_req(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;

	suite = torture_suite_create(mem_ctx, "tevent_req");

	torture_suite_add_simple_tcase_const(
		suite,
		"create",
		test_tevent_req_create,
		NULL);
	torture_suite_add_simple_tcase_const(
		suite,
		"profile1",
		test_tevent_req_profile1,
		NULL);
	torture_suite_add_simple_tcase_const(
		suite,
		"profile2",
		test_tevent_req_profile2,
		NULL);

	return suite;
}
