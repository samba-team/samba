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
#include "fcn_wait.h"
#include "notifyd.h"
#include "notifyd_db.h"
#include "messages.h"
#include "lib/util/server_id.h"
#include "lib/util/server_id_db.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/torture/torture.h"
#include "torture/local/proto.h"
#include "lib/param/loadparm.h"
#include "source3/param/loadparm.h"
#include "source4/torture/smbtorture.h"

struct fcn_test_state {
	struct tevent_req *fcn_req;
	bool got_trigger;
};

static void fcn_test_done(struct tevent_req *subreq);

static struct tevent_req *fcn_test_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	struct server_id notifyd,
	const char *fcn_path,
	uint32_t fcn_filter,
	uint32_t fcn_subdir_filter,
	const char *trigger_path,
	uint32_t trigger_action,
	uint32_t trigger_filter)
{
	struct tevent_req *req = NULL;
	struct fcn_test_state *state = NULL;
	struct notify_trigger_msg msg;
	struct iovec iov[2];
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct fcn_test_state);
	if (req == NULL) {
		return NULL;
	}

	state->fcn_req = fcn_wait_send(
		state,
		ev,
		msg_ctx,
		notifyd,
		fcn_path,
		fcn_filter,
		fcn_subdir_filter);
	if (tevent_req_nomem(state->fcn_req, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->fcn_req, fcn_test_done, req);

	msg = (struct notify_trigger_msg) {
		.when = timespec_current(),
		.action = trigger_action,
		.filter = trigger_filter,
	};
	iov[0] = (struct iovec) {
		.iov_base = &msg,
		.iov_len = offsetof(struct notify_trigger_msg, path),
	};
	iov[1] = (struct iovec) {
		.iov_base = discard_const_p(char, trigger_path),
		.iov_len = strlen(trigger_path)+1,
	};

	status = messaging_send_iov(
		msg_ctx,
		notifyd,
		MSG_SMB_NOTIFY_TRIGGER,
		iov,
		ARRAY_SIZE(iov),
		NULL,
		0);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void fcn_test_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fcn_test_state *state = tevent_req_data(
		req, struct fcn_test_state);
	NTSTATUS status;
	bool ok;

	SMB_ASSERT(subreq == state->fcn_req);

	status = fcn_wait_recv(subreq, NULL, NULL, NULL, NULL);

	if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
		TALLOC_FREE(subreq);
		state->fcn_req = NULL;
		tevent_req_done(req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		TALLOC_FREE(subreq);
		state->fcn_req = NULL;
		return;
	}

	state->got_trigger = true;

	ok = tevent_req_cancel(subreq);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
}

static NTSTATUS fcn_test_recv(struct tevent_req *req, bool *got_trigger)
{
	struct fcn_test_state *state = tevent_req_data(
		req, struct fcn_test_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (got_trigger != NULL) {
		*got_trigger = state->got_trigger;
	}

	return NT_STATUS_OK;
}

static NTSTATUS fcn_test(
	struct messaging_context *msg_ctx,
	struct server_id notifyd,
	const char *fcn_path,
	uint32_t fcn_filter,
	uint32_t fcn_subdir_filter,
	const char *trigger_path,
	uint32_t trigger_action,
	uint32_t trigger_filter,
	bool *got_trigger)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(msg_ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = fcn_test_send(
		ev,
		ev,
		msg_ctx,
		notifyd,
		fcn_path,
		fcn_filter,
		fcn_subdir_filter,
		trigger_path,
		trigger_action,
		trigger_filter);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = fcn_test_recv(req, got_trigger);
fail:
	TALLOC_FREE(ev);
	return status;
}

static bool test_notifyd_trigger1(struct torture_context *tctx)
{
	struct messaging_context *msg_ctx = NULL;
	struct server_id_db *names = NULL;
	struct server_id notifyd;
	NTSTATUS status;
	bool got_trigger = false;
	bool ok;

	/*
	 * Basic filechangenotify test: Wait for /home, trigger on
	 * /home/foo, check an event was received
	 */

	lp_load_global(tctx->lp_ctx->szConfigFile);

	msg_ctx = messaging_init(tctx, tctx->ev);
	torture_assert_not_null(tctx, msg_ctx, "messaging_init");

	names = messaging_names_db(msg_ctx);
	ok = server_id_db_lookup_one(names, "notify-daemon", &notifyd);
	torture_assert(tctx, ok, "server_id_db_lookup_one");

	status = fcn_test(
		msg_ctx,
		notifyd,
		"/home",
		UINT32_MAX,
		UINT32_MAX,
		"/home/foo",
		UINT32_MAX,
		UINT32_MAX,
		&got_trigger);
	torture_assert_ntstatus_ok(tctx, status, "fcn_test");
	torture_assert(tctx, got_trigger, "got_trigger");

	return true;
}

struct notifyd_have_state {
	struct server_id self;
	bool found;
};

static bool notifyd_have_fn(
	const char *path,
	struct server_id server,
	const struct notify_instance *instance,
	void *private_data)
{
	struct notifyd_have_state *state = private_data;
	state->found |= server_id_equal(&server, &state->self);
	return true;
}

static bool notifyd_have_self(struct messaging_context *msg_ctx)
{
	struct notifyd_have_state state = {
		.self = messaging_server_id(msg_ctx),
	};
	NTSTATUS status;

	status = notify_walk(msg_ctx, notifyd_have_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	return state.found;
}

static bool test_notifyd_dbtest1(struct torture_context *tctx)
{
	struct tevent_context *ev = tctx->ev;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req = NULL;
	struct server_id_db *names = NULL;
	struct server_id notifyd;
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure fcn_wait_send adds us to the notifyd internal
	 * database and that cancelling the fcn request removes us
	 * again.
	 */

	lp_load_global(tctx->lp_ctx->szConfigFile);

	msg_ctx = messaging_init(tctx, ev);
	torture_assert_not_null(tctx, msg_ctx, "messaging_init");

	names = messaging_names_db(msg_ctx);
	ok = server_id_db_lookup_one(names, "notify-daemon", &notifyd);
	torture_assert(tctx, ok, "server_id_db_lookup_one");

	req = fcn_wait_send(
		msg_ctx, ev, msg_ctx, notifyd, "/x", UINT32_MAX, UINT32_MAX);
	torture_assert_not_null(tctx, req, "fcn_wait_send");

	ok = notifyd_have_self(msg_ctx);
	torture_assert(tctx, ok, "notifyd_have_self");

	ok = tevent_req_cancel(req);
	torture_assert(tctx, ok, "tevent_req_cancel");

	ok = tevent_req_poll(req, ev);
	torture_assert(tctx, ok, "tevent_req_poll");

	status = fcn_wait_recv(req, NULL, NULL, NULL, NULL);
	torture_assert_ntstatus_equal(
		tctx, status, NT_STATUS_CANCELLED, "fcn_wait_recv");
	TALLOC_FREE(req);

	ok = notifyd_have_self(msg_ctx);
	torture_assert(tctx, !ok, "tevent_req_poll");
	TALLOC_FREE(msg_ctx);

	return true;
}

NTSTATUS torture_notifyd_init(TALLOC_CTX *mem_ctx);
NTSTATUS torture_notifyd_init(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = NULL;
	struct torture_tcase *tcase = NULL;
	bool ok;

	suite = torture_suite_create(mem_ctx, "notifyd");
	if (suite == NULL) {
		goto fail;
	}

	tcase = torture_suite_add_simple_test(
		suite, "trigger1", test_notifyd_trigger1);
	if (tcase == NULL) {
		goto fail;
	}

	tcase = torture_suite_add_simple_test(
		suite, "dbtest1", test_notifyd_dbtest1);
	if (tcase == NULL) {
		goto fail;
	}
	suite->description = "notifyd unit tests";

	ok = torture_register_suite(mem_ctx, suite);
	if (!ok) {
		goto fail;
	}
	return NT_STATUS_OK;
fail:
	TALLOC_FREE(suite);
	return NT_STATUS_NO_MEMORY;
}
