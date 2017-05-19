/*
 * Unix SMB/CIFS implementation.
 * Test g_lock API
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
#include "system/filesys.h"
#include "g_lock.h"
#include "messages.h"
#include "lib/util/server_id.h"

static bool get_g_lock_ctx(TALLOC_CTX *mem_ctx,
			   struct tevent_context **ev,
			   struct messaging_context **msg,
			   struct g_lock_ctx **ctx)
{
	*ev = samba_tevent_context_init(mem_ctx);
	if (*ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}
	*msg = messaging_init(*ev, *ev);
	if (*msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		TALLOC_FREE(*ev);
		return false;
	}
	*ctx = g_lock_ctx_init(*ev, *msg);
	if (*ctx == NULL) {
		fprintf(stderr, "g_lock_ctx_init failed\n");
		TALLOC_FREE(*msg);
		TALLOC_FREE(*ev);
		return false;
	}

	return true;
}

bool run_g_lock1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock1";
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_READ,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_READ,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WAS_LOCKED)) {
		fprintf(stderr, "Double lock got %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, lockname);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_unlock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, lockname);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		fprintf(stderr, "g_lock_unlock returned: %s\n",
			nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

struct lock2_parser_state {
	uint8_t *rdata;
	bool ok;
};

static void lock2_parser(const struct g_lock_rec *locks,
			 size_t num_locks,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock2_parser_state *state = private_data;

	if (datalen != sizeof(uint8_t)) {
		return;
	}
	*state->rdata = *data;
	state->ok = true;
}

/*
 * Test g_lock_write_data
 */

bool run_g_lock2(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock2";
	uint8_t data = 42;
	uint8_t rdata;
	struct lock2_parser_state state = { .rdata = &rdata };
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	status = g_lock_write_data(ctx, lockname, &data, sizeof(data));
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_LOCKED)) {
		fprintf(stderr, "unlocked g_lock_write_data returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_write_data(ctx, lockname, &data, sizeof(data));
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_write_data failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, lockname);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_unlock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_dump(ctx, lockname, lock2_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_dump failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (!state.ok) {
		fprintf(stderr, "Could not parse data\n");
		goto fail;
	}
	if (rdata != data) {
		fprintf(stderr, "Returned %"PRIu8", expected %"PRIu8"\n",
			rdata, data);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

struct lock3_parser_state {
	struct server_id self;
	enum g_lock_type lock_type;
	bool ok;
};

static void lock3_parser(const struct g_lock_rec *locks,
			 size_t num_locks,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock3_parser_state *state = private_data;

	if (datalen != 0) {
		fprintf(stderr, "datalen=%zu\n", datalen);
		return;
	}
	if (num_locks != 1) {
		fprintf(stderr, "num_locks=%zu\n", num_locks);
		return;
	}
	if (locks[0].lock_type != state->lock_type) {
		fprintf(stderr, "found type %d, expected %d\n",
			(int)locks[0].lock_type, (int)state->lock_type);
		return;
	}
	if (!server_id_equal(&locks[0].pid, &state->self)) {
		struct server_id_buf tmp1, tmp2;
		fprintf(stderr, "found pid %s, expected %s\n",
			server_id_str_buf(locks[0].pid, &tmp1),
			server_id_str_buf(state->self, &tmp2));
		return;
	}

	state->ok = true;
}

/*
 * Test lock upgrade/downgrade
 */

bool run_g_lock3(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock3";
	struct lock3_parser_state state;
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	state.self = messaging_server_id(msg);

	status = g_lock_lock(ctx, lockname, G_LOCK_READ,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_READ,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WAS_LOCKED)) {
		fprintf(stderr, "g_lock_lock returned %s, expected %s\n",
			nt_errstr(status), nt_errstr(NT_STATUS_WAS_LOCKED));
		goto fail;
	}

	state.lock_type = G_LOCK_READ;
	state.ok = false;

	status = g_lock_dump(ctx, lockname, lock3_parser, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr, "g_lock_dump returned %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!state.ok) {
		goto fail;
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	state.lock_type = G_LOCK_WRITE;
	state.ok = false;

	status = g_lock_dump(ctx, lockname, lock3_parser, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr, "g_lock_dump returned %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!state.ok) {
		goto fail;
	}


	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}
