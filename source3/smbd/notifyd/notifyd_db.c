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
#include "lib/util/server_id_db.h"
#include "notifyd_private.h"
#include "notifyd_db.h"

struct notifyd_parse_db_state {
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data);
	void *private_data;
};

static bool notifyd_parse_db_parser(TDB_DATA key, TDB_DATA value,
				    void *private_data)
{
	struct notifyd_parse_db_state *state = private_data;
	char path[key.dsize+1];
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;
	bool ok;

	memcpy(path, key.dptr, key.dsize);
	path[key.dsize] = 0;

	ok = notifyd_parse_entry(value.dptr,
				 value.dsize,
				 NULL,
				 &instances,
				 &num_instances);
	if (!ok) {
		DBG_DEBUG("Could not parse entry for path %s\n", path);
		return true;
	}

	for (i=0; i<num_instances; i++) {
		ok = state->fn(path, instances[i].client,
			       &instances[i].instance,
			       state->private_data);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static NTSTATUS notifyd_parse_db(
	const uint8_t *buf,
	size_t buflen,
	uint64_t *log_index,
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data),
	void *private_data)
{
	struct notifyd_parse_db_state state = {
		.fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	if (buflen < 8) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	*log_index = BVAL(buf, 0);

	buf += 8;
	buflen -= 8;

	status = dbwrap_parse_marshall_buf(
		buf, buflen, notifyd_parse_db_parser, &state);
	return status;
}

NTSTATUS notify_walk(struct messaging_context *msg_ctx,
		     bool (*fn)(const char *path, struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data)
{
	struct server_id_db *names_db = NULL;
	struct server_id notifyd = { .pid = 0, };
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	struct messaging_rec *rec = NULL;
	uint64_t log_idx;
	NTSTATUS status;
	int ret;
	bool ok;

	names_db = messaging_names_db(msg_ctx);
	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		DBG_WARNING("No notify daemon around\n");
		return NT_STATUS_SERVER_UNAVAILABLE;
	}

	ev = samba_tevent_context_init(msg_ctx);
	if (ev == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req = messaging_read_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY_DB);
	if (req == NULL) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_set_endtime(req, ev, timeval_current_ofs(10, 0));
	if (!ok) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	status = messaging_send_buf(
		msg_ctx, notifyd, MSG_SMB_NOTIFY_GET_DB, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_send_buf failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(ev);
		return status;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_DEBUG("tevent_req_poll failed\n");
		TALLOC_FREE(ev);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = messaging_read_recv(req, ev, &rec);
	if (ret != 0) {
		DBG_DEBUG("messaging_read_recv failed: %s\n",
			  strerror(ret));
		TALLOC_FREE(ev);
		return map_nt_error_from_unix(ret);
	}

	status = notifyd_parse_db(
		rec->buf.data, rec->buf.length, &log_idx, fn, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("notifyd_parse_db failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(ev);
		return status;
	}

	TALLOC_FREE(ev);
	return NT_STATUS_OK;
}
