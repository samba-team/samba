/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2014
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

#include "replace.h"
#include "notifyd.h"
#include "lib/messages_ctdb.h"
#include <tevent.h>
#include "lib/util/tevent_unix.h"

int main(int argc, const char *argv[])
{
	TALLOC_CTX *frame;
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct tevent_req *req;
	int err, ret;
	bool ok;

	talloc_enable_leak_report_full();

	frame = talloc_stackframe();

	setup_logging("notifyd", DEBUG_DEFAULT_STDOUT);
	lp_set_cmdline("log level", "10");

	ok = lp_load_initial_only(get_dyn_CONFIGFILE());
	if (!ok) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n",
			get_dyn_CONFIGFILE());
		return 1;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		fprintf(stderr, "samba_tevent_context_init failed\n");
		return 1;
	}

	msg = messaging_init(ev, ev);
	if (msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		return 1;
	}

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n",
			get_dyn_CONFIGFILE());
		return 1;
	}

	req = notifyd_send(ev, ev, msg, messaging_ctdb_connection(),
			   NULL, NULL);
	if (req == NULL) {
		fprintf(stderr, "notifyd_send failed\n");
		return 1;
	}

	ok = tevent_req_poll_unix(req, ev, &err);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll_unix failed: %s\n",
			strerror(err));
		return 1;
	}

	ret = notifyd_recv(req);

	printf("notifyd_recv returned %d (%s)\n", ret,
	       ret ? strerror(ret) : "ok");

	TALLOC_FREE(frame);

	return 0;
}
