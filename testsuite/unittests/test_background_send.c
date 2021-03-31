/*
 * Unix SMB/CIFS implementation.
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
#include <assert.h>
#include "source3/lib/background.h"
#include "source3/include/messages.h"
#include "lib/util/talloc_stack.h"
#include "source3/param/loadparm.h"
#include "dynconfig/dynconfig.h"

static int bg_trigger(void *private_data)
{
	return 1;
}

static void test_background_send(void)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req = NULL;
	uint32_t ping_msg = MSG_PING;

	ev = tevent_context_init(frame);
	assert(ev != NULL);

	msg_ctx = messaging_init(frame, ev);
	assert(msg_ctx != NULL);

	req = background_job_send(
		frame, ev, msg_ctx, &ping_msg, 1, 0, bg_trigger, NULL);
	assert(req != NULL);

	/*
	 * Here's the core of this test: TALLOC_FREE msg_ctx before
	 * req. This happens if you use background_job_send() smbd and
	 * don't manually TALLOC_FREE req before exit_server()
	 */
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(req);

	TALLOC_FREE(frame);
}

int main(int argc, const char *argv[])
{
	const char testname[] = "test_background_send";
	bool ok;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <configfile>\n", argv[0]);
		return 1;
	}

	printf("test: %s\n", testname);

	ok = lp_load_initial_only(argv[1]);
	if (!ok) {
		fprintf(stderr, "lp_load_initial_only(%s) failed\n", argv[1]);
		return 1;
	}

	test_background_send();	/* crashes on failure */

	printf("success: %s\n", testname);
	return 0;
}
