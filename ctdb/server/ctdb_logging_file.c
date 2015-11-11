/*
   ctdb logging code

   Copyright (C) Andrew Tridgell  2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>

#include "lib/util/debug.h"
#include "lib/util/time_basic.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system.h"

#define CTDB_LOG_FILE_PREFIX "file"

struct file_state {
	int fd;
};

/*
  log file logging function
 */
static void ctdb_log_to_file(void *private_ptr, int dbglevel, const char *s)
{
	struct file_state *state = talloc_get_type(
		private_ptr, struct file_state);
	struct timeval tv;
	struct timeval_buf tvbuf;
	char *s2 = NULL;
	int ret;

	GetTimeOfDay(&tv);
	timeval_str_buf(&tv, false, true, &tvbuf);

	ret = asprintf(&s2, "%s [%s%5u]: %s\n",
		       tvbuf.buf,
		       debug_extra, (unsigned)getpid(), s);
	if (ret == -1) {
		const char *errstr = "asprintf failed\n";
		sys_write(state->fd, errstr, strlen(errstr));
		return;
	}
	if (s2) {
		sys_write(state->fd, s2, strlen(s2));
		free(s2);
	}
}

static int file_state_destructor(struct file_state *state)
{
       close(state->fd);
       state->fd = -1;
       return 0;
}

static int ctdb_log_setup_file(TALLOC_CTX *mem_ctx,
			       const char *logging,
			       const char *app_name)
{
	struct file_state *state;
	const char *logfile;
	size_t l;

	l = strlen(CTDB_LOG_FILE_PREFIX);
	if (logging[l] != ':') {
		return EINVAL;
	}
	logfile = &logging[0] + l + 1;

	state = talloc_zero(mem_ctx, struct file_state);
	if (state == NULL) {
		return ENOMEM;
	}

	if (logfile == NULL || strcmp(logfile, "-") == 0) {
		int ret;

		state->fd = 1;
		/* also catch stderr of subcommands to stdout */
		ret = dup2(1, 2);
		if (ret == -1) {
			return errno;
		}
	} else {
		state->fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0666);
		if (state->fd == -1) {
			return errno;
		}
	}

	talloc_set_destructor(state, file_state_destructor);
	debug_set_callback(state, ctdb_log_to_file);

	return 0;
}

void ctdb_log_init_file(void)
{
	ctdb_log_register_backend(CTDB_LOG_FILE_PREFIX, ctdb_log_setup_file);
}
