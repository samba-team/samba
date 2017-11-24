/*
   Create and remove pidfile

   Copyright (C) Amitay Isaacs  2016

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
#include "system/filesys.h"

#include <talloc.h>

#include "lib/util/blocking.h"
#include "lib/util/pidfile.h"

#include "common/pidfile.h"

struct pidfile_context {
	const char *pidfile;
	int fd;
	pid_t pid;
};

static int pidfile_context_destructor(struct pidfile_context *pid_ctx);

int pidfile_context_create(TALLOC_CTX *mem_ctx, const char *pidfile,
			   struct pidfile_context **result)
{
	struct pidfile_context *pid_ctx;
	int fd, ret = 0;

	pid_ctx = talloc_zero(mem_ctx, struct pidfile_context);
	if (pid_ctx == NULL) {
		return ENOMEM;
	}

	pid_ctx->pidfile = talloc_strdup(pid_ctx, pidfile);
	if (pid_ctx->pidfile == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	pid_ctx->pid = getpid();

	ret = pidfile_path_create(pid_ctx->pidfile, &fd);
	if (ret != 0) {
		return ret;
	}

	pid_ctx->fd = fd;

	talloc_set_destructor(pid_ctx, pidfile_context_destructor);

	*result = pid_ctx;
	return 0;

fail:
	talloc_free(pid_ctx);
	return ret;
}

static int pidfile_context_destructor(struct pidfile_context *pid_ctx)
{
	if (getpid() != pid_ctx->pid) {
		return 0;
	}

	(void) unlink(pid_ctx->pidfile);

	pidfile_fd_close(pid_ctx->fd);

	return 0;
}
