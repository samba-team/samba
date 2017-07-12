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

#include "common/pidfile.h"

struct pidfile_context {
	const char *pidfile;
	int fd;
	pid_t pid;
};

static int pidfile_context_destructor(struct pidfile_context *pid_ctx);

int pidfile_create(TALLOC_CTX *mem_ctx, const char *pidfile,
		   struct pidfile_context **result)
{
	struct pidfile_context *pid_ctx;
	struct flock lck;
	char tmp[64];
	int fd, ret = 0;
	int len;
	ssize_t nwritten;

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

	fd = open(pidfile, O_CREAT|O_WRONLY|O_NONBLOCK, 0644);
	if (fd == -1) {
		ret = errno;
		goto fail;
	}

	if (! set_close_on_exec(fd)) {
		close(fd);
		ret = EIO;
		goto fail;
	}

	pid_ctx->fd = fd;

	lck = (struct flock) {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	do {
		ret = fcntl(fd, F_SETLK, &lck);
	} while ((ret == -1) && (errno == EINTR));

	if (ret != 0) {
		ret = errno;
		goto fail;
	}

	do {
		ret = ftruncate(fd, 0);
	} while ((ret == -1) && (errno == EINTR));

	if (ret == -1) {
		ret = EIO;
		goto fail_unlink;
	}

	len = snprintf(tmp, sizeof(tmp), "%u\n", pid_ctx->pid);
	if (len < 0) {
		ret = EIO;
		goto fail_unlink;
	}

	do {
		nwritten = write(fd, tmp, len);
	} while ((nwritten == -1) && (errno == EINTR));

	if ((nwritten == -1) || (nwritten != len)) {
		ret = EIO;
		goto fail_unlink;
	}

	talloc_set_destructor(pid_ctx, pidfile_context_destructor);

	*result = pid_ctx;
	return 0;

fail_unlink:
	unlink(pidfile);
	close(fd);

fail:
	talloc_free(pid_ctx);
	return ret;
}

static int pidfile_context_destructor(struct pidfile_context *pid_ctx)
{
	struct flock lck;
	int ret;

	if (getpid() != pid_ctx->pid) {
		return 0;
	}

	lck = (struct flock) {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
	};

	(void) unlink(pid_ctx->pidfile);

	do {
		ret = fcntl(pid_ctx->fd, F_SETLK, &lck);
	} while ((ret == -1) && (errno == EINTR));

	do {
		ret = close(pid_ctx->fd);
	} while ((ret == -1) && (errno == EINTR));

	return 0;
}
