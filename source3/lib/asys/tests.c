/*
 * Test async syscalls
 * Copyright (C) Volker Lendecke 2012
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

#include "asys.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, const char *argv[])
{
	struct asys_context *ctx;
	int i, fd, ret;

	int *buf;

	int ntasks = 10;

	ret = asys_context_init(&ctx, 0);
	if (ret != 0) {
		perror("asys_context_create failed");
		return 1;
	}

	fd = open("asys_testfile", O_CREAT|O_RDWR, 0644);
	if (fd == -1) {
		perror("open failed");
		return 1;
	}

	buf = calloc(ntasks, sizeof(int));
	if (buf == NULL) {
		perror("calloc failed");
		return 1;
	}

	for (i=0; i<ntasks; i++) {
		buf[i] = i;
	}

	for (i=0; i<ntasks; i++) {
		ret = asys_pwrite(ctx, fd, &buf[i], sizeof(int),
				  i * sizeof(int), &buf[i]);
		if (ret != 0) {
			errno = ret;
			perror("asys_pwrite failed");
			return 1;
		}
	}

	for (i=0; i<ntasks; i++) {
		void *priv;
		ssize_t retval;
		int err;
		int *pidx;

		ret = asys_result(ctx, &retval, &err, &priv);
		if (ret == -1) {
			errno = ret;
			perror("asys_result failed");
			return 1;
		}
		pidx = (int *)priv;

		printf("%d returned %d\n", *pidx, (int)retval);
	}

	ret = asys_context_destroy(ctx);
	if (ret != 0) {
		perror("asys_context_delete failed");
		return 1;
	}

	free(buf);

	return 0;
}
