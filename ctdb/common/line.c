/*
   Line based I/O over fds

   Copyright (C) Amitay Isaacs  2018

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

#include <talloc.h>

#include "lib/util/sys_rw.h"

#include "common/line.h"

struct line_read_state {
	line_process_fn_t callback;
	void *private_data;
	char *buf;
	size_t hint, len, offset;
	int num_lines;
};

static bool line_read_one(char *buf, size_t start, size_t len, size_t *pos)
{
	size_t i;

	for (i=start; i<len; i++) {
		if (buf[i] == '\n' || buf[i] == '\0') {
			*pos = i;
			return true;
		}
	}

	return false;
}

static int line_read_process(struct line_read_state *state)
{
	size_t start = 0;
	size_t pos = 0;

	while (1) {
		int ret;
		bool ok;

		ok = line_read_one(state->buf, start, state->offset, &pos);
		if (! ok) {
			break;
		}

		state->buf[pos] = '\0';
		state->num_lines += 1;

		ret = state->callback(state->buf + start, state->private_data);
		if (ret != 0) {
			return ret;
		}

		start = pos+1;
	}

	if (pos > 0) {
		if (pos+1 < state->offset) {
			memmove(state->buf,
				state->buf + pos+1,
				state->offset - (pos+1));
		}
		state->offset -= (pos+1);
	}

	return 0;
}

int line_read(int fd,
	      size_t length,
	      TALLOC_CTX *mem_ctx,
	      line_process_fn_t callback,
	      void *private_data,
	      int *num_lines)
{
	struct line_read_state state;

	if (length < 32) {
		length = 32;
	}

	state = (struct line_read_state) {
		.callback = callback,
		.private_data = private_data,
		.hint = length,
	};

	while (1) {
		ssize_t n;
		int ret;

		if (state.offset == state.len) {
			state.len += state.hint;
			state.buf = talloc_realloc_size(mem_ctx,
							state.buf,
							state.len);
			if (state.buf == NULL) {
				return ENOMEM;
			}
		}

		n = sys_read(fd,
			     state.buf + state.offset,
			     state.len - state.offset);
		if (n < 0) {
			return errno;
		}
		if (n == 0) {
			break;
		}

		state.offset += n;

		ret = line_read_process(&state);
		if (ret != 0) {
			if (num_lines != NULL) {
				*num_lines = state.num_lines;
			}
			return ret;
		}
	}

	if (num_lines != NULL) {
		*num_lines = state.num_lines;
	}
	return 0;
}
