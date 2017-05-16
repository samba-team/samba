/*
   Unix SMB/CIFS implementation.

   run a child command

   Copyright (C) Andrew Tridgell 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <tevent.h>

struct samba_runcmd_state {
	int stdout_log_level;
	int stderr_log_level;
	struct tevent_fd *fde_stdout;
	struct tevent_fd *fde_stderr;
	struct tevent_fd *fde_status;
	int fd_stdin, fd_stdout, fd_stderr, fd_status;
	char *arg0;
	pid_t pid;
	struct tfork *tfork;
	char buf[1024];
	uint16_t buf_used;
};
