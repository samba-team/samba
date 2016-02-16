/*
 * Unix SMB/CIFS implementation.
 *  Samba system utilities
 * Copyright (C) Jeremy Allison  2000
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
#include "system/wait.h"
#include "system/filesys.h"
#include <talloc.h>
#include "lib/sys_popen.h"
#include "lib/util/debug.h"

/**************************************************************************
 Extract a command into an arg list.
****************************************************************************/

static char **extract_args(TALLOC_CTX *mem_ctx, const char *command)
{
	char *trunc_cmd;
	char *saveptr;
	char *ptr;
	int argcl;
	char **argl = NULL;
	int i;

	if (!(trunc_cmd = talloc_strdup(mem_ctx, command))) {
		DEBUG(0, ("talloc failed\n"));
		goto nomem;
	}

	if(!(ptr = strtok_r(trunc_cmd, " \t", &saveptr))) {
		TALLOC_FREE(trunc_cmd);
		errno = EINVAL;
		return NULL;
	}

	/*
	 * Count the args.
	 */

	for( argcl = 1; ptr; ptr = strtok_r(NULL, " \t", &saveptr))
		argcl++;

	TALLOC_FREE(trunc_cmd);

	if (!(argl = talloc_array(mem_ctx, char *, argcl + 1))) {
		goto nomem;
	}

	/*
	 * Now do the extraction.
	 */

	if (!(trunc_cmd = talloc_strdup(mem_ctx, command))) {
		goto nomem;
	}

	ptr = strtok_r(trunc_cmd, " \t", &saveptr);
	i = 0;

	if (!(argl[i++] = talloc_strdup(argl, ptr))) {
		goto nomem;
	}

	while((ptr = strtok_r(NULL, " \t", &saveptr)) != NULL) {

		if (!(argl[i++] = talloc_strdup(argl, ptr))) {
			goto nomem;
		}
	}

	argl[i++] = NULL;
	TALLOC_FREE(trunc_cmd);
	return argl;

 nomem:
	DEBUG(0, ("talloc failed\n"));
	TALLOC_FREE(trunc_cmd);
	TALLOC_FREE(argl);
	errno = ENOMEM;
	return NULL;
}

/**************************************************************************
 Wrapper for popen. Safer as it doesn't search a path.
 Modified from the glibc sources.
 modified by tridge to return a file descriptor. We must kick our FILE* habit
****************************************************************************/

typedef struct _popen_list
{
	int fd;
	pid_t child_pid;
	struct _popen_list *next;
} popen_list;

static popen_list *popen_chain;

int sys_popen(const char *command)
{
	int parent_end, child_end;
	int pipe_fds[2];
	popen_list *entry = NULL;
	char **argl = NULL;
	int ret;

	if (!*command) {
		errno = EINVAL;
		return -1;
	}

	ret = pipe(pipe_fds);
	if (ret < 0) {
		DEBUG(0, ("sys_popen: error opening pipe: %s\n",
			  strerror(errno)));
		return -1;
	}

	parent_end = pipe_fds[0];
	child_end = pipe_fds[1];

	entry = talloc_zero(NULL, popen_list);
	if (entry == NULL) {
		DEBUG(0, ("sys_popen: malloc failed\n"));
		goto err_exit;
	}

	/*
	 * Extract the command and args into a NULL terminated array.
	 */

	argl = extract_args(NULL, command);
	if (argl == NULL) {
		DEBUG(0, ("sys_popen: extract_args() failed: %s\n", strerror(errno)));
		goto err_exit;
	}

	entry->child_pid = fork();

	if (entry->child_pid == -1) {
		DEBUG(0, ("sys_popen: fork failed: %s\n", strerror(errno)));
		goto err_exit;
	}

	if (entry->child_pid == 0) {

		/*
		 * Child !
		 */

		int child_std_end = STDOUT_FILENO;
		popen_list *p;

		close(parent_end);
		if (child_end != child_std_end) {
			dup2 (child_end, child_std_end);
			close (child_end);
		}

		/*
		 * POSIX.2:  "popen() shall ensure that any streams from previous
		 * popen() calls that remain open in the parent process are closed
		 * in the new child process."
		 */

		for (p = popen_chain; p; p = p->next)
			close(p->fd);

		ret = execv(argl[0], argl);
		if (ret == -1) {
			DEBUG(0, ("sys_popen: ERROR executing command "
				  "'%s': %s\n", command, strerror(errno)));
		}
		_exit (127);
	}

	/*
	 * Parent.
	 */

	close (child_end);
	TALLOC_FREE(argl);

	/* Link into popen_chain. */
	entry->next = popen_chain;
	popen_chain = entry;
	entry->fd = parent_end;

	return entry->fd;

err_exit:

	TALLOC_FREE(entry);
	TALLOC_FREE(argl);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	return -1;
}

/**************************************************************************
 Wrapper for pclose. Modified from the glibc sources.
****************************************************************************/

int sys_pclose(int fd)
{
	int wstatus;
	popen_list **ptr = &popen_chain;
	popen_list *entry = NULL;
	pid_t wait_pid;
	int status = -1;

	/* Unlink from popen_chain. */
	for ( ; *ptr != NULL; ptr = &(*ptr)->next) {
		if ((*ptr)->fd == fd) {
			entry = *ptr;
			*ptr = (*ptr)->next;
			status = 0;
			break;
		}
	}

	if (status < 0 || close(entry->fd) < 0)
		return -1;

	/*
	 * As Samba is catching and eating child process
	 * exits we don't really care about the child exit
	 * code, a -1 with errno = ECHILD will do fine for us.
	 */

	do {
		wait_pid = waitpid (entry->child_pid, &wstatus, 0);
	} while (wait_pid == -1 && errno == EINTR);

	TALLOC_FREE(entry);

	if (wait_pid == -1)
		return -1;
	return wstatus;
}
