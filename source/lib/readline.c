/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba readline wrapper implementation
   Copyright (C) Simo Sorce 2001
   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/****************************************************************************
 Display the prompt and wait for input. Call callback() regularly
****************************************************************************/

char *smb_readline(char *prompt, void (*callback)(void), 
		   char **(completion_fn)(const char *text, int start, int end))
{
	char *ret;
	int fd = fileno(stdin);

#if HAVE_LIBREADLINE

	/*
	 * Current versions of readline on Linux seem to have
	 * problems with EOF on a pipe.
	 */

	if (isatty(fd)) {
		if (completion_fn)
			rl_attempted_completion_function = completion_fn;

		if (callback)
			rl_event_hook = (Function *)callback;
		ret = readline(prompt);
		if (ret && *ret)
			add_history(ret);
		return ret;
	} else
#endif
	{
		fd_set fds;
		extern FILE *dbf;
		static pstring line;
		struct timeval timeout;

		fprintf(dbf, "%s", prompt);
		fflush(dbf);

		while (1) {
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;

			FD_ZERO(&fds);
			FD_SET(fd,&fds);
	
			if (sys_select_intr(fd+1,&fds,NULL,NULL,&timeout) == 1) {
				ret = fgets(line, sizeof(line), stdin);
				return ret;
			}
			if (callback)
				callback();
		}
	}
}

/****************************************************************************
history
****************************************************************************/
void cmd_history(void)
{
#if defined(HAVE_LIBREADLINE)
	HIST_ENTRY **hlist;
	int i;

	hlist = history_list();
	
	for (i = 0; hlist && hlist[i]; i++) {
		DEBUG(0, ("%d: %s\n", i, hlist[i]->line));
	}
#else
	DEBUG(0,("no history without readline support\n"));
#endif
}
