/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba readline wrapper implementation
   Copyright (C) Simo Sorce 2001, 
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

/* user input through readline callback */
static char *command_line;
static int *readline_event;

/****************************************************************************
samba readline callback function
****************************************************************************/
static int smb_rl_callback_handler(char *line_read)
{
	if (!command_line) return RL_ERROR;

	if (line_read)
	{
		pstrcpy(command_line, line_read);
#if defined(HAVE_LIBREADLINE)
#if    defined(HAVE_READLINE_HISTORY_H) || defined(HAVE_HISTORY_H)
		if (strlen(line_read)) add_history(line_read);
		free(line_read);
#endif
#endif
		*readline_event = RL_GOT_LINE;
	} else {
		*readline_event = RL_GOT_EOF;
	}
	return 0;
}

void smb_rl_read_char (void)
{
#ifdef HAVE_LIBREADLINE
	*readline_event = RL_NO_EVENTS;
	rl_callback_read_char ();
#else
	pstring line;
	fgets(line, sizeof(line), stdin);
	smb_rl_callback_handler(line);
#endif
}

/****************************************************************************
init samba readline
****************************************************************************/
void init_smb_readline(char *prg_name, char *cline_ptr, int *event_ptr)
{
	command_line = cline_ptr;
	readline_event = event_ptr;

#ifdef HAVE_LIBREADLINE
	rl_readline_name = prg_name;
	rl_already_prompted = 1;
	rl_callback_handler_install(NULL, (VFunction *)&smb_rl_callback_handler);
#endif
}

/****************************************************************************
display the prompt
****************************************************************************/
void smb_readline_prompt(char *prompt)
{
	extern FILE *dbf;
	
	fprintf(dbf, "%s", prompt);
	fflush(dbf);

#ifdef HAVE_LIBREADLINE
	rl_callback_handler_remove();
	rl_callback_handler_install(prompt, (VFunction *)&smb_rl_callback_handler);
#endif
}

/****************************************************************************
removes readline callback handler
****************************************************************************/
void smb_readline_remove_handler(void)
{
#ifdef HAVE_LIBREADLINE
	rl_callback_handler_remove ();
#endif

	readline_event = NULL;
	command_line = NULL;
}

/****************************************************************************
history
****************************************************************************/
void cmd_history(void)
{
#if defined(HAVE_LIBREADLINE) && (defined(HAVE_READLINE_HISTORY_H) || defined(HAVE_HISTORY_H))
	HIST_ENTRY **hlist;
	int i;

	hlist = history_list ();
	
	for (i = 0; hlist && hlist[i]; i++) {
		DEBUG(0, ("%d: %s\n", i, hlist[i]->line));
	}
#else
	DEBUG(0,("no history without readline support\n"));
#endif
}

