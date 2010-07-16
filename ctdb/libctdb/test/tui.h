/*

This file is taken from nfsim (http://ozlabs.org/~jk/projects/nfsim/)

Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

This file is part of nfsim.

nfsim is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

nfsim is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with nfsim; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __HAVE_TUI_H
#define __HAVE_TUI_H

#include <stdbool.h>

#define TUI_MAX_CMD_LEN		1024
#define TUI_MAX_ARGS		128

int tui_register_command(const char *command,
			 bool (*handler)(int argc, char **argv),
			 void (*helpfn)(int argc, char **argv));

int tui_register_pre_post_hook(void (*pre)(const char *),
			       bool (*post)(const char *));

void tui_run(int fd);

bool tui_do_command(int argc, char *argv[], bool abort);

/* Is this a valid command?  Sanity check for expect. */
bool tui_is_command(const char *name);

/* A script test failed (a command failed with -e, or an expect failed). */
void script_fail(const char *fmt, ...) __attribute__((noreturn));

extern int tui_echo_commands;
extern int tui_abort_on_fail;
extern int tui_quiet;
extern int tui_linenum;

#endif /* __HAVE_TUI_H */
