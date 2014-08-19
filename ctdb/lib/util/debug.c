/*
   Unix SMB/CIFS implementation.
   ctdb debug functions
   Copyright (C) Volker Lendecke 2007

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
#include <ctype.h>
#include <assert.h>
#include "debug.h"

int DEBUGLEVEL;

static void print_asc(int level, const uint8_t *buf, size_t len)
{
	int i;
	for (i=0;i<len;i++) {
		DEBUGADD(level,("%c", isprint(buf[i])?buf[i]:'.'));
	}
}

void dump_data(int level, const uint8_t *buf, size_t len)
{
	int i=0;

	if (len<=0) return;

	if (!DEBUGLVL(level)) return;

	DEBUG(level, (__location__ " dump data of size %i:\n", (int)len));
	DEBUGADD(level,("[%03X] ",i));
	for (i=0;i<len;) {
		DEBUGADD(level,("%02X ",(int)buf[i]));
		i++;
		if (i%8 == 0) DEBUGADD(level,(" "));
		if (i%16 == 0) {
			print_asc(level,&buf[i-16],8); DEBUGADD(level,(" "));
			print_asc(level,&buf[i-8],8); DEBUGADD(level,("\n"));
			if (i<len) DEBUGADD(level,("[%03X] ",i));
		}
	}
	if (i%16) {
		int n;
		n = 16 - (i%16);
		DEBUGADD(level,(" "));
		if (n>8) DEBUGADD(level,(" "));
		while (n--) DEBUGADD(level,("   "));
		n = MIN(8,i%16);
		print_asc(level,&buf[i-(i%16)],n); DEBUGADD(level,( " " ));
		n = (i%16) - n;
		if (n>0) print_asc(level,&buf[i-n],n);
		DEBUGADD(level,("\n"));
	}
	DEBUG(level, (__location__ " dump data of size %i finished\n", (int)len));
}

/* state variables for the debug system */
static struct {
	debug_callback_fn callback;
	void *callback_private;
} state;

static int current_msg_level = 0;

void debug_set_callback(void *private_ptr, debug_callback_fn fn)
{
	assert(fn != NULL);

	state.callback_private = private_ptr;
	state.callback = fn;
}

bool dbghdr(int level, const char *location, const char *func)
{
	current_msg_level = level;
	return true;
}

bool dbgtext( const char *format_str, ... )
{
	va_list ap;
	char *msgbuf = NULL;
	int res;

	va_start(ap, format_str);
	res = vasprintf(&msgbuf, format_str, ap);
	va_end(ap);
	if (res == -1) {
		return false;
	}

	if (state.callback != NULL) {
		state.callback(state.callback_private,
			       current_msg_level, msgbuf);
	} else {
		write(2, msgbuf, strlen(msgbuf));
	}

	free(msgbuf);
	return true;
}
