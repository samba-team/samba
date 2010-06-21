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

#ifndef __HAVE_LOG_H
#define __HAVE_LOG_H
#include <stdbool.h>

enum log_type {
	LOG_ALWAYS	= 0x00,
	/* Packets that are written to ctdbd. */
	LOG_WRITE	= 0x02,
	/* Packets that are read from ctdbd. */
	LOG_READ	= 0x04,
	/* Logging from libctdb. */
	LOG_LIB		= 0x08,
	/* Logging from normal operations. */
	LOG_UI		= 0x10,
	/* Verbose debugging. */
	LOG_VERBOSE	= 0x20,
};

/* Adds a \n for convenient logging.  Returns true if it was expected. */
bool log_line(enum log_type type, const char *format, ...);
/* Builds up buffer and prints out line at a time. */
void log_partial(enum log_type type, char *buf, unsigned bufsize,
		 const char *format, ...);
#endif /* __HAVE_LOG_H */
