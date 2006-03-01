/* 
   Unix SMB/CIFS implementation.
   Samba debug defines
   Copyright (C) Andrew Tridgell 2003

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

/* If we have these macros, we can add additional info to the header. */

#ifdef HAVE_FUNCTION_MACRO
#define FUNCTION_MACRO  (__FUNCTION__)
#else
#define FUNCTION_MACRO  ("")
#endif

/* the debug operations structure - contains function pointers to 
   various debug implementations of each operation */
struct debug_ops {
	/* function to log (using DEBUG) suspicious usage of data structure */
	void (*log_suspicious_usage)(const char* from, const char* info);
				
	/* function to log (using printf) suspicious usage of data structure.
	 * To be used in circumstances when using DEBUG would cause loop. */
	void (*print_suspicious_usage)(const char* from, const char* info);
	
	/* function to return process/thread id */
	uint32_t (*get_task_id)(void);
	
	/* function to log process/thread id */
	void (*log_task_id)(int fd);
};

extern int DEBUGLEVEL;

#define DEBUGLVL(level) ((level) <= DEBUGLEVEL)
#define _DEBUG(level, body, header) do { \
	if (DEBUGLVL(level)) { \
		if (header) { \
			do_debug_header(level, __location__, FUNCTION_MACRO); \
		} \
		do_debug body; \
	} \
} while (0)
#define DEBUG(level, body) _DEBUG(level, body, True)
#define DEBUGADD(level, body) _DEBUG(level, body, False)
#define DEBUGC(class, level, body) DEBUG(level, body)
#define DEBUGADDC(class, level, body) DEBUGADD(level, body)
#define DEBUGTAB(n) do_debug_tab(n)

enum debug_logtype {DEBUG_STDOUT = 0, DEBUG_FILE = 1, DEBUG_STDERR = 2};
