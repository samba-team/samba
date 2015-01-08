/*
   Unix SMB/CIFS implementation.
   Critical Fault handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Tim Prouty 2009

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

#ifndef _SAMBA_FAULT_H_
#define _SAMBA_FAULT_H_

#include <sys/types.h>

#include "attr.h"

#ifndef DEBUG
#include "debug.h"
#endif /* DEBUG */

/**
 * assert macros
 */
#ifdef _SAMBA_DEBUG_H
#define SMB_ASSERT(b) \
do { \
	if (!(b)) { \
		DEBUG(0,("PANIC: assert failed at %s(%d): %s\n", \
			 __FILE__, __LINE__, #b)); \
		smb_panic("assert failed: " #b); \
	} \
} while(0)
#endif /* _SAMBA_DEBUG_H */

extern const char *panic_action;

/**
 Something really nasty happened - panic !
**/
typedef void (*smb_panic_handler_t)(const char *why);

void fault_configure(smb_panic_handler_t panic_handler);
void fault_setup(void);
void fault_setup_disable(void);
_NORETURN_ void smb_panic(const char *reason);


#endif /* _SAMBA_FAULT_H_ */
