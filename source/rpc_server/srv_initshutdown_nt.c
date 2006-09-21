/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell               1992-1997.
 *  Copyright (C) Gerald Carter                 2006.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* Implementation of registry functions. */

#include "includes.h"
#include "regfio.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV


/*******************************************************************
 ********************************************************************/
WERROR _initshutdown_Init(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot)
{
	uint32_t reason = 0;

	/* thunk down to _winreg_InitiateSystemShutdownEx() 
	   (just returns a status) */
	
	return _winreg_InitiateSystemShutdownEx( p, hostname, message, timeout, 
		force_apps, reboot, reason );
}

/*******************************************************************
 ********************************************************************/

WERROR _initshutdown_InitEx(pipes_struct *p, uint16_t *hostname, struct initshutdown_String *message, uint32_t timeout, uint8_t force_apps, uint8_t reboot, uint32_t reason)
{
	return _winreg_InitiateSystemShutdownEx( p, hostname, message, timeout, 
		force_apps, reboot, reason );
}




/*******************************************************************
 reg_abort_shutdwon
 ********************************************************************/

WERROR _initshutdown_Abort(pipes_struct *p, uint16_t *server)
{
	return _winreg_AbortSystemShutdown( p, server );
}
