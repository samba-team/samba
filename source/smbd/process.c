/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Andrew Tridgell 1992-2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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

/*
 * initialize an smb process
 */
void smbd_process_init(void)
{
	TALLOC_CTX *mem_ctx;

	generate_wellknown_sids();
	
	mem_ctx = talloc_init("smbd_process_init talloc");
	if (!mem_ctx) {
		DEBUG(0,("smbd_process_init: ERROR: No memory\n"));
		exit(1);
	}
	namecache_enable();

	if (!share_info_db_init())
		exit(1);

	if (!init_registry())
		exit(1);

	/* possibly reload the services file. */
	reload_services(NULL, True);

	if (!init_account_policy()) {
		DEBUG(0,("Could not open account policy tdb.\n"));
		exit(1);
	}

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) == 0)
			DEBUG(2,("Changed root to %s\n", lp_rootdir()));
	}

	/* Setup oplocks */
	if (!init_oplocks())
		exit(1);
	
	/* Setup change notify */
	if (!init_change_notify())
		exit(1);

	talloc_destroy(mem_ctx);
}

void init_subsystems(void)
{
	/* Setup the PROCESS_MODEL subsystem */
	if (!process_model_init())
		exit(1);

	/* Setup the AUTH subsystem */
	if (!auth_init())
		exit(1);

	/* Setup the NTVFS subsystem */
	if (!ntvfs_init())
		exit(1);

	/* Setup the DCERPC subsystem */
	if (!dcesrv_init())
		exit(1);

}
