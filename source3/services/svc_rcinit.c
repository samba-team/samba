/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 *  Copyright (C) Gerald Carter                   2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*********************************************************************
*********************************************************************/

static WERROR rcinit_stop( const char *service, SERVICE_STATUS *status )
{
	char *command = NULL;
	int ret, fd;

	if (asprintf(&command, "%s/%s/%s stop",
				get_dyn_MODULESDIR(), SVCCTL_SCRIPT_DIR, service) < 0) {
		return WERR_NOMEM;
	}

	/* we've already performed the access check when the service was opened */

	become_root();
	ret = smbrun( command , &fd );
	unbecome_root();

	DEBUGADD(5, ("rcinit_start: [%s] returned [%d]\n", command, ret));
	close(fd);

	SAFE_FREE(command);

	ZERO_STRUCTP( status );
	status->type = 0x0020;
	status->state = (ret == 0 ) ? 0x0001 : 0x0004;
	status->controls_accepted = 0x0005;

	return ( ret == 0 ) ? WERR_OK : WERR_ACCESS_DENIED;
}

/*********************************************************************
*********************************************************************/

static WERROR rcinit_start( const char *service )
{
	char *command = NULL;
	int ret, fd;

	if (asprintf(&command, "%s/%s/%s start",
				get_dyn_MODULESDIR(), SVCCTL_SCRIPT_DIR, service) < 0) {
		return WERR_NOMEM;
	}

	/* we've already performed the access check when the service was opened */

	become_root();
	ret = smbrun( command , &fd );
	unbecome_root();

	DEBUGADD(5, ("rcinit_start: [%s] returned [%d]\n", command, ret));
	close(fd);

	SAFE_FREE(command);

	return ( ret == 0 ) ? WERR_OK : WERR_ACCESS_DENIED;
}

/*********************************************************************
*********************************************************************/

static WERROR rcinit_status( const char *service, SERVICE_STATUS *status )
{
	char *command = NULL;
	int ret, fd;

	if (asprintf(&command, "%s/%s/%s status",
				get_dyn_MODULESDIR(), SVCCTL_SCRIPT_DIR, service) < 0) {
		return WERR_NOMEM;
	}

	/* we've already performed the access check when the service was opened */
	/* assume as return code of 0 means that the service is ok.  Anything else
	   is STOPPED */

	become_root();
	ret = smbrun( command , &fd );
	unbecome_root();

	DEBUGADD(5, ("rcinit_start: [%s] returned [%d]\n", command, ret));
	close(fd);

	SAFE_FREE(command);

	ZERO_STRUCTP( status );
	status->type = 0x0020;
	status->state = (ret == 0 ) ? 0x0004 : 0x0001;
	status->controls_accepted = 0x0005;

	return WERR_OK;
}

/*********************************************************************
*********************************************************************/

/* struct for svcctl control to manipulate rcinit service */

SERVICE_CONTROL_OPS rcinit_svc_ops = {
	rcinit_stop,
	rcinit_start,
	rcinit_status
};
