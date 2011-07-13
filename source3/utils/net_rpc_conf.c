/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Local configuration interface
 *  Copyright (C) Vicentiu Ciorbaru 2011
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

/*
 * This is an interface to Samba's configuration.
 *
 * This tool supports local as well as remote interaction via rpc
 * with the configuration stored in the registry.
 */


#include "includes.h"
#include "utils/net.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/init_samr.h"
#include "../librpc/gen_ndr/ndr_winreg_c.h"
#include "../libcli/registry/util_reg.h"
#include "rpc_client/cli_winreg.h"
#include "../lib/smbconf/smbconf.h"


/* function calls */
int net_rpc_conf(struct net_context *c, int argc,
		 const char **argv)
{
	return 0;

}
