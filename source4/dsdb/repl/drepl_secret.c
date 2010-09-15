/*
   Unix SMB/CIFS mplementation.

   DSDB replication service - repl secret handling

   Copyright (C) Andrew Tridgell 2010
   Copyright (C) Andrew Bartlett 2010

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

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "smbd/service.h"
#include "dsdb/repl/drepl_service.h"
#include "param/param.h"


/**
 * Called when the auth code wants us to try and replicate
 * a users secrets
 */
void drepl_repl_secret(struct dreplsrv_service *service,
		       const char *user_dn)
{
	DEBUG(0,(__location__ ": got drepl_repl_secret with %s\n", user_dn));
}
