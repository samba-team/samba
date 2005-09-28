/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"
#include "wrepl_server/wrepl_out_helpers.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "libcli/composite/composite.h"
#include "libcli/wrepl/winsrepl.h"

NTSTATUS wreplsrv_apply_records(struct wreplsrv_partner *partner, struct wreplsrv_pull_names_io *names_io)
{
	NTSTATUS status;

	/* TODO: ! */
	DEBUG(0,("TODO: apply records count[%u]:owner[%s]:min[%llu]:max[%llu]:partner[%s]\n",
		names_io->out.num_names, names_io->in.owner.address,
		names_io->in.owner.min_version, names_io->in.owner.max_version,
		partner->address));

	status = wreplsrv_add_table(partner->service,
				    partner->service,
				    &partner->service->table,
				    names_io->in.owner.address,
				    names_io->in.owner.max_version);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}
