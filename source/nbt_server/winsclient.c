/* 
   Unix SMB/CIFS implementation.

   wins client name registration and refresh

   Copyright (C) Andrew Tridgell	2005
   
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
#include "nbt_server/nbt_server.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "lib/events/events.h"
#include "smbd/service_task.h"


/*
  refresh a WINS name registration
*/
static void nbtd_refresh_wins_refresh(struct event_context *ev, struct timed_event *te,
				       struct timeval t, void *private)
{
	struct nbtd_iface_name *iname = talloc_get_type(private, struct nbtd_iface_name);
	nbtd_winsclient_refresh(iname);
}

/*
  called when a wins name refresh has completed
*/
static void nbtd_refresh_wins_handler(struct composite_context *c)
{
	NTSTATUS status;
	struct nbt_name_refresh_wins io;
	struct nbtd_iface_name *iname = talloc_get_type(c->async.private, 
							struct nbtd_iface_name);
	TALLOC_CTX *tmp_ctx = talloc_new(iname);

	status = nbt_name_refresh_wins_recv(c, tmp_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		/* none of the WINS servers responded - try again 
		   periodically */
		int wins_retry_time = lp_parm_int(-1, "nbt", "wins_retry", 300);
		event_add_timed(iname->iface->nbtsrv->task->event_ctx, 
				iname,
				timeval_current_ofs(wins_retry_time, 0),
				nbtd_refresh_wins_refresh,
				iname);
		talloc_free(tmp_ctx);
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("Name refresh failure with WINS for %s<%02x> - %s\n", 
			 iname->name.name, iname->name.type, nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}	

	if (io.out.rcode != 0) {
		DEBUG(1,("WINS server %s rejected name refresh of %s<%02x> - rcode %d\n", 
			 io.out.wins_server, iname->name.name, iname->name.type, io.out.rcode));
		iname->nb_flags |= NBT_NM_CONFLICT;
		talloc_free(tmp_ctx);
		return;
	}	

	/* success - start a periodic name refresh */
	iname->nb_flags |= NBT_NM_ACTIVE;
	if (iname->wins_server) {
		talloc_free(iname->wins_server);
	}
	iname->wins_server = talloc_steal(iname, io.out.wins_server);

	iname->registration_time = timeval_current();
	event_add_timed(iname->iface->nbtsrv->task->event_ctx, 
			iname,
			timeval_add(&iname->registration_time, iname->ttl/2, 0),
			nbtd_refresh_wins_refresh,
			iname);

	talloc_free(tmp_ctx);
}

/*
  refresh a name with our WINS servers
*/
void nbtd_winsclient_refresh(struct nbtd_iface_name *iname)
{
	struct nbtd_interface *iface = iname->iface;
	struct nbt_name_refresh_wins io;
	struct composite_context *c;

	/* setup a wins name refresh request */
	io.in.name            = iname->name;
	io.in.wins_servers    = lp_wins_server_list();
	io.in.addresses       = nbtd_address_list(iface, iname);
	io.in.nb_flags        = iname->nb_flags;
	io.in.ttl             = iname->ttl;

	c = nbt_name_refresh_wins_send(iface->nbtsock, &io);
	if (c == NULL) {
		talloc_free(io.in.addresses);
		return;
	}
	talloc_steal(c, io.in.addresses);

	c->async.fn = nbtd_refresh_wins_handler;
	c->async.private = iname;
}
