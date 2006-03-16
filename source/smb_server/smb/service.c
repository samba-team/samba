/* 
   Unix SMB/CIFS implementation.
   service (connection) handling
   Copyright (C) Andrew Tridgell 1992-2003
   
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
#include "smb_server/smb_server.h"
#include "smbd/service_stream.h"
#include "ntvfs/ntvfs.h"


/**
 * Find a service entry. service is always in dos codepage.
 *
 * @param service is modified (to canonical form??)
 **/
static int find_service(const char *service)
{
	int iService;

	iService = lp_servicenumber(service);

	if (iService >= 0 && !lp_snum_ok(iService)) {
		DEBUG(0,("Invalid snum %d for %s\n",iService, service));
		iService = -1;
	}

	if (iService == -1) {
		DEBUG(3,("find_service() failed to find service %s\n", service));
	}

	return iService;
}


/****************************************************************************
  Make a connection, given the snum to connect to, and the vuser of the
  connecting user if appropriate.
****************************************************************************/
static NTSTATUS make_connection_snum(struct smbsrv_request *req,
				     int snum, enum ntvfs_type type,
				     DATA_BLOB password, 
				     const char *dev)
{
	struct smbsrv_tcon *tcon;
	NTSTATUS status;

	if (!socket_check_access(req->smb_conn->connection->socket, 
				 lp_servicename(snum), 
				 lp_hostsallow(snum), 
				 lp_hostsdeny(snum))) {
		return NT_STATUS_ACCESS_DENIED;
	}

	tcon = smbsrv_smb_tcon_new(req->smb_conn, lp_servicename(snum));
	if (!tcon) {
		DEBUG(0,("Couldn't find free connection.\n"));
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	req->tcon = tcon;

	/* init ntvfs function pointers */
	status = ntvfs_init_connection(tcon, snum, type,
				       req->smb_conn->negotiate.protocol,
				       req->smb_conn->connection->event.ctx,
				       req->smb_conn->connection->msg_ctx,
				       req->smb_conn->connection->server_id,
				       &tcon->ntvfs);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("ntvfs_init_connection failed for service %s\n", 
			  lp_servicename(snum)));
		goto failed;
	}

	status = ntvfs_set_oplock_handler(tcon->ntvfs, smbsrv_send_oplock_break, tcon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("make_connection: NTVFS failed to set the oplock handler!\n"));
		goto failed;
	}

	/* Invoke NTVFS connection hook */
	status = ntvfs_connect(req, lp_servicename(snum));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("make_connection: NTVFS make connection failed!\n"));
		goto failed;
	}

	return NT_STATUS_OK;

failed:
	req->tcon = NULL;
	talloc_free(tcon);
	return status;
}

/****************************************************************************
 Make a connection to a service.
 *
 * @param service 
****************************************************************************/
static NTSTATUS make_connection(struct smbsrv_request *req,
				const char *service, DATA_BLOB password, 
				const char *dev)
{
	int snum;
	enum ntvfs_type type;
	const char *type_str;

	/* TODO: check the password, when it's share level security! */

	/* the service might be of the form \\SERVER\SHARE. Should we put
	   the server name we get from this somewhere? */
	if (strncmp(service, "\\\\", 2) == 0) {
		char *p = strchr(service+2, '\\');
		if (p) {
			service = p + 1;
		}
	}

	snum = find_service(service);

	if (snum == -1) {
		DEBUG(0,("couldn't find service %s\n", service));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	/* work out what sort of connection this is */
	if (strcmp(lp_fstype(snum), "IPC") == 0) {
		type = NTVFS_IPC;
		type_str = "IPC";
	} else if (lp_print_ok(snum)) {
		type = NTVFS_PRINT;
		type_str = "LPT:";
	} else {
		type = NTVFS_DISK;
		type_str = "A:";
	}

	if (strcmp(dev, "?????") != 0 && strcasecmp(type_str, dev) != 0) {
		/* the client gave us the wrong device type */
		return NT_STATUS_BAD_DEVICE_TYPE;
	}

	return make_connection_snum(req, snum, type, password, dev);
}

/*
  backend for tree connect call
*/
NTSTATUS smbsrv_tcon_backend(struct smbsrv_request *req, union smb_tcon *con)
{
	NTSTATUS status;
	int snum;

	if (con->generic.level == RAW_TCON_TCON) {
		DATA_BLOB password;
		password = data_blob(con->tcon.in.password, strlen(con->tcon.in.password) + 1);

		status = make_connection(req, con->tcon.in.service, password, con->tcon.in.dev);
		
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		con->tcon.out.max_xmit = req->smb_conn->negotiate.max_recv;
		con->tcon.out.tid = req->tcon->tid;

		return status;
	} 

	status = make_connection(req, con->tconx.in.path, con->tconx.in.password, 
				 con->tconx.in.device);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	snum = req->tcon->ntvfs->config.snum;

	con->tconx.out.tid = req->tcon->tid;
	con->tconx.out.dev_type = talloc_strdup(req, req->tcon->ntvfs->dev_type);
	con->tconx.out.fs_type = talloc_strdup(req, req->tcon->ntvfs->fs_type);
	con->tconx.out.options = SMB_SUPPORT_SEARCH_BITS | (lp_csc_policy(snum) << 2);
	if (lp_msdfs_root(snum) && lp_host_msdfs()) {
		con->tconx.out.options |= SMB_SHARE_IN_DFS;
	}

	return status;
}
