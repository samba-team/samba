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


/****************************************************************************
 Add a home service. Returns the new service number or -1 if fail.
****************************************************************************/
int add_home_service(const char *service, const char *username, const char *homedir)
{
	int iHomeService;

	if (!service || !homedir)
		return -1;

	if ((iHomeService = lp_servicenumber(HOMES_NAME)) < 0)
		return -1;

	/*
	 * If this is a winbindd provided username, remove
	 * the domain component before adding the service.
	 * Log a warning if the "path=" parameter does not
	 * include any macros.
	 */

	{
		const char *p = strchr(service,*lp_winbind_separator());

		/* We only want the 'user' part of the string */
		if (p) {
			service = p + 1;
		}
	}

	if (!lp_add_home(service, iHomeService, username, homedir)) {
		return -1;
	}
	
	return lp_servicenumber(service);

}


/**
 * Find a service entry. service is always in dos codepage.
 *
 * @param service is modified (to canonical form??)
 **/
static int find_service(const char *service)
{
	int iService;

	iService = lp_servicenumber(service);

	/* If we still don't have a service, attempt to add it as a printer. */
	if (iService == -1) {
		int iPrinterService;

		if ((iPrinterService = lp_servicenumber(PRINTERS_NAME)) >= 0) {
			const char *pszTemp;

			DEBUG(3,("checking whether %s is a valid printer name...\n", service));
			pszTemp = lp_printcapname();
			if ((pszTemp != NULL) && pcap_printername_ok(service, pszTemp)) {
				DEBUG(3,("%s is a valid printer name\n", service));
				DEBUG(3,("adding %s as a printer service\n", service));
				lp_add_printer(service, iPrinterService);
				iService = lp_servicenumber(service);
				if (iService < 0)
					DEBUG(0,("failed to add %s as a printer service!\n", service));
			} else {
				DEBUG(3,("%s is not a valid printer name\n", service));
			}
		}
	}

	/* Check for default vfs service?  Unsure whether to implement this */
	if (iService == -1) {
	}

	/* just possibly it's a default service? */
	if (iService == -1) {
		char *pdefservice = lp_defaultservice();
		if (pdefservice && *pdefservice && 
		    !strequal(pdefservice,service) &&
		    !strstr(service,"..")) {
			/*
			 * We need to do a local copy here as lp_defaultservice() 
			 * returns one of the rotating lp_string buffers that
			 * could get overwritten by the recursive find_service() call
			 * below. Fix from Josef Hinteregger <joehtg@joehtg.co.at>.
			 */
			pstring defservice;
			pstrcpy(defservice, pdefservice);
			iService = find_service(defservice);
			if (iService >= 0) {
				/* REWRITE: all_string_sub(service, "_","/",0); */
				iService = lp_add_service(service, iService);
			}
		}
	}

	if (iService >= 0 && !VALID_SNUM(iService)) {
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

	tcon = conn_new(req->smb_conn);
	if (!tcon) {
		DEBUG(0,("Couldn't find free connection.\n"));
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	req->tcon = tcon;

	tcon->service = snum;
	tcon->type = type;

	/*
	 * New code to check if there's a share security descripter
	 * added from NT server manager. This is done after the
	 * smb.conf checks are done as we need a uid and token. JRA.
	 *
	 */

	if (!share_access_check(req, tcon, snum, SA_RIGHT_FILE_WRITE_DATA)) {
		if (!share_access_check(req, tcon, snum, SA_RIGHT_FILE_READ_DATA)) {
			/* No access, read or write. */
			DEBUG(0,( "make_connection: connection to %s denied due to security descriptor.\n",
				  lp_servicename(snum)));
			conn_free(req->smb_conn, tcon);
			return NT_STATUS_ACCESS_DENIED;
		} else {
			tcon->read_only = True;
		}
	}

	/* check number of connections */
	if (!claim_connection(tcon,
			      lp_servicename(SNUM(tcon)),
			      lp_max_connections(SNUM(tcon)),
			      False,0)) {
		DEBUG(1,("too many connections - rejected\n"));
		conn_free(req->smb_conn, tcon);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}  

	/* init ntvfs function pointers */
	status = ntvfs_init_connection(req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("ntvfs_init_connection failed for service %s\n", lp_servicename(SNUM(tcon))));
		conn_free(req->smb_conn, tcon);
		return status;
	}
	
	/* Invoke NTVFS connection hook */
	if (tcon->ntvfs_ops->connect) {
		status = tcon->ntvfs_ops->connect(req, lp_servicename(snum));
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("make_connection: NTVFS make connection failed!\n"));
			conn_free(req->smb_conn, tcon);
			return status;
		}
	}
	
	return NT_STATUS_OK;
}

/****************************************************************************
 Make a connection to a service.
 *
 * @param service 
****************************************************************************/
static NTSTATUS make_connection(struct smbsrv_request *req,
				const char *service, DATA_BLOB password, 
				const char *dev, uint16_t vuid)
{
	int snum;
	enum ntvfs_type type;
	const char *type_str;

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
		DEBUG(0,("%s couldn't find service %s\n",
			 sub_get_remote_machine(), service));
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

/****************************************************************************
close a cnum
****************************************************************************/
void close_cnum(struct smbsrv_tcon *tcon)
{
	DEBUG(3,("%s closed connection to service %s\n",
		 tcon->smb_conn->socket.client_addr, lp_servicename(SNUM(tcon))));

	yield_connection(tcon, lp_servicename(SNUM(tcon)));

	/* tell the ntvfs backend that we are disconnecting */
	tcon->ntvfs_ops->disconnect(tcon);

	conn_free(tcon->smb_conn, tcon);
}



/*
  backend for tree connect call
*/
NTSTATUS tcon_backend(struct smbsrv_request *req, union smb_tcon *con)
{
	NTSTATUS status;

	/* can only do bare tcon in share level security */
	if (req->user_ctx == NULL && lp_security() != SEC_SHARE) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (con->generic.level == RAW_TCON_TCON) {
		DATA_BLOB password;
		password = data_blob(con->tcon.in.password, strlen(con->tcon.in.password) + 1);

		status = make_connection(req, con->tcon.in.service, password, con->tcon.in.dev, req->user_ctx->vuid);
		
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		con->tcon.out.max_xmit = req->smb_conn->negotiate.max_recv;
		con->tcon.out.cnum = req->tcon->cnum;
		
		return status;
	} 

	status = make_connection(req, con->tconx.in.path, con->tconx.in.password, 
				 con->tconx.in.device, req->user_ctx->vuid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	con->tconx.out.cnum = req->tcon->cnum;
	con->tconx.out.dev_type = talloc_strdup(req->mem_ctx, req->tcon->dev_type);
	con->tconx.out.fs_type = talloc_strdup(req->mem_ctx, req->tcon->fs_type);
	con->tconx.out.options = SMB_SUPPORT_SEARCH_BITS | (lp_csc_policy(req->tcon->service) << 2);
	if (lp_msdfs_root(req->tcon->service) && lp_host_msdfs()) {
		con->tconx.out.options |= SMB_SHARE_IN_DFS;
	}

	return status;
}
