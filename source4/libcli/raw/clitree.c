/* 
   Unix SMB/CIFS implementation.
   SMB client tree context management functions
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

#define SETUP_REQUEST_TREE(cmd, wct, buflen) do { \
	req = cli_request_setup(tree, cmd, wct, buflen); \
	if (!req) return NULL; \
} while (0)


/****************************************************************************
 Initialize the tree context
****************************************************************************/
struct cli_tree *cli_tree_init(struct cli_session *session)
{
	struct cli_tree *tree;
	TALLOC_CTX *mem_ctx = talloc_init("cli_tree");
	if (mem_ctx == NULL) {
		return NULL;
	}

	tree = talloc_zero(mem_ctx, sizeof(*tree));
	if (!tree) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	tree->mem_ctx = mem_ctx;
	tree->session = session;
	tree->session->reference_count++;

	return tree;
}

/****************************************************************************
reduce reference count on a tree and destroy if <= 0
****************************************************************************/
void cli_tree_close(struct cli_tree *tree)
{
	if (!tree) return;
	tree->reference_count--;
	if (tree->reference_count <= 0) {
		cli_session_close(tree->session);
		talloc_destroy(tree->mem_ctx);
	}
}


/****************************************************************************
 Send a tconX (async send)
****************************************************************************/
struct cli_request *smb_tree_connect_send(struct cli_tree *tree, union smb_tcon *parms)
{
	struct cli_request *req;

	switch (parms->tcon.level) {
	case RAW_TCON_TCON:
		SETUP_REQUEST_TREE(SMBtcon, 0, 0);
		cli_req_append_ascii4(req, parms->tcon.in.service, STR_ASCII);
		cli_req_append_ascii4(req, parms->tcon.in.password,STR_ASCII);
		cli_req_append_ascii4(req, parms->tcon.in.dev,     STR_ASCII);
		break;

	case RAW_TCON_TCONX:
		SETUP_REQUEST_TREE(SMBtconX, 4, 0);
		SSVAL(req->out.vwv, VWV(0), 0xFF);
		SSVAL(req->out.vwv, VWV(1), 0);
		SSVAL(req->out.vwv, VWV(2), parms->tconx.in.flags);
		SSVAL(req->out.vwv, VWV(3), parms->tconx.in.password.length);
		cli_req_append_blob(req, &parms->tconx.in.password);
		cli_req_append_string(req, parms->tconx.in.path,   STR_TERMINATE | STR_UPPER);
		cli_req_append_string(req, parms->tconx.in.device, STR_TERMINATE | STR_ASCII);
		break;
	}

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}

	return req;
}

/****************************************************************************
 Send a tconX (async recv)
****************************************************************************/
NTSTATUS smb_tree_connect_recv(struct cli_request *req, TALLOC_CTX *mem_ctx, union smb_tcon *parms)
{
	char *p;

	if (!cli_request_receive(req) ||
	    cli_request_is_error(req)) {
		goto failed;
	}

	switch (parms->tcon.level) {
	case RAW_TCON_TCON:
		CLI_CHECK_WCT(req, 2);
		parms->tcon.out.max_xmit = SVAL(req->in.vwv, VWV(0));
		parms->tcon.out.cnum = SVAL(req->in.vwv, VWV(1));
		break;

	case RAW_TCON_TCONX:
		ZERO_STRUCT(parms->tconx.out);
		parms->tconx.out.cnum = SVAL(req->in.hdr, HDR_TID);
		if (req->in.wct >= 4) {
			parms->tconx.out.options = SVAL(req->in.vwv, VWV(3));
		}

		/* output is actual service name */
		p = req->in.data;
		if (!p) break;

		p += cli_req_pull_string(req, mem_ctx, &parms->tconx.out.dev_type, 
					 p, -1, STR_ASCII | STR_TERMINATE);
		p += cli_req_pull_string(req, mem_ctx, &parms->tconx.out.fs_type, 
					 p, -1, STR_TERMINATE);
		break;
	}

failed:
	return cli_request_destroy(req);
}

/****************************************************************************
 Send a tconX (sync interface)
****************************************************************************/
NTSTATUS smb_tree_connect(struct cli_tree *tree, TALLOC_CTX *mem_ctx, union smb_tcon *parms)
{
	struct cli_request *req = smb_tree_connect_send(tree, parms);
	return smb_tree_connect_recv(req, mem_ctx, parms);
}


/****************************************************************************
 Send a tree disconnect.
****************************************************************************/
NTSTATUS smb_tree_disconnect(struct cli_tree *tree)
{
	struct cli_request *req;

	if (!tree) return NT_STATUS_OK;
	req = cli_request_setup(tree, SMBtdis, 0, 0);

	if (cli_request_send(req)) {
		cli_request_receive(req);
	}
	return cli_request_destroy(req);
}


/*
  a convenient function to establish a cli_tree from scratch, using reasonable default
  parameters
*/
NTSTATUS cli_tree_full_connection(struct cli_tree **ret_tree, 
				  const char *my_name, 
				  const char *dest_host, int port,
				  const char *service, const char *service_type,
				  const char *user, const char *domain, 
				  const char *password)
{
	struct cli_socket *sock;
	struct cli_transport *transport;
	struct cli_session *session;
	struct cli_tree *tree;
	NTSTATUS status;
	struct nmb_name calling;
	struct nmb_name called;
	union smb_sesssetup setup;
	union smb_tcon tcon;
	TALLOC_CTX *mem_ctx;

	*ret_tree = NULL;

	sock = cli_sock_init();
	if (!sock) {
		return NT_STATUS_NO_MEMORY;
	}

	/* open a TCP socket to the server */
	if (!cli_sock_connect_byname(sock, dest_host, port)) {
		DEBUG(2,("Failed to establish socket connection - %s\n", strerror(errno)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	transport = cli_transport_init(sock);
	if (!transport) {
		cli_sock_close(sock);
		return NT_STATUS_NO_MEMORY;
	}

	/* send a NBT session request, if applicable */
	make_nmb_name(&calling, my_name, 0x0);
	make_nmb_name(&called,  dest_host, 0x20);

	if (!cli_transport_connect(transport, &calling, &called)) {
		cli_transport_close(transport);
		return NT_STATUS_UNSUCCESSFUL;
	}


	/* negotiate protocol options with the server */
	status = smb_raw_negotiate(transport);
	if (!NT_STATUS_IS_OK(status)) {
		cli_transport_close(transport);
		return status;
	}

	session = cli_session_init(transport);
	if (!session) {
		cli_transport_close(transport);
		return NT_STATUS_NO_MEMORY;
	}

	/* prepare a session setup to establish a security context */
	setup.generic.level = RAW_SESSSETUP_GENERIC;
	setup.generic.in.sesskey = transport->negotiate.sesskey;
	setup.generic.in.capabilities = transport->negotiate.capabilities;
	if (!user || !user[0]) {
		setup.generic.in.password = NULL;
		setup.generic.in.user = "";
		setup.generic.in.domain = "";
	} else {
		setup.generic.in.password = password;
		setup.generic.in.user = user;
		setup.generic.in.domain = domain;
	}

	mem_ctx = talloc_init("tcon");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	status = smb_raw_session_setup(session, mem_ctx, &setup);
	if (!NT_STATUS_IS_OK(status)) {
		cli_session_close(session);
		talloc_destroy(mem_ctx);
		return status;
	}

	session->vuid = setup.generic.out.vuid;

	tree = cli_tree_init(session);
	if (!tree) {
		cli_session_close(session);
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* connect to a share using a tree connect */
	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;
	tcon.tconx.in.password = data_blob(NULL, 0);
	asprintf(&tcon.tconx.in.path, "\\\\%s\\%s", dest_host, service);
	if (!service_type) {
		if (strequal(service, "IPC$"))
			service_type = "IPC";
		else
			service_type = "?????";
	}
	tcon.tconx.in.device = service_type;
	
	status = smb_tree_connect(tree, mem_ctx, &tcon);

	free(tcon.tconx.in.path);

	if (!NT_STATUS_IS_OK(status)) {
		cli_tree_close(tree);
		talloc_destroy(mem_ctx);
		return status;
	}

	tree->tid = tcon.tconx.out.cnum;
	if (tcon.tconx.out.dev_type) {
		tree->device = talloc_strdup(tree->mem_ctx, tcon.tconx.out.dev_type);
	}
	if (tcon.tconx.out.fs_type) {
		tree->fs_type = talloc_strdup(tree->mem_ctx, tcon.tconx.out.fs_type);
	}

	talloc_destroy(mem_ctx);

	*ret_tree = tree;
	return NT_STATUS_OK;
}
