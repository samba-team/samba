/*
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Andrew Tridgell 2003

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
#include "libcli/raw/libcliraw.h"

/*
  wrapper around smbcli_sock_connect()
*/
BOOL smbcli_socket_connect(struct smbcli_state *cli, const char *server)
{
	struct smbcli_socket *sock;

	sock = smbcli_sock_init(cli);
	if (!sock) return False;

	if (!smbcli_sock_connect_byname(sock, server, 0)) {
		talloc_free(sock);
		return False;
	}
	
	cli->transport = smbcli_transport_init(sock);
	talloc_free(sock);
	if (!cli->transport) {
		return False;
	}

	return True;
}

/* wrapper around smbcli_transport_connect() */
BOOL smbcli_transport_establish(struct smbcli_state *cli, 
			     struct nmb_name *calling,
			     struct nmb_name *called)
{
	return smbcli_transport_connect(cli->transport, calling, called);
}

/* wrapper around smb_raw_negotiate() */
NTSTATUS smbcli_negprot(struct smbcli_state *cli)
{
	return smb_raw_negotiate(cli->transport);
}

/* wrapper around smb_raw_session_setup() */
NTSTATUS smbcli_session_setup(struct smbcli_state *cli, 
			      const char *user, 
			      const char *password, 
			      const char *domain)
{
	union smb_sesssetup setup;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	cli->session = smbcli_session_init(cli->transport);
	if (!cli->session) return NT_STATUS_UNSUCCESSFUL;
	talloc_free(cli->transport);

	mem_ctx = talloc_init("smbcli_session_setup");
	if (!mem_ctx) return NT_STATUS_NO_MEMORY;

	setup.generic.level = RAW_SESSSETUP_GENERIC;
	setup.generic.in.sesskey = cli->transport->negotiate.sesskey;
	setup.generic.in.capabilities = cli->transport->negotiate.capabilities;
	if (!user || !user[0]) {
		setup.generic.in.password = NULL;
		setup.generic.in.user = "";
		setup.generic.in.domain = "";
		setup.generic.in.capabilities &= ~CAP_EXTENDED_SECURITY;
	} else {
		if (cli->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) {
			setup.generic.in.password = password;
		} else {
			setup.generic.in.password = NULL;
		}
		setup.generic.in.user = user;
		setup.generic.in.domain = domain;
	}

	status = smb_raw_session_setup(cli->session, mem_ctx, &setup);

	cli->session->vuid = setup.generic.out.vuid;

	talloc_free(mem_ctx);

	return status;
}

/* wrapper around smb_tree_connect() */
NTSTATUS smbcli_send_tconX(struct smbcli_state *cli, const char *sharename, 
			   const char *devtype, const char *password)
{
	union smb_tcon tcon;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	cli->tree = smbcli_tree_init(cli->session);
	talloc_free(cli->session);
	if (!cli->tree) return NT_STATUS_UNSUCCESSFUL;

	mem_ctx = talloc_init("tcon");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* setup a tree connect */
	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;
	if (cli->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) {
		tcon.tconx.in.password = data_blob(NULL, 0);
	} else if (cli->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		tcon.tconx.in.password = data_blob_talloc(mem_ctx, NULL, 24);
		if (cli->transport->negotiate.secblob.length < 8) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		SMBencrypt(password, cli->transport->negotiate.secblob.data, tcon.tconx.in.password.data);
	} else {
		tcon.tconx.in.password = data_blob_talloc(mem_ctx, password, strlen(password)+1);
	}
	tcon.tconx.in.path = sharename;
	tcon.tconx.in.device = devtype;
	
	status = smb_tree_connect(cli->tree, mem_ctx, &tcon);

	cli->tree->tid = tcon.tconx.out.cnum;

	talloc_free(mem_ctx);

	return status;
}


/*
  easy way to get to a fully connected smbcli_state in one call
*/
NTSTATUS smbcli_full_connection(TALLOC_CTX *parent_ctx,
				struct smbcli_state **ret_cli, 
				const char *myname,
				const char *host,
				struct in_addr *ip,
				const char *sharename,
				const char *devtype,
				const char *username,
				const char *domain,
				const char *password,
				uint_t flags,
				BOOL *retry)
{
	struct smbcli_tree *tree;
	NTSTATUS status;
	char *p;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("smbcli_full_connection");

	*ret_cli = NULL;

	/* if the username is of the form DOMAIN\username then split out the domain */
	p = strpbrk(username, "\\/");
	if (p) {
		domain = talloc_strndup(mem_ctx, username, PTR_DIFF(p, username));
		username = talloc_strdup(mem_ctx, p+1);
	}

	status = smbcli_tree_full_connection(parent_ctx,
					     &tree, myname, host, 0, sharename, devtype,
					     username, domain, password);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	(*ret_cli) = smbcli_state_init(parent_ctx);

	(*ret_cli)->tree = tree;
	(*ret_cli)->session = tree->session;
	(*ret_cli)->transport = tree->session->transport;
	talloc_steal(*ret_cli, tree->session->transport->socket);
	
done:
	talloc_free(mem_ctx);

	return status;
}


/*
  disconnect the tree
*/
NTSTATUS smbcli_tdis(struct smbcli_state *cli)
{
	return smb_tree_disconnect(cli->tree);
}

/****************************************************************************
 Initialise a client state structure.
****************************************************************************/
struct smbcli_state *smbcli_state_init(TALLOC_CTX *mem_ctx)
{
	struct smbcli_state *cli;

	cli = talloc_p(mem_ctx, struct smbcli_state);
	if (cli) {
		ZERO_STRUCTP(cli);
	}

	return cli;
}

/****************************************************************************
 Shutdown a client structure.
****************************************************************************/
void smbcli_shutdown(struct smbcli_state *cli)
{
	talloc_free(cli);
}
