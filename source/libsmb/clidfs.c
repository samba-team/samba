/*
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Andrew Tridgell                  1994-1998
   Copyright (C) Gerald (Jerry) Carter            2004
   Copyright (C) Jeremy Allison                   2007

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

/********************************************************************
 Important point.

 DFS paths are *always* of the form \server\share\<pathname> (the \ characters
 are not C escaped here).

 - but if we're using POSIX paths then <pathname> may contain
   '/' separators, not '\\' separators. So cope with '\\' or '/'
   as a separator when looking at the pathname part.... JRA.
********************************************************************/

struct client_connection {
	struct client_connection *prev, *next;
	struct cli_state *cli;
	char *mount;
};

/* global state....globals reek! */
int max_protocol = PROTOCOL_NT1;

static struct cm_cred_struct {
	char *username;
	char *password;
	bool got_pass;
	bool use_kerberos;
	bool fallback_after_kerberos;
	int signing_state;
} cm_creds;

static void cm_set_password(const char *newpass);

static int port;
static int name_type = 0x20;
static bool have_ip;
static struct sockaddr_storage dest_ss;

static struct client_connection *connections;

static bool cli_check_msdfs_proxy(TALLOC_CTX *ctx,
				struct cli_state *cli,
				const char *sharename,
				char **pp_newserver,
				char **pp_newshare,
				bool force_encrypt,
				const char *username,
				const char *password,
				const char *domain);

/********************************************************************
 Ensure a connection is encrypted.
********************************************************************/

NTSTATUS cli_cm_force_encryption(struct cli_state *c,
			const char *username,
			const char *password,
			const char *domain,
			const char *sharename)
{
	NTSTATUS status = cli_force_encryption(c,
					username,
					password,
					domain);

	if (NT_STATUS_EQUAL(status,NT_STATUS_NOT_SUPPORTED)) {
		d_printf("Encryption required and "
			"server that doesn't support "
			"UNIX extensions - failing connect\n");
	} else if (NT_STATUS_EQUAL(status,NT_STATUS_UNKNOWN_REVISION)) {
		d_printf("Encryption required and "
			"can't get UNIX CIFS extensions "
			"version from server.\n");
	} else if (NT_STATUS_EQUAL(status,NT_STATUS_UNSUPPORTED_COMPRESSION)) {
		d_printf("Encryption required and "
			"share %s doesn't support "
			"encryption.\n", sharename);
	} else if (!NT_STATUS_IS_OK(status)) {
		d_printf("Encryption required and "
			"setup failed with error %s.\n",
			nt_errstr(status));
	}

	return status;
}
	
/********************************************************************
 Return a connection to a server.
********************************************************************/

static struct cli_state *do_connect(TALLOC_CTX *ctx,
					const char *server,
					const char *share,
					bool show_sessetup,
					bool force_encrypt)
{
	struct cli_state *c = NULL;
	struct nmb_name called, calling;
	const char *server_n;
	struct sockaddr_storage ss;
	char *servicename;
	char *sharename;
	char *newserver, *newshare;
	const char *username;
	const char *password;
	NTSTATUS status;

	/* make a copy so we don't modify the global string 'service' */
	servicename = talloc_strdup(ctx,share);
	if (!servicename) {
		return NULL;
	}
	sharename = servicename;
	if (*sharename == '\\') {
		server = sharename+2;
		sharename = strchr_m(server,'\\');
		if (!sharename) {
			return NULL;
		}
		*sharename = 0;
		sharename++;
	}

	server_n = server;

	zero_sockaddr(&ss);

	make_nmb_name(&calling, global_myname(), 0x0);
	make_nmb_name(&called , server, name_type);

 again:
	zero_sockaddr(&ss);
	if (have_ip)
		ss = dest_ss;

	/* have to open a new connection */
	if (!(c=cli_initialise()) || (cli_set_port(c, port) != port)) {
		d_printf("Connection to %s failed\n", server_n);
		if (c) {
			cli_shutdown(c);
		}
		return NULL;
	}
	status = cli_connect(c, server_n, &ss);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Connection to %s failed (Error %s)\n",
				server_n,
				nt_errstr(status));
		cli_shutdown(c);
		return NULL;
	}

	c->protocol = max_protocol;
	c->use_kerberos = cm_creds.use_kerberos;
	c->fallback_after_kerberos = cm_creds.fallback_after_kerberos;
	cli_setup_signing_state(c, cm_creds.signing_state);

	if (!cli_session_request(c, &calling, &called)) {
		char *p;
		d_printf("session request to %s failed (%s)\n",
			 called.name, cli_errstr(c));
		cli_shutdown(c);
		c = NULL;
		if ((p=strchr_m(called.name, '.'))) {
			*p = 0;
			goto again;
		}
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}

	DEBUG(4,(" session request ok\n"));

	if (!cli_negprot(c)) {
		d_printf("protocol negotiation failed\n");
		cli_shutdown(c);
		return NULL;
	}

	if (!cm_creds.got_pass && !cm_creds.use_kerberos) {
		char *label = NULL;
		char *pass;
		label = talloc_asprintf(ctx, "Enter %s's password: ",
			cm_creds.username);
		pass = getpass(label);
		if (pass) {
			cm_set_password(pass);
		}
		TALLOC_FREE(label);
	}

	username = cm_creds.username ? cm_creds.username : "";
	password = cm_creds.password ? cm_creds.password : "";

	if (!NT_STATUS_IS_OK(cli_session_setup(c, username,
					       password, strlen(password),
					       password, strlen(password),
					       lp_workgroup()))) {
		/* If a password was not supplied then
		 * try again with a null username. */
		if (password[0] || !username[0] || cm_creds.use_kerberos ||
		    !NT_STATUS_IS_OK(cli_session_setup(c, "",
				    		"", 0,
						"", 0,
					       lp_workgroup()))) {
			d_printf("session setup failed: %s\n", cli_errstr(c));
			if (NT_STATUS_V(cli_nt_error(c)) ==
			    NT_STATUS_V(NT_STATUS_MORE_PROCESSING_REQUIRED))
				d_printf("did you forget to run kinit?\n");
			cli_shutdown(c);
			return NULL;
		}
		d_printf("Anonymous login successful\n");
	}

	if ( show_sessetup ) {
		if (*c->server_domain) {
			DEBUG(0,("Domain=[%s] OS=[%s] Server=[%s]\n",
				c->server_domain,c->server_os,c->server_type));
		} else if (*c->server_os || *c->server_type) {
			DEBUG(0,("OS=[%s] Server=[%s]\n",
				 c->server_os,c->server_type));
		}
	}
	DEBUG(4,(" session setup ok\n"));

	/* here's the fun part....to support 'msdfs proxy' shares
	   (on Samba or windows) we have to issues a TRANS_GET_DFS_REFERRAL
	   here before trying to connect to the original share.
	   check_dfs_proxy() will fail if it is a normal share. */

	if ((c->capabilities & CAP_DFS) &&
			cli_check_msdfs_proxy(ctx, c, sharename,
				&newserver, &newshare,
				force_encrypt,
				username,
				password,
				lp_workgroup())) {
		cli_shutdown(c);
		return do_connect(ctx, newserver,
				newshare, false, force_encrypt);
	}

	/* must be a normal share */

	if (!cli_send_tconX(c, sharename, "?????",
				password, strlen(password)+1)) {
		d_printf("tree connect failed: %s\n", cli_errstr(c));
		cli_shutdown(c);
		return NULL;
	}

	if (force_encrypt) {
		status = cli_cm_force_encryption(c,
					username,
					password,
					lp_workgroup(),
					sharename);
		if (!NT_STATUS_IS_OK(status)) {
			cli_shutdown(c);
			return NULL;
		}
	}

	DEBUG(4,(" tconx ok\n"));
	return c;
}

/****************************************************************************
****************************************************************************/

static void cli_cm_set_mntpoint(struct cli_state *c, const char *mnt)
{
	struct client_connection *p;
	int i;

	for (p=connections,i=0; p; p=p->next,i++) {
		if (strequal(p->cli->desthost, c->desthost) &&
				strequal(p->cli->share, c->share)) {
			break;
		}
	}

	if (p) {
		char *name = clean_name(NULL, mnt);
		if (!name) {
			return;
		}
		TALLOC_FREE(p->mount);
		p->mount = talloc_strdup(p, name);
		TALLOC_FREE(name);
	}
}

/****************************************************************************
****************************************************************************/

const char *cli_cm_get_mntpoint(struct cli_state *c)
{
	struct client_connection *p;
	int i;

	for (p=connections,i=0; p; p=p->next,i++) {
		if (strequal(p->cli->desthost, c->desthost) &&
				strequal(p->cli->share, c->share)) {
			break;
		}
	}

	if (p) {
		return p->mount;
	}
	return NULL;
}

/********************************************************************
 Add a new connection to the list
********************************************************************/

static struct cli_state *cli_cm_connect(TALLOC_CTX *ctx,
					struct cli_state *referring_cli,
	 				const char *server,
					const char *share,
					bool show_hdr,
					bool force_encrypt)
{
	struct client_connection *node;

	/* NB This must be the null context here... JRA. */
	node = TALLOC_ZERO_ARRAY(NULL, struct client_connection, 1);
	if (!node) {
		return NULL;
	}

	node->cli = do_connect(ctx, server, share, show_hdr, force_encrypt);

	if ( !node->cli ) {
		TALLOC_FREE( node );
		return NULL;
	}

	DLIST_ADD( connections, node );

	cli_cm_set_mntpoint(node->cli, "");

	if (referring_cli && referring_cli->posix_capabilities) {
		uint16 major, minor;
		uint32 caplow, caphigh;
		if (cli_unix_extensions_version(node->cli, &major,
					&minor, &caplow, &caphigh)) {
			cli_set_unix_extensions_capabilities(node->cli,
					major, minor,
					caplow, caphigh);
		}
	}

	return node->cli;
}

/********************************************************************
 Return a connection to a server.
********************************************************************/

static struct cli_state *cli_cm_find(const char *server, const char *share)
{
	struct client_connection *p;

	for (p=connections; p; p=p->next) {
		if ( strequal(server, p->cli->desthost) &&
				strequal(share,p->cli->share)) {
			return p->cli;
		}
	}

	return NULL;
}

/****************************************************************************
 Open a client connection to a \\server\share.  Set's the current *cli
 global variable as a side-effect (but only if the connection is successful).
****************************************************************************/

struct cli_state *cli_cm_open(TALLOC_CTX *ctx,
				struct cli_state *referring_cli,
				const char *server,
				const char *share,
				bool show_hdr,
				bool force_encrypt)
{
	struct cli_state *c;

	/* try to reuse an existing connection */

	c = cli_cm_find(server, share);
	if (!c) {
		c = cli_cm_connect(ctx, referring_cli,
				server, share, show_hdr, force_encrypt);
	}

	return c;
}

/****************************************************************************
****************************************************************************/

void cli_cm_shutdown(void)
{
	struct client_connection *p, *x;

	for (p=connections; p;) {
		cli_shutdown(p->cli);
		x = p;
		p = p->next;

		TALLOC_FREE(x);
	}

	connections = NULL;
	return;
}

/****************************************************************************
****************************************************************************/

void cli_cm_display(void)
{
	struct client_connection *p;
	int i;

	for ( p=connections,i=0; p; p=p->next,i++ ) {
		d_printf("%d:\tserver=%s, share=%s\n",
			i, p->cli->desthost, p->cli->share );
	}
}

/****************************************************************************
****************************************************************************/

static void cm_set_password(const char *newpass)
{
	SAFE_FREE(cm_creds.password);
	cm_creds.password = SMB_STRDUP(newpass);
	if (cm_creds.password) {
		cm_creds.got_pass = true;
	}
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_credentials(void)
{
	SAFE_FREE(cm_creds.username);
	cm_creds.username = SMB_STRDUP(get_cmdline_auth_info_username());

	if (get_cmdline_auth_info_got_pass()) {
		cm_set_password(get_cmdline_auth_info_password());
	}

	cm_creds.use_kerberos = get_cmdline_auth_info_use_kerberos();
	cm_creds.fallback_after_kerberos = false;
	cm_creds.signing_state = get_cmdline_auth_info_signing_state();
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_port(int port_number)
{
	port = port_number;
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_dest_name_type(int type)
{
	name_type = type;
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_signing_state(int state)
{
	cm_creds.signing_state = state;
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_username(const char *username)
{
	SAFE_FREE(cm_creds.username);
	cm_creds.username = SMB_STRDUP(username);
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_password(const char *newpass)
{
	SAFE_FREE(cm_creds.password);
	cm_creds.password = SMB_STRDUP(newpass);
	if (cm_creds.password) {
		cm_creds.got_pass = true;
	}
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_use_kerberos(void)
{
	cm_creds.use_kerberos = true;
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_fallback_after_kerberos(void)
{
	cm_creds.fallback_after_kerberos = true;
}

/****************************************************************************
****************************************************************************/

void cli_cm_set_dest_ss(struct sockaddr_storage *pss)
{
	dest_ss = *pss;
	have_ip = true;
}

/**********************************************************************
 split a dfs path into the server, share name, and extrapath components
**********************************************************************/

static void split_dfs_path(TALLOC_CTX *ctx,
				const char *nodepath,
				char **pp_server,
				char **pp_share,
				char **pp_extrapath)
{
	char *p, *q;
	char *path;

	*pp_server = NULL;
	*pp_share = NULL;
	*pp_extrapath = NULL;

	path = talloc_strdup(ctx, nodepath);
	if (!path) {
		return;
	}

	if ( path[0] != '\\' ) {
		return;
	}

	p = strchr_m( path + 1, '\\' );
	if ( !p ) {
		return;
	}

	*p = '\0';
	p++;

	/* Look for any extra/deep path */
	q = strchr_m(p, '\\');
	if (q != NULL) {
		*q = '\0';
		q++;
		*pp_extrapath = talloc_strdup(ctx, q);
	} else {
		*pp_extrapath = talloc_strdup(ctx, "");
	}

	*pp_share = talloc_strdup(ctx, p);
	*pp_server = talloc_strdup(ctx, &path[1]);
}

/****************************************************************************
 Return the original path truncated at the directory component before
 the first wildcard character. Trust the caller to provide a NULL
 terminated string
****************************************************************************/

static char *clean_path(TALLOC_CTX *ctx, const char *path)
{
	size_t len;
	char *p1, *p2, *p;
	char *path_out;

	/* No absolute paths. */
	while (IS_DIRECTORY_SEP(*path)) {
		path++;
	}

	path_out = talloc_strdup(ctx, path);
	if (!path_out) {
		return NULL;
	}

	p1 = strchr_m(path_out, '*');
	p2 = strchr_m(path_out, '?');

	if (p1 || p2) {
		if (p1 && p2) {
			p = MIN(p1,p2);
		} else if (!p1) {
			p = p2;
		} else {
			p = p1;
		}
		*p = '\0';

		/* Now go back to the start of this component. */
		p1 = strrchr_m(path_out, '/');
		p2 = strrchr_m(path_out, '\\');
		p = MAX(p1,p2);
		if (p) {
			*p = '\0';
		}
	}

	/* Strip any trailing separator */

	len = strlen(path_out);
	if ( (len > 0) && IS_DIRECTORY_SEP(path_out[len-1])) {
		path_out[len-1] = '\0';
	}

	return path_out;
}

/****************************************************************************
****************************************************************************/

static char *cli_dfs_make_full_path(TALLOC_CTX *ctx,
					struct cli_state *cli,
					const char *dir)
{
	char path_sep = '\\';

	/* Ensure the extrapath doesn't start with a separator. */
	while (IS_DIRECTORY_SEP(*dir)) {
		dir++;
	}

	if (cli->posix_capabilities & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		path_sep = '/';
	}
	return talloc_asprintf(ctx, "%c%s%c%s%c%s",
			path_sep,
			cli->desthost,
			path_sep,
			cli->share,
			path_sep,
			dir);
}

/********************************************************************
 check for dfs referral
********************************************************************/

static bool cli_dfs_check_error( struct cli_state *cli, NTSTATUS status )
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

	/* only deal with DS when we negotiated NT_STATUS codes and UNICODE */

	if (!((flgs2&FLAGS2_32_BIT_ERROR_CODES) &&
				(flgs2&FLAGS2_UNICODE_STRINGS)))
		return false;

	if (NT_STATUS_EQUAL(status, NT_STATUS(IVAL(cli->inbuf,smb_rcls))))
		return true;

	return false;
}

/********************************************************************
 Get the dfs referral link.
********************************************************************/

bool cli_dfs_get_referral(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			CLIENT_DFS_REFERRAL**refs,
			size_t *num_refs,
			uint16 *consumed)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_GET_DFS_REFERRAL;
	char *param;
	char *rparam=NULL, *rdata=NULL;
	char *p;
	char *endp;
	size_t pathlen = 2*(strlen(path)+1);
	uint16 num_referrals;
	CLIENT_DFS_REFERRAL *referrals = NULL;
	bool ret = false;

	*num_refs = 0;
	*refs = NULL;

	param = SMB_MALLOC_ARRAY(char, 2+pathlen+2);
	if (!param) {
		return false;
	}
	SSVAL(param, 0, 0x03);	/* max referral level */
	p = &param[2];

	p += clistr_push(cli, p, path, pathlen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                          /* fid, flags */
			&setup, 1, 0,                   /* setup, length, max */
			param, param_len, 2,            /* param, length, max */
			NULL, 0, cli->max_xmit /* data, length, max */
			)) {
		SAFE_FREE(param);
		return false;
	}

	SAFE_FREE(param);

	if (!cli_receive_trans(cli, SMBtrans2,
		&rparam, &param_len,
		&rdata, &data_len)) {
			return false;
	}

	if (data_len < 4) {
		goto out;
	}

	endp = rdata + data_len;

	*consumed     = SVAL(rdata, 0);
	num_referrals = SVAL(rdata, 2);

	if (num_referrals != 0) {
		uint16 ref_version;
		uint16 ref_size;
		int i;
		uint16 node_offset;

		referrals = TALLOC_ARRAY(ctx, CLIENT_DFS_REFERRAL,
				num_referrals);

		if (!referrals) {
			goto out;
		}
		/* start at the referrals array */

		p = rdata+8;
		for (i=0; i<num_referrals && p < endp; i++) {
			if (p + 18 > endp) {
				goto out;
			}
			ref_version = SVAL(p, 0);
			ref_size    = SVAL(p, 2);
			node_offset = SVAL(p, 16);

			if (ref_version != 3) {
				p += ref_size;
				continue;
			}

			referrals[i].proximity = SVAL(p, 8);
			referrals[i].ttl       = SVAL(p, 10);

			if (p + node_offset > endp) {
				goto out;
			}
			clistr_pull_talloc(ctx, cli, &referrals[i].dfspath,
				p+node_offset, -1,
				STR_TERMINATE|STR_UNICODE );

			if (!referrals[i].dfspath) {
				goto out;
			}
			p += ref_size;
		}
		if (i < num_referrals) {
			goto out;
		}
	}

	ret = true;

	*num_refs = num_referrals;
	*refs = referrals;

  out:

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
	return ret;
}

/********************************************************************
********************************************************************/

bool cli_resolve_path(TALLOC_CTX *ctx,
			const char *mountpt,
			struct cli_state *rootcli,
			const char *path,
			struct cli_state **targetcli,
			char **pp_targetpath)
{
	CLIENT_DFS_REFERRAL *refs = NULL;
	size_t num_refs = 0;
	uint16 consumed;
	struct cli_state *cli_ipc = NULL;
	char *dfs_path = NULL;
	char *cleanpath = NULL;
	char *extrapath = NULL;
	int pathlen;
	char *server = NULL;
	char *share = NULL;
	struct cli_state *newcli = NULL;
	char *newpath = NULL;
	char *newmount = NULL;
	char *ppath = NULL;
	SMB_STRUCT_STAT sbuf;
	uint32 attributes;

	if ( !rootcli || !path || !targetcli ) {
		return false;
	}

	/* Don't do anything if this is not a DFS root. */

	if ( !rootcli->dfsroot) {
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return false;
		}
		return true;
	}

	*targetcli = NULL;

	/* Send a trans2_query_path_info to check for a referral. */

	cleanpath = clean_path(ctx, path);
	if (!cleanpath) {
		return false;
	}

	dfs_path = cli_dfs_make_full_path(ctx, rootcli, cleanpath);
	if (!dfs_path) {
		return false;
	}

	if (cli_qpathinfo_basic( rootcli, dfs_path, &sbuf, &attributes)) {
		/* This is an ordinary path, just return it. */
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return false;
		}
		goto done;
	}

	/* Special case where client asked for a path that does not exist */

	if (cli_dfs_check_error(rootcli, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		*targetcli = rootcli;
		*pp_targetpath = talloc_strdup(ctx, path);
		if (!*pp_targetpath) {
			return false;
		}
		goto done;
	}

	/* We got an error, check for DFS referral. */

	if (!cli_dfs_check_error(rootcli, NT_STATUS_PATH_NOT_COVERED)) {
		return false;
	}

	/* Check for the referral. */

	if (!(cli_ipc = cli_cm_open(ctx, rootcli,
					rootcli->desthost,
					"IPC$", false,
					(rootcli->trans_enc_state != NULL)))) {
		return false;
	}

	if (!cli_dfs_get_referral(ctx, cli_ipc, dfs_path, &refs,
			&num_refs, &consumed) || !num_refs) {
		return false;
	}

	/* Just store the first referral for now. */

	if (!refs[0].dfspath) {
		return false;
	}
	split_dfs_path(ctx, refs[0].dfspath, &server, &share, &extrapath );

	if (!server || !share) {
		return false;
	}

	/* Make sure to recreate the original string including any wildcards. */

	dfs_path = cli_dfs_make_full_path(ctx, rootcli, path);
	if (!dfs_path) {
		return false;
	}
	pathlen = strlen(dfs_path)*2;
	consumed = MIN(pathlen, consumed);
	*pp_targetpath = talloc_strdup(ctx, &dfs_path[consumed/2]);
	if (!*pp_targetpath) {
		return false;
	}
	dfs_path[consumed/2] = '\0';

	/*
 	 * *pp_targetpath is now the unconsumed part of the path.
 	 * dfs_path is now the consumed part of the path
	 * (in \server\share\path format).
 	 */

	/* Open the connection to the target server & share */
	if ((*targetcli = cli_cm_open(ctx, rootcli,
					server,
					share,
					false,
					(rootcli->trans_enc_state != NULL))) == NULL) {
		d_printf("Unable to follow dfs referral [\\%s\\%s]\n",
			server, share );
		return false;
	}

	if (extrapath && strlen(extrapath) > 0) {
		*pp_targetpath = talloc_asprintf(ctx,
						"%s%s",
						extrapath,
						*pp_targetpath);
		if (!*pp_targetpath) {
			return false;
		}
	}

	/* parse out the consumed mount path */
	/* trim off the \server\share\ */

	ppath = dfs_path;

	if (*ppath != '\\') {
		d_printf("cli_resolve_path: "
			"dfs_path (%s) not in correct format.\n",
			dfs_path );
		return false;
	}

	ppath++; /* Now pointing at start of server name. */

	if ((ppath = strchr_m( dfs_path, '\\' )) == NULL) {
		return false;
	}

	ppath++; /* Now pointing at start of share name. */

	if ((ppath = strchr_m( ppath+1, '\\' )) == NULL) {
		return false;
	}

	ppath++; /* Now pointing at path component. */

	newmount = talloc_asprintf(ctx, "%s\\%s", mountpt, ppath );
	if (!newmount) {
		return false;
	}

	cli_cm_set_mntpoint(*targetcli, newmount);

	/* Check for another dfs referral, note that we are not
	   checking for loops here. */

	if (!strequal(*pp_targetpath, "\\") && !strequal(*pp_targetpath, "/")) {
		if (cli_resolve_path(ctx,
					newmount,
					*targetcli,
					*pp_targetpath,
					&newcli,
					&newpath)) {
			/*
			 * When cli_resolve_path returns true here it's always
 			 * returning the complete path in newpath, so we're done
 			 * here.
 			 */
			*targetcli = newcli;
			*pp_targetpath = newpath;
			return true;
		}
	}

  done:

	/* If returning true ensure we return a dfs root full path. */
	if ((*targetcli)->dfsroot) {
		dfs_path = talloc_strdup(ctx, *pp_targetpath);
		if (!dfs_path) {
			return false;
		}
		*pp_targetpath = cli_dfs_make_full_path(ctx, *targetcli, dfs_path);
	}

	return true;
}

/********************************************************************
********************************************************************/

static bool cli_check_msdfs_proxy(TALLOC_CTX *ctx,
				struct cli_state *cli,
				const char *sharename,
				char **pp_newserver,
				char **pp_newshare,
				bool force_encrypt,
				const char *username,
				const char *password,
				const char *domain)
{
	CLIENT_DFS_REFERRAL *refs = NULL;
	size_t num_refs = 0;
	uint16 consumed;
	char *fullpath = NULL;
	bool res;
	uint16 cnum;
	char *newextrapath = NULL;

	if (!cli || !sharename) {
		return false;
	}

	cnum = cli->cnum;

	/* special case.  never check for a referral on the IPC$ share */

	if (strequal(sharename, "IPC$")) {
		return false;
	}

	/* send a trans2_query_path_info to check for a referral */

	fullpath = talloc_asprintf(ctx, "\\%s\\%s", cli->desthost, sharename );
	if (!fullpath) {
		return false;
	}

	/* check for the referral */

	if (!cli_send_tconX(cli, "IPC$", "IPC", NULL, 0)) {
		return false;
	}

	if (force_encrypt) {
		NTSTATUS status = cli_cm_force_encryption(cli,
					username,
					password,
					lp_workgroup(),
					"IPC$");
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	res = cli_dfs_get_referral(ctx, cli, fullpath, &refs, &num_refs, &consumed);

	if (!cli_tdis(cli)) {
		return false;
	}

	cli->cnum = cnum;

	if (!res || !num_refs) {
		return false;
	}

	if (!refs[0].dfspath) {
		return false;
	}

	split_dfs_path(ctx, refs[0].dfspath, pp_newserver,
			pp_newshare, &newextrapath );

	if ((*pp_newserver == NULL) || (*pp_newshare == NULL)) {
		return false;
	}

	/* check that this is not a self-referral */

	if (strequal(cli->desthost, *pp_newserver) &&
			strequal(sharename, *pp_newshare)) {
		return false;
	}

	return true;
}
