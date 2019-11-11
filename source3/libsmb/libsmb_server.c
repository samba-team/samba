/*
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002
   Copyright (C) Derrell Lipman 2003-2008
   Copyright (C) Jeremy Allison 2007, 2008
   Copyright (C) SATOH Fumiyasu <fumiyas@osstech.co.jp> 2009.

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
#include "libsmb/libsmb.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_lsarpc.h"
#include "libcli/security/security.h"
#include "libsmb/nmblib.h"
#include "../libcli/smb/smbXcli_base.h"

/*
 * Check a server for being alive and well.
 * returns 0 if the server is in shape. Returns 1 on error
 *
 * Also useable outside libsmbclient to enable external cache
 * to do some checks too.
 */
int
SMBC_check_server(SMBCCTX * context,
                  SMBCSRV * server)
{
	time_t now;

	if (!cli_state_is_connected(server->cli)) {
		return 1;
	}

	now = time_mono(NULL);

	if (server->last_echo_time == (time_t)0 ||
			now > server->last_echo_time +
				(server->cli->timeout/1000)) {
		unsigned char data[16] = {0};
		NTSTATUS status = cli_echo(server->cli,
					1,
					data_blob_const(data, sizeof(data)));
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Some NetApp servers return
			 * NT_STATUS_INVALID_PARAMETER.That's OK, they still
			 * replied.
			 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13007
			 */
			if (!NT_STATUS_EQUAL(status,
					NT_STATUS_INVALID_PARAMETER)) {
				return 1;
			}
		}
		server->last_echo_time = now;
	}
	return 0;
}

/*
 * Remove a server from the cached server list it's unused.
 * On success, 0 is returned. 1 is returned if the server could not be removed.
 *
 * Also useable outside libsmbclient
 */
int
SMBC_remove_unused_server(SMBCCTX * context,
                          SMBCSRV * srv)
{
	SMBCFILE * file;

	/* are we being fooled ? */
	if (!context || !context->internal->initialized || !srv) {
                return 1;
        }

	/* Check all open files/directories for a relation with this server */
	for (file = context->internal->files; file; file = file->next) {
		if (file->srv == srv) {
			/* Still used */
			DEBUG(3, ("smbc_remove_usused_server: "
                                  "%p still used by %p.\n",
				  srv, file));
			return 1;
		}
	}

	DLIST_REMOVE(context->internal->servers, srv);

	cli_shutdown(srv->cli);
	srv->cli = NULL;

	DEBUG(3, ("smbc_remove_usused_server: %p removed.\n", srv));

	smbc_getFunctionRemoveCachedServer(context)(context, srv);

        SAFE_FREE(srv);
	return 0;
}

/****************************************************************
 * Call the auth_fn with fixed size (fstring) buffers.
 ***************************************************************/
static void
SMBC_call_auth_fn(TALLOC_CTX *ctx,
                  SMBCCTX *context,
                  const char *server,
                  const char *share,
                  char **pp_workgroup,
                  char **pp_username,
                  char **pp_password)
{
	fstring workgroup = { 0 };
	fstring username = { 0 };
	fstring password = { 0 };
        smbc_get_auth_data_with_context_fn auth_with_context_fn;

	if (*pp_workgroup != NULL) {
		strlcpy(workgroup, *pp_workgroup, sizeof(workgroup));
	}
	if (*pp_username != NULL) {
		strlcpy(username, *pp_username, sizeof(username));
	}
	if (*pp_password != NULL) {
		strlcpy(password, *pp_password, sizeof(password));
	}

        /* See if there's an authentication with context function provided */
        auth_with_context_fn = smbc_getFunctionAuthDataWithContext(context);
        if (auth_with_context_fn)
        {
            (* auth_with_context_fn)(context,
                                     server, share,
                                     workgroup, sizeof(workgroup),
                                     username, sizeof(username),
                                     password, sizeof(password));
        }
        else
        {
            smbc_getFunctionAuthData(context)(server, share,
                                              workgroup, sizeof(workgroup),
                                              username, sizeof(username),
                                              password, sizeof(password));
        }

	TALLOC_FREE(*pp_workgroup);
	TALLOC_FREE(*pp_username);
	TALLOC_FREE(*pp_password);

	*pp_workgroup = talloc_strdup(ctx, workgroup);
	*pp_username = talloc_strdup(ctx, username);
	*pp_password = talloc_strdup(ctx, password);
}


void
SMBC_get_auth_data(const char *server, const char *share,
                   char *workgroup_buf, int workgroup_buf_len,
                   char *username_buf, int username_buf_len,
                   char *password_buf, int password_buf_len)
{
        /* Default function just uses provided data.  Nothing to do. */
}



SMBCSRV *
SMBC_find_server(TALLOC_CTX *ctx,
                 SMBCCTX *context,
                 const char *server,
                 const char *share,
                 char **pp_workgroup,
                 char **pp_username,
                 char **pp_password)
{
        SMBCSRV *srv;
        int auth_called = 0;

        if (!pp_workgroup || !pp_username || !pp_password) {
                return NULL;
        }

check_server_cache:

	srv = smbc_getFunctionGetCachedServer(context)(context,
                                                       server, share,
                                                       *pp_workgroup,
                                                       *pp_username);

	if (!auth_called && !srv && (!*pp_username || !(*pp_username)[0] ||
                                     !*pp_password || !(*pp_password)[0])) {
		SMBC_call_auth_fn(ctx, context, server, share,
                                  pp_workgroup, pp_username, pp_password);

		/*
                 * However, smbc_auth_fn may have picked up info relating to
                 * an existing connection, so try for an existing connection
                 * again ...
                 */
		auth_called = 1;
		goto check_server_cache;

	}

	if (srv) {
		if (smbc_getFunctionCheckServer(context)(context, srv)) {
			/*
                         * This server is no good anymore
                         * Try to remove it and check for more possible
                         * servers in the cache
                         */
			if (smbc_getFunctionRemoveUnusedServer(context)(context,
                                                                        srv)) {
                                /*
                                 * We could not remove the server completely,
                                 * remove it from the cache so we will not get
                                 * it again. It will be removed when the last
                                 * file/dir is closed.
                                 */
				smbc_getFunctionRemoveCachedServer(context)(context,
                                                                            srv);
			}

			/*
                         * Maybe there are more cached connections to this
                         * server
                         */
			goto check_server_cache;
		}

		return srv;
 	}

        return NULL;
}

static struct cli_credentials *SMBC_auth_credentials(TALLOC_CTX *mem_ctx,
						     SMBCCTX *context,
						     const char *domain,
						     const char *username,
						     const char *password)
{
	struct cli_credentials *creds = NULL;
	bool use_kerberos = false;
	bool fallback_after_kerberos = false;
	bool use_ccache = false;
	bool pw_nt_hash = false;

	use_kerberos = smbc_getOptionUseKerberos(context);
	fallback_after_kerberos = smbc_getOptionFallbackAfterKerberos(context);
	use_ccache = smbc_getOptionUseCCache(context);
	pw_nt_hash = smbc_getOptionUseNTHash(context);

	creds = cli_session_creds_init(mem_ctx,
				       username,
				       domain,
				       NULL, /* realm */
				       password,
				       use_kerberos,
				       fallback_after_kerberos,
				       use_ccache,
				       pw_nt_hash);
	if (creds == NULL) {
		return NULL;
	}

	return creds;
}

/*
 * Connect to a server, possibly on an existing connection
 *
 * Here, what we want to do is: If the server and username
 * match an existing connection, reuse that, otherwise, establish a
 * new connection.
 *
 * If we have to create a new connection, call the auth_fn to get the
 * info we need, unless the username and password were passed in.
 */

static SMBCSRV *
SMBC_server_internal(TALLOC_CTX *ctx,
            SMBCCTX *context,
            bool connect_if_not_found,
            const char *server,
            uint16_t port,
            const char *share,
            char **pp_workgroup,
            char **pp_username,
            char **pp_password,
	    bool *in_cache)
{
	SMBCSRV *srv=NULL;
	char *workgroup = NULL;
	struct cli_state *c = NULL;
	const char *server_n = server;
        int is_ipc = (share != NULL && strcmp(share, "IPC$") == 0);
	uint32_t fs_attrs = 0;
	const char *username_used = NULL;
	const char *password_used = NULL;
 	NTSTATUS status;
	char *newserver, *newshare;
	int flags = 0;
	struct smbXcli_tcon *tcon = NULL;
	int signing_state = SMB_SIGNING_DEFAULT;
	struct cli_credentials *creds = NULL;

	*in_cache = false;

	if (server[0] == 0) {
		errno = EPERM;
		return NULL;
	}

        /* Look for a cached connection */
        srv = SMBC_find_server(ctx, context, server, share,
                               pp_workgroup, pp_username, pp_password);

        /*
         * If we found a connection and we're only allowed one share per
         * server...
         */
        if (srv &&
	    share != NULL && *share != '\0' &&
            smbc_getOptionOneSharePerServer(context)) {

                /*
                 * ... then if there's no current connection to the share,
                 * connect to it.  SMBC_find_server(), or rather the function
                 * pointed to by context->get_cached_srv_fn which
                 * was called by SMBC_find_server(), will have issued a tree
                 * disconnect if the requested share is not the same as the
                 * one that was already connected.
                 */

		/*
		 * Use srv->cli->desthost and srv->cli->share instead of
		 * server and share below to connect to the actual share,
		 * i.e., a normal share or a referred share from
		 * 'msdfs proxy' share.
		 */
                if (!cli_state_has_tcon(srv->cli)) {
                        /* Ensure we have accurate auth info */
			SMBC_call_auth_fn(ctx, context,
					  smbXcli_conn_remote_name(srv->cli->conn),
					  srv->cli->share,
                                          pp_workgroup,
                                          pp_username,
                                          pp_password);

			if (!*pp_workgroup || !*pp_username || !*pp_password) {
				errno = ENOMEM;
				cli_shutdown(srv->cli);
				srv->cli = NULL;
				smbc_getFunctionRemoveCachedServer(context)(context,
                                                                            srv);
				return NULL;
			}

			/*
			 * We don't need to renegotiate encryption
			 * here as the encryption context is not per
			 * tid.
			 */

			status = cli_tree_connect(srv->cli,
						  srv->cli->share,
						  "?????",
						  *pp_password);
			if (!NT_STATUS_IS_OK(status)) {
                                cli_shutdown(srv->cli);
                                errno = map_errno_from_nt_status(status);
				srv->cli = NULL;
                                smbc_getFunctionRemoveCachedServer(context)(context,
                                                                            srv);
                                srv = NULL;
				goto not_found;
                        }

                        /* Determine if this share supports case sensitivity */
                        if (is_ipc) {
                                DEBUG(4,
                                      ("IPC$ so ignore case sensitivity\n"));
                                status = NT_STATUS_OK;
                        } else {
                                status = cli_get_fs_attr_info(srv->cli, &fs_attrs);
                        }

                        if (!NT_STATUS_IS_OK(status)) {
                                DEBUG(4, ("Could not retrieve "
                                          "case sensitivity flag: %s.\n",
                                          nt_errstr(status)));

                                /*
                                 * We can't determine the case sensitivity of
                                 * the share. We have no choice but to use the
                                 * user-specified case sensitivity setting.
                                 */
                                if (smbc_getOptionCaseSensitive(context)) {
                                        cli_set_case_sensitive(srv->cli, true);
                                } else {
                                        cli_set_case_sensitive(srv->cli, false);
                                }
                        } else if (!is_ipc) {
                                DEBUG(4,
                                      ("Case sensitive: %s\n",
                                       (fs_attrs & FILE_CASE_SENSITIVE_SEARCH
                                        ? "True"
                                        : "False")));
                                cli_set_case_sensitive(
                                        srv->cli,
                                        (fs_attrs & FILE_CASE_SENSITIVE_SEARCH
                                         ? True
                                         : False));
                        }

                        /*
                         * Regenerate the dev value since it's based on both
                         * server and share
                         */
                        if (srv) {
				const char *remote_name =
					smbXcli_conn_remote_name(srv->cli->conn);

				srv->dev = (dev_t)(str_checksum(remote_name) ^
                                                   str_checksum(srv->cli->share));
                        }
                }
        }

 not_found:

        /* If we have a connection... */
        if (srv) {

                /* ... then we're done here.  Give 'em what they came for. */
		*in_cache = true;
                goto done;
        }

        /* If we're not asked to connect when a connection doesn't exist... */
        if (! connect_if_not_found) {
                /* ... then we're done here. */
                return NULL;
        }

	if (!*pp_workgroup || !*pp_username || !*pp_password) {
		errno = ENOMEM;
		return NULL;
	}

	DEBUG(4,("SMBC_server: server_n=[%s] server=[%s]\n", server_n, server));

	DEBUG(4,(" -> server_n=[%s] server=[%s]\n", server_n, server));

	status = NT_STATUS_UNSUCCESSFUL;

	if (context->internal->smb_encryption_level != SMBC_ENCRYPTLEVEL_NONE) {
		signing_state = SMB_SIGNING_REQUIRED;
	}

	if (port == 0) {
	        if (share == NULL || *share == '\0' || is_ipc) {
			/*
			 * Try 139 first for IPC$
			 */
			status = cli_connect_nb(server_n, NULL, NBT_SMB_PORT, 0x20,
					smbc_getNetbiosName(context),
					signing_state, flags, &c);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * No IPC$ or 139 did not work
		 */
		status = cli_connect_nb(server_n, NULL, port, 0x20,
					smbc_getNetbiosName(context),
					signing_state, flags, &c);
	}

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			DBG_ERR("NetBIOS support disabled, unable to connect");
		}

		errno = map_errno_from_nt_status(status);
		return NULL;
	}

	cli_set_timeout(c, smbc_getTimeout(context));

	status = smbXcli_negprot(c->conn, c->timeout,
				 lp_client_min_protocol(),
				 lp_client_max_protocol());
	if (!NT_STATUS_IS_OK(status)) {
		cli_shutdown(c);
		errno = map_errno_from_nt_status(status);
		return NULL;
	}

	if (smbXcli_conn_protocol(c->conn) >= PROTOCOL_SMB2_02) {
		/* Ensure we ask for some initial credits. */
		smb2cli_conn_set_max_credits(c->conn, DEFAULT_SMB2_MAX_CREDITS);
	}

	username_used = *pp_username;
	password_used = *pp_password;

	creds = SMBC_auth_credentials(c,
				      context,
				      *pp_workgroup,
				      username_used,
				      password_used);
	if (creds == NULL) {
		cli_shutdown(c);
		errno = ENOMEM;
		return NULL;
	}

	status = cli_session_setup_creds(c, creds);
	if (!NT_STATUS_IS_OK(status)) {

                /* Failed.  Try an anonymous login, if allowed by flags. */
		username_used = "";
		password_used = "";

                if (smbc_getOptionNoAutoAnonymousLogin(context) ||
		    !NT_STATUS_IS_OK(cli_session_setup_anon(c))) {

                        cli_shutdown(c);
                        errno = EPERM;
                        return NULL;
                }
	}

	DEBUG(4,(" session setup ok\n"));

	/* here's the fun part....to support 'msdfs proxy' shares
	   (on Samba or windows) we have to issues a TRANS_GET_DFS_REFERRAL
	   here before trying to connect to the original share.
	   cli_check_msdfs_proxy() will fail if it is a normal share. */

	if (smbXcli_conn_dfs_supported(c->conn) &&
			cli_check_msdfs_proxy(ctx, c, share,
				&newserver, &newshare,
				/* FIXME: cli_check_msdfs_proxy() does
				   not support smbc_smb_encrypt_level type */
				context->internal->smb_encryption_level ?
					true : false,
				creds)) {
		cli_shutdown(c);
		srv = SMBC_server_internal(ctx, context, connect_if_not_found,
				newserver, port, newshare, pp_workgroup,
				pp_username, pp_password, in_cache);
		TALLOC_FREE(newserver);
		TALLOC_FREE(newshare);
		return srv;
	}

	/* must be a normal share */

	status = cli_tree_connect_creds(c, share, "?????", creds);
	if (!NT_STATUS_IS_OK(status)) {
		cli_shutdown(c);
		errno = map_errno_from_nt_status(status);
		return NULL;
	}

	DEBUG(4,(" tconx ok\n"));

	if (smbXcli_conn_protocol(c->conn) >= PROTOCOL_SMB2_02) {
		tcon = c->smb2.tcon;
	} else {
		tcon = c->smb1.tcon;
	}

        /* Determine if this share supports case sensitivity */
	if (is_ipc) {
                DEBUG(4, ("IPC$ so ignore case sensitivity\n"));
                status = NT_STATUS_OK;
        } else {
                status = cli_get_fs_attr_info(c, &fs_attrs);
        }

        if (!NT_STATUS_IS_OK(status)) {
                DEBUG(4, ("Could not retrieve case sensitivity flag: %s.\n",
                          nt_errstr(status)));

                /*
                 * We can't determine the case sensitivity of the share. We
                 * have no choice but to use the user-specified case
                 * sensitivity setting.
                 */
                if (smbc_getOptionCaseSensitive(context)) {
                        cli_set_case_sensitive(c, True);
                } else {
                        cli_set_case_sensitive(c, False);
                }
	} else if (!is_ipc) {
                DEBUG(4, ("Case sensitive: %s\n",
                          (fs_attrs & FILE_CASE_SENSITIVE_SEARCH
                           ? "True"
                           : "False")));
		smbXcli_tcon_set_fs_attributes(tcon, fs_attrs);
        }

	if (context->internal->smb_encryption_level) {
		/* Attempt encryption. */
		status = cli_cm_force_encryption_creds(c,
						       creds,
						       share);
		if (!NT_STATUS_IS_OK(status)) {

			/*
			 * context->smb_encryption_level == 1
			 * means don't fail if encryption can't be negotiated,
			 * == 2 means fail if encryption can't be negotiated.
			 */

			DEBUG(4,(" SMB encrypt failed\n"));

			if (context->internal->smb_encryption_level == 2) {
	                        cli_shutdown(c);
				errno = EPERM;
				return NULL;
			}
		}
		DEBUG(4,(" SMB encrypt ok\n"));
	}

	/*
	 * Ok, we have got a nice connection
	 * Let's allocate a server structure.
	 */

	srv = SMB_MALLOC_P(SMBCSRV);
	if (!srv) {
		cli_shutdown(c);
		errno = ENOMEM;
		return NULL;
	}

	ZERO_STRUCTP(srv);
	DLIST_ADD(srv->cli, c);
	srv->dev = (dev_t)(str_checksum(server) ^ str_checksum(share));
        srv->no_pathinfo = False;
        srv->no_pathinfo2 = False;
	srv->no_pathinfo3 = False;
        srv->no_nt_session = False;

done:
	if (!pp_workgroup || !*pp_workgroup || !**pp_workgroup) {
		workgroup = talloc_strdup(ctx, smbc_getWorkgroup(context));
	} else {
		workgroup = *pp_workgroup;
	}
	if(!workgroup) {
		if (c != NULL) {
			cli_shutdown(c);
		}
		SAFE_FREE(srv);
		return NULL;
	}

	/* set the credentials to make DFS work */
	smbc_set_credentials_with_fallback(context,
					   workgroup,
				    	   *pp_username,
				   	   *pp_password);

	return srv;
}

SMBCSRV *
SMBC_server(TALLOC_CTX *ctx,
		SMBCCTX *context,
		bool connect_if_not_found,
		const char *server,
		uint16_t port,
		const char *share,
		char **pp_workgroup,
		char **pp_username,
		char **pp_password)
{
	SMBCSRV *srv=NULL;
	bool in_cache = false;

	srv = SMBC_server_internal(ctx, context, connect_if_not_found,
			server, port, share, pp_workgroup,
			pp_username, pp_password, &in_cache);

	if (!srv) {
		return NULL;
	}
	if (in_cache) {
		return srv;
	}

	/* Now add it to the cache (internal or external)  */
	/* Let the cache function set errno if it wants to */
	errno = 0;
	if (smbc_getFunctionAddCachedServer(context)(context, srv,
						server, share,
						*pp_workgroup,
						*pp_username)) {
		int saved_errno = errno;
		DEBUG(3, (" Failed to add server to cache\n"));
		errno = saved_errno;
		if (errno == 0) {
			errno = ENOMEM;
		}
		SAFE_FREE(srv);
		return NULL;
	}

	DEBUG(2, ("Server connect ok: //%s/%s: %p\n",
		server, share, srv));

	DLIST_ADD(context->internal->servers, srv);
	return srv;
}

/*
 * Connect to a server for getting/setting attributes, possibly on an existing
 * connection.  This works similarly to SMBC_server().
 */
SMBCSRV *
SMBC_attr_server(TALLOC_CTX *ctx,
                 SMBCCTX *context,
                 const char *server,
                 uint16_t port,
                 const char *share,
                 char **pp_workgroup,
                 char **pp_username,
                 char **pp_password)
{
        int flags;
	struct cli_state *ipc_cli = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
        NTSTATUS nt_status;
	SMBCSRV *srv=NULL;
	SMBCSRV *ipc_srv=NULL;

	/*
	 * Use srv->cli->desthost and srv->cli->share instead of
	 * server and share below to connect to the actual share,
	 * i.e., a normal share or a referred share from
	 * 'msdfs proxy' share.
	 */
	srv = SMBC_server(ctx, context, true, server, port, share,
			pp_workgroup, pp_username, pp_password);
	if (!srv) {
		return NULL;
	}
	server = smbXcli_conn_remote_name(srv->cli->conn);
	share = srv->cli->share;

        /*
         * See if we've already created this special connection.  Reference
         * our "special" share name '*IPC$', which is an impossible real share
         * name due to the leading asterisk.
         */
        ipc_srv = SMBC_find_server(ctx, context, server, "*IPC$",
                                   pp_workgroup, pp_username, pp_password);
        if (!ipc_srv) {
		struct cli_credentials *creds = NULL;
		int signing_state = SMB_SIGNING_DEFAULT;

                /* We didn't find a cached connection.  Get the password */
		if (!*pp_password || (*pp_password)[0] == '\0') {
                        /* ... then retrieve it now. */
			SMBC_call_auth_fn(ctx, context, server, share,
                                          pp_workgroup,
                                          pp_username,
                                          pp_password);
			if (!*pp_workgroup || !*pp_username || !*pp_password) {
				errno = ENOMEM;
				return NULL;
			}
                }

                flags = 0;

		creds = SMBC_auth_credentials(NULL,
					      context,
					      *pp_workgroup,
					      *pp_username,
					      *pp_password);
		if (creds == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		if (context->internal->smb_encryption_level != SMBC_ENCRYPTLEVEL_NONE) {
			signing_state = SMB_SIGNING_REQUIRED;
		}

		nt_status = cli_full_connection_creds(&ipc_cli,
						lp_netbios_name(), server,
						NULL, 0, "IPC$", "?????",
						creds,
						flags,
						signing_state);
                if (! NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(creds);
                        DEBUG(1,("cli_full_connection failed! (%s)\n",
                                 nt_errstr(nt_status)));
                        errno = ENOTSUP;
                        return NULL;
                }
		talloc_steal(ipc_cli, creds);

		if (context->internal->smb_encryption_level) {
			/* Attempt encryption. */
			nt_status = cli_cm_force_encryption_creds(ipc_cli,
								  creds,
								  "IPC$");
			if (!NT_STATUS_IS_OK(nt_status)) {

				/*
				 * context->smb_encryption_level ==
				 * 1 means don't fail if encryption can't be
				 * negotiated, == 2 means fail if encryption
				 * can't be negotiated.
				 */

				DEBUG(4,(" SMB encrypt failed on IPC$\n"));

				if (context->internal->smb_encryption_level == 2) {
		                        cli_shutdown(ipc_cli);
					errno = EPERM;
					return NULL;
				}
			}
			DEBUG(4,(" SMB encrypt ok on IPC$\n"));
		}

                ipc_srv = SMB_MALLOC_P(SMBCSRV);
                if (!ipc_srv) {
                        errno = ENOMEM;
                        cli_shutdown(ipc_cli);
                        return NULL;
                }

                ZERO_STRUCTP(ipc_srv);
                DLIST_ADD(ipc_srv->cli, ipc_cli);

                nt_status = cli_rpc_pipe_open_noauth(
			ipc_srv->cli, &ndr_table_lsarpc, &pipe_hnd);
                if (!NT_STATUS_IS_OK(nt_status)) {
                        DEBUG(1, ("cli_nt_session_open fail!\n"));
                        errno = ENOTSUP;
                        cli_shutdown(ipc_srv->cli);
                        free(ipc_srv);
                        return NULL;
                }

                /*
                 * Some systems don't support
                 * SEC_FLAG_MAXIMUM_ALLOWED, but NT sends 0x2000000
                 * so we might as well do it too.
                 */

                nt_status = rpccli_lsa_open_policy(
                        pipe_hnd,
                        talloc_tos(),
                        True,
                        GENERIC_EXECUTE_ACCESS,
                        &ipc_srv->pol);

                if (!NT_STATUS_IS_OK(nt_status)) {
                        errno = SMBC_errno(context, ipc_srv->cli);
                        cli_shutdown(ipc_srv->cli);
                        free(ipc_srv);
                        return NULL;
                }

                /* now add it to the cache (internal or external) */

                errno = 0;      /* let cache function set errno if it likes */
                if (smbc_getFunctionAddCachedServer(context)(context, ipc_srv,
                                                             server,
                                                             "*IPC$",
                                                             *pp_workgroup,
                                                             *pp_username)) {
                        DEBUG(3, (" Failed to add server to cache\n"));
                        if (errno == 0) {
                                errno = ENOMEM;
                        }
                        cli_shutdown(ipc_srv->cli);
                        free(ipc_srv);
                        return NULL;
                }

                DLIST_ADD(context->internal->servers, ipc_srv);
        }

        return ipc_srv;
}
