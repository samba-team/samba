/*
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002
   Copyright (C) Derrell Lipman 2003-2008
   Copyright (C) Jeremy Allison 2007, 2008

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
#include "libsmb/namequery.h"
#include "libsmb/libsmb.h"
#include "auth_info.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_srvsvc_c.h"
#include "libsmb/nmblib.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../libcli/security/security.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/time_basic.h"

/*
 * Routine to open a directory
 * We accept the URL syntax explained in SMBC_parse_path(), above.
 */

static void remove_dirplus(SMBCFILE *dir)
{
	struct smbc_dirplus_list *d = NULL;

	d = dir->dirplus_list;
	while (d != NULL) {
		struct smbc_dirplus_list *f = d;
		d = d->next;

		SAFE_FREE(f->smb_finfo->short_name);
		SAFE_FREE(f->smb_finfo->name);
		SAFE_FREE(f->smb_finfo);
		SAFE_FREE(f);
	}

	dir->dirplus_list = NULL;
	dir->dirplus_end = NULL;
	dir->dirplus_next = NULL;
}

static void
remove_dir(SMBCFILE *dir)
{
	struct smbc_dir_list *d,*f;

	d = dir->dir_list;
	while (d) {

		f = d; d = d->next;

		SAFE_FREE(f->dirent);
		SAFE_FREE(f);

	}

	dir->dir_list = dir->dir_end = dir->dir_next = NULL;

}

static int
add_dirent(SMBCFILE *dir,
           const char *name,
           const char *comment,
           uint32_t type)
{
	struct smbc_dirent *dirent;
	int size;
        int name_length = (name == NULL ? 0 : strlen(name));
        int comment_len = (comment == NULL ? 0 : strlen(comment));

	/*
	 * Allocate space for the dirent, which must be increased by the
	 * size of the name and the comment and 1 each for the null terminator.
	 */

	size = sizeof(struct smbc_dirent) + name_length + comment_len + 2;

	dirent = (struct smbc_dirent *)SMB_MALLOC(size);

	if (!dirent) {

		dir->dir_error = ENOMEM;
		return -1;

	}

	ZERO_STRUCTP(dirent);

	if (dir->dir_list == NULL) {

		dir->dir_list = SMB_MALLOC_P(struct smbc_dir_list);
		if (!dir->dir_list) {

			SAFE_FREE(dirent);
			dir->dir_error = ENOMEM;
			return -1;

		}
		ZERO_STRUCTP(dir->dir_list);

		dir->dir_end = dir->dir_next = dir->dir_list;
	}
	else {

		dir->dir_end->next = SMB_MALLOC_P(struct smbc_dir_list);

		if (!dir->dir_end->next) {

			SAFE_FREE(dirent);
			dir->dir_error = ENOMEM;
			return -1;

		}
		ZERO_STRUCTP(dir->dir_end->next);

		dir->dir_end = dir->dir_end->next;
	}

	dir->dir_end->next = NULL;
	dir->dir_end->dirent = dirent;

	dirent->smbc_type = type;
	dirent->namelen = name_length;
	dirent->commentlen = comment_len;
	dirent->dirlen = size;

        /*
         * dirent->namelen + 1 includes the null (no null termination needed)
         * Ditto for dirent->commentlen.
         * The space for the two null bytes was allocated.
         */
	strncpy(dirent->name, (name?name:""), dirent->namelen + 1);
	dirent->comment = (char *)(&dirent->name + dirent->namelen + 1);
	strncpy(dirent->comment, (comment?comment:""), dirent->commentlen + 1);

	return 0;

}

static int add_dirplus(SMBCFILE *dir, struct file_info *finfo)
{
	struct smbc_dirplus_list *new_entry = NULL;
	struct libsmb_file_info *info = NULL;

	new_entry = SMB_MALLOC_P(struct smbc_dirplus_list);
	if (new_entry == NULL) {
		dir->dir_error = ENOMEM;
		return -1;
	}
	ZERO_STRUCTP(new_entry);
	new_entry->ino = finfo->ino;

	info = SMB_MALLOC_P(struct libsmb_file_info);
	if (info == NULL) {
		SAFE_FREE(new_entry);
		dir->dir_error = ENOMEM;
		return -1;
	}

	ZERO_STRUCTP(info);

	info->btime_ts = finfo->btime_ts;
	info->atime_ts = finfo->atime_ts;
	info->ctime_ts = finfo->ctime_ts;
	info->mtime_ts = finfo->mtime_ts;
	info->gid = finfo->gid;
	info->attrs = finfo->attr;
	info->size = finfo->size;
	info->uid = finfo->uid;
	info->name = SMB_STRDUP(finfo->name);
	if (info->name == NULL) {
		SAFE_FREE(info);
		SAFE_FREE(new_entry);
		dir->dir_error = ENOMEM;
		return -1;
	}

	if (finfo->short_name) {
		info->short_name = SMB_STRDUP(finfo->short_name);
	} else {
		info->short_name = SMB_STRDUP("");
	}

	if (info->short_name == NULL) {
		SAFE_FREE(info->name);
		SAFE_FREE(info);
		SAFE_FREE(new_entry);
		dir->dir_error = ENOMEM;
		return -1;
	}
	new_entry->smb_finfo = info;

	/* Now add to the list. */
	if (dir->dirplus_list == NULL) {
		/* Empty list - point everything at new_entry. */
		dir->dirplus_list = new_entry;
		dir->dirplus_end = new_entry;
		dir->dirplus_next = new_entry;
	} else {
		/* Append to list but leave the ->next cursor alone. */
		dir->dirplus_end->next = new_entry;
		dir->dirplus_end = new_entry;
	}

	return 0;
}

static void
list_unique_wg_fn(const char *name,
                  uint32_t type,
                  const char *comment,
                  void *state)
{
	SMBCFILE *dir = (SMBCFILE *)state;
        struct smbc_dir_list *dir_list;
        struct smbc_dirent *dirent;
	int dirent_type;
        int do_remove = 0;

	dirent_type = dir->dir_type;

	if (add_dirent(dir, name, comment, dirent_type) < 0) {
		/* An error occurred, what do we do? */
		/* FIXME: Add some code here */
		/* Change cli_NetServerEnum to take a fn
		   returning NTSTATUS... JRA. */
	}

        /* Point to the one just added */
        dirent = dir->dir_end->dirent;

        /* See if this was a duplicate */
        for (dir_list = dir->dir_list;
             dir_list != dir->dir_end;
             dir_list = dir_list->next) {
                if (! do_remove &&
                    strcmp(dir_list->dirent->name, dirent->name) == 0) {
                        /* Duplicate.  End end of list need to be removed. */
                        do_remove = 1;
                }

                if (do_remove && dir_list->next == dir->dir_end) {
                        /* Found the end of the list.  Remove it. */
                        dir->dir_end = dir_list;
                        free(dir_list->next);
                        free(dirent);
                        dir_list->next = NULL;
                        break;
                }
        }
}

static void
list_fn(const char *name,
        uint32_t type,
        const char *comment,
        void *state)
{
	SMBCFILE *dir = (SMBCFILE *)state;
	int dirent_type;

	/*
         * We need to process the type a little ...
         *
         * Disk share     = 0x00000000
         * Print share    = 0x00000001
         * Comms share    = 0x00000002 (obsolete?)
         * IPC$ share     = 0x00000003
         *
         * administrative shares:
         * ADMIN$, IPC$, C$, D$, E$ ...  are type |= 0x80000000
         */

	if (dir->dir_type == SMBC_FILE_SHARE) {
		switch (type) {
                case 0 | 0x80000000:
		case 0:
			dirent_type = SMBC_FILE_SHARE;
			break;

		case 1:
			dirent_type = SMBC_PRINTER_SHARE;
			break;

		case 2:
			dirent_type = SMBC_COMMS_SHARE;
			break;

                case 3 | 0x80000000:
		case 3:
			dirent_type = SMBC_IPC_SHARE;
			break;

		default:
			dirent_type = SMBC_FILE_SHARE; /* FIXME, error? */
			break;
		}
	}
	else {
                dirent_type = dir->dir_type;
        }

	if (add_dirent(dir, name, comment, dirent_type) < 0) {
		/* An error occurred, what do we do? */
		/* FIXME: Add some code here */
		/* Change cli_NetServerEnum to take a fn
		   returning NTSTATUS... JRA. */
	}
}

static NTSTATUS
dir_list_fn(const char *mnt,
            struct file_info *finfo,
            const char *mask,
            void *state)
{
	SMBCFILE *dirp = (SMBCFILE *)state;
	int ret;

	if (add_dirent((SMBCFILE *)state, finfo->name, "",
		       (finfo->attr&FILE_ATTRIBUTE_DIRECTORY?SMBC_DIR:SMBC_FILE)) < 0) {
		SMBCFILE *dir = (SMBCFILE *)state;
		return map_nt_error_from_unix(dir->dir_error);
	}
	ret = add_dirplus(dirp, finfo);
	if (ret < 0) {
		return map_nt_error_from_unix(dirp->dir_error);
	}
	return NT_STATUS_OK;
}

static NTSTATUS
net_share_enum_rpc(struct cli_state *cli,
                   void (*fn)(const char *name,
                              uint32_t type,
                              const char *comment,
                              void *state),
                   void *state)
{
        uint32_t i;
	WERROR result;
	uint32_t preferred_len = 0xffffffff;
        uint32_t type;
	struct srvsvc_NetShareInfoCtr info_ctr;
	struct srvsvc_NetShareCtr1 ctr1;
	fstring name = "";
        fstring comment = "";
	struct rpc_pipe_client *pipe_hnd = NULL;
        NTSTATUS nt_status;
	uint32_t resume_handle = 0;
	uint32_t total_entries = 0;
	struct dcerpc_binding_handle *b;

        /* Open the server service pipe */
        nt_status = cli_rpc_pipe_open_noauth(cli, &ndr_table_srvsvc,
					     &pipe_hnd);
        if (!NT_STATUS_IS_OK(nt_status)) {
                DEBUG(1, ("net_share_enum_rpc pipe open fail!\n"));
		goto done;
        }

	ZERO_STRUCT(info_ctr);
	ZERO_STRUCT(ctr1);

	info_ctr.level = 1;
	info_ctr.ctr.ctr1 = &ctr1;

	b = pipe_hnd->binding_handle;

        /* Issue the NetShareEnum RPC call and retrieve the response */
	nt_status = dcerpc_srvsvc_NetShareEnumAll(b, talloc_tos(),
						  pipe_hnd->desthost,
						  &info_ctr,
						  preferred_len,
						  &total_entries,
						  &resume_handle,
						  &result);

        /* Was it successful? */
	if (!NT_STATUS_IS_OK(nt_status)) {
                /*  Nope.  Go clean up. */
		goto done;
	}

	if (!W_ERROR_IS_OK(result)) {
                /*  Nope.  Go clean up. */
		nt_status = werror_to_ntstatus(result);
		goto done;
        }

	if (total_entries == 0) {
                /*  Nope.  Go clean up. */
		nt_status = NT_STATUS_NOT_FOUND;
		goto done;
	}

        /* For each returned entry... */
        for (i = 0; i < info_ctr.ctr.ctr1->count; i++) {

                /* pull out the share name */
		fstrcpy(name, info_ctr.ctr.ctr1->array[i].name);

                /* pull out the share's comment */
		fstrcpy(comment, info_ctr.ctr.ctr1->array[i].comment);

                /* Get the type value */
                type = info_ctr.ctr.ctr1->array[i].type;

                /* Add this share to the list */
                (*fn)(name, type, comment, state);
        }

done:
        /* Close the server service pipe */
        TALLOC_FREE(pipe_hnd);

        /* Tell 'em if it worked */
        return nt_status;
}


/*
 * Verify that the options specified in a URL are valid
 */
int
SMBC_check_options(char *server,
                   char *share,
                   char *path,
                   char *options)
{
        DEBUG(4, ("SMBC_check_options(): server='%s' share='%s' "
                  "path='%s' options='%s'\n",
                  server, share, path, options));

        /* No options at all is always ok */
        if (! *options) return 0;

        /* Currently, we don't support any options. */
        return -1;
}


SMBCFILE *
SMBC_opendir_ctx(SMBCCTX *context,
                 const char *fname)
{
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *options = NULL;
	char *workgroup = NULL;
	char *path = NULL;
	size_t path_len = 0;
	uint16_t port = 0;
	SMBCSRV *srv  = NULL;
	SMBCFILE *dir = NULL;
	struct sockaddr_storage rem_ss;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
	        DEBUG(4, ("no valid context\n"));
		TALLOC_FREE(frame);
		errno = EINVAL + 8192;
		return NULL;

	}

	if (!fname) {
		DEBUG(4, ("no valid fname\n"));
		TALLOC_FREE(frame);
		errno = EINVAL + 8193;
		return NULL;
	}

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            &options)) {
	        DEBUG(4, ("no valid path\n"));
		TALLOC_FREE(frame);
		errno = EINVAL + 8194;
		return NULL;
	}

	DEBUG(4, ("parsed path: fname='%s' server='%s' share='%s' "
                  "path='%s' options='%s'\n",
                  fname, server, share, path, options));

        /* Ensure the options are valid */
        if (SMBC_check_options(server, share, path, options)) {
                DEBUG(4, ("unacceptable options (%s)\n", options));
		TALLOC_FREE(frame);
                errno = EINVAL + 8195;
                return NULL;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return NULL;
		}
	}

	dir = SMB_MALLOC_P(SMBCFILE);

	if (!dir) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}

	ZERO_STRUCTP(dir);

	dir->cli_fd   = 0;
	dir->fname    = SMB_STRDUP(fname);
	if (dir->fname == NULL) {
		SAFE_FREE(dir);
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}
	dir->srv      = NULL;
	dir->offset   = 0;
	dir->file     = False;
	dir->dir_list = dir->dir_next = dir->dir_end = NULL;

	if (server[0] == (char)0) {

                int i;
                int count;
                int max_lmb_count;
                struct sockaddr_storage *ip_list;
                struct sockaddr_storage server_addr;
                struct user_auth_info *u_info;
		NTSTATUS status;

		if (share[0] != (char)0 || path[0] != (char)0) {

			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			TALLOC_FREE(frame);
			errno = EINVAL + 8196;
			return NULL;
		}

                /* Determine how many local master browsers to query */
                max_lmb_count = (smbc_getOptionBrowseMaxLmbCount(context) == 0
                                 ? INT_MAX
                                 : smbc_getOptionBrowseMaxLmbCount(context));

		u_info = user_auth_info_init(frame);
		if (u_info == NULL) {
			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return NULL;
		}
		set_cmdline_auth_info_username(u_info, user);
		set_cmdline_auth_info_password(u_info, password);

		/*
                 * We have server and share and path empty but options
                 * requesting that we scan all master browsers for their list
                 * of workgroups/domains.  This implies that we must first try
                 * broadcast queries to find all master browsers, and if that
                 * doesn't work, then try our other methods which return only
                 * a single master browser.
                 */

                ip_list = NULL;
		status = name_resolve_bcast(MSBROWSE, 1, talloc_tos(),
					    &ip_list, &count);
                if (!NT_STATUS_IS_OK(status))
		{

                        TALLOC_FREE(ip_list);

                        if (!find_master_ip(workgroup, &server_addr)) {

				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
                                errno = ENOENT;
                                return NULL;
                        }

			ip_list = (struct sockaddr_storage *)talloc_memdup(
				talloc_tos(), &server_addr,
				sizeof(server_addr));
			if (ip_list == NULL) {
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				errno = ENOMEM;
				return NULL;
			}
                        count = 1;
                }

                for (i = 0; i < count && i < max_lmb_count; i++) {
			char addr[INET6_ADDRSTRLEN];
			char *wg_ptr = NULL;
                	struct cli_state *cli = NULL;

			print_sockaddr(addr, sizeof(addr), &ip_list[i]);
                        DEBUG(99, ("Found master browser %d of %d: %s\n",
                                   i+1, MAX(count, max_lmb_count),
                                   addr));

                        cli = get_ipc_connect_master_ip(talloc_tos(),
							&ip_list[i],
                                                        u_info,
							&wg_ptr);
			/* cli == NULL is the master browser refused to talk or
			   could not be found */
			if (!cli) {
				continue;
			}

			workgroup = talloc_strdup(frame, wg_ptr);
			server = talloc_strdup(frame, smbXcli_conn_remote_name(cli->conn));

                        cli_shutdown(cli);

			if (!workgroup || !server) {
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				errno = ENOMEM;
				return NULL;
			}

                        DEBUG(4, ("using workgroup %s %s\n",
                                  workgroup, server));

                        /*
                         * For each returned master browser IP address, get a
                         * connection to IPC$ on the server if we do not
                         * already have one, and determine the
                         * workgroups/domains that it knows about.
                         */

                        srv = SMBC_server(frame, context, True, server, port, "IPC$",
                                          &workgroup, &user, &password);
                        if (!srv) {
                                continue;
                        }

			if (smbXcli_conn_protocol(srv->cli->conn) > PROTOCOL_NT1) {
				continue;
			}

                        dir->srv = srv;
                        dir->dir_type = SMBC_WORKGROUP;

                        /* Now, list the stuff ... */

                        if (!cli_NetServerEnum(srv->cli,
                                               workgroup,
                                               SV_TYPE_DOMAIN_ENUM,
                                               list_unique_wg_fn,
                                               (void *)dir)) {
                                continue;
                        }
                }

                TALLOC_FREE(ip_list);
        } else {
                /*
                 * Server not an empty string ... Check the rest and see what
                 * gives
                 */
		if (*share == '\0') {
			if (*path != '\0') {

                                /* Should not have empty share with path */
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				errno = EINVAL + 8197;
				return NULL;

			}

			/*
                         * We don't know if <server> is really a server name
                         * or is a workgroup/domain name.  If we already have
                         * a server structure for it, we'll use it.
                         * Otherwise, check to see if <server><1D>,
                         * <server><1B>, or <server><20> translates.  We check
                         * to see if <server> is an IP address first.
                         */

                        /*
                         * See if we have an existing server.  Do not
                         * establish a connection if one does not already
                         * exist.
                         */
                        srv = SMBC_server(frame, context, False,
                                          server, port, "IPC$",
                                          &workgroup, &user, &password);

                        /*
                         * If no existing server and not an IP addr, look for
                         * LMB or DMB
                         */
			if (!srv &&
                            !is_ipaddress(server) &&
			    (resolve_name(server, &rem_ss, 0x1d, false) ||   /* LMB */
                             resolve_name(server, &rem_ss, 0x1b, false) )) { /* DMB */
				/*
				 * "server" is actually a workgroup name,
				 * not a server. Make this clear.
				 */
				char *wgroup = server;
				fstring buserver;

				dir->dir_type = SMBC_SERVER;

				/*
				 * Get the backup list ...
				 */
				if (!name_status_find(wgroup, 0, 0,
                                                      &rem_ss, buserver)) {
					char addr[INET6_ADDRSTRLEN];

					print_sockaddr(addr, sizeof(addr), &rem_ss);
                                        DEBUG(0,("Could not get name of "
                                                "local/domain master browser "
                                                "for workgroup %s from "
						"address %s\n",
						wgroup,
						addr));
					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					TALLOC_FREE(frame);
					errno = EPERM;
					return NULL;

				}

				/*
                                 * Get a connection to IPC$ on the server if
                                 * we do not already have one
                                 */
				srv = SMBC_server(frame, context, True,
                                                  buserver, port, "IPC$",
                                                  &workgroup,
                                                  &user, &password);
				if (!srv) {
				        DEBUG(0, ("got no contact to IPC$\n"));
					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					TALLOC_FREE(frame);
					return NULL;

				}

				dir->srv = srv;

				if (smbXcli_conn_protocol(srv->cli->conn) > PROTOCOL_NT1) {
					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					TALLOC_FREE(frame);
					return NULL;
				}

				/* Now, list the servers ... */
				if (!cli_NetServerEnum(srv->cli, wgroup,
                                                       0x0000FFFE, list_fn,
						       (void *)dir)) {

					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					TALLOC_FREE(frame);
					return NULL;
				}
			} else if (srv ||
                                   (resolve_name(server, &rem_ss, 0x20, false))) {
				NTSTATUS status;

                                /*
                                 * If we hadn't found the server, get one now
                                 */
                                if (!srv) {
                                        srv = SMBC_server(frame, context, True,
                                                          server, port, "IPC$",
                                                          &workgroup,
                                                          &user, &password);
                                }

                                if (!srv) {
                                        if (dir) {
                                                SAFE_FREE(dir->fname);
                                                SAFE_FREE(dir);
                                        }
					TALLOC_FREE(frame);
                                        return NULL;

                                }

                                dir->dir_type = SMBC_FILE_SHARE;
                                dir->srv = srv;

                                /* List the shares ... */

				status = net_share_enum_rpc(srv->cli,
							list_fn,
							(void *)dir);
				if (!NT_STATUS_IS_OK(status) &&
				    smbXcli_conn_protocol(srv->cli->conn) <=
						PROTOCOL_NT1) {
					/*
					 * Only call cli_RNetShareEnum()
					 * on SMB1 connections, not SMB2+.
					 */
					int rc = cli_RNetShareEnum(srv->cli,
							       list_fn,
							       (void *)dir);
					if (rc != 0) {
						status = cli_nt_error(srv->cli);
					} else {
						status = NT_STATUS_OK;
					}
				}
				if (!NT_STATUS_IS_OK(status)) {
					/*
					 * Set cli->raw_status so SMBC_errno()
					 * will correctly return the error.
					 */
					srv->cli->raw_status = status;
					if (dir != NULL) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					TALLOC_FREE(frame);
					errno = map_errno_from_nt_status(
								status);
					return NULL;
				}
                        } else {
                                /* Neither the workgroup nor server exists */
                                errno = ECONNREFUSED;
                                if (dir) {
                                        SAFE_FREE(dir->fname);
                                        SAFE_FREE(dir);
                                }
				TALLOC_FREE(frame);
                                return NULL;
			}

		}
		else {
                        /*
                         * The server and share are specified ... work from
                         * there ...
                         */
			char *targetpath;
			struct cli_state *targetcli;
			NTSTATUS status;

			/* We connect to the server and list the directory */
			dir->dir_type = SMBC_FILE_SHARE;

			srv = SMBC_server(frame, context, True, server, port, share,
                                          &workgroup, &user, &password);

			if (!srv) {
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				return NULL;
			}

			dir->srv = srv;

			/* Now, list the files ... */

                        path_len = strlen(path);
			path = talloc_asprintf_append(path, "\\*");
			if (!path) {
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				return NULL;
			}

			status = cli_resolve_path(
				frame, "", context->internal->auth_info,
				srv->cli, path, &targetcli, &targetpath);
			if (!NT_STATUS_IS_OK(status)) {
				d_printf("Could not resolve %s\n", path);
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				TALLOC_FREE(frame);
				return NULL;
			}

			status = cli_list(targetcli, targetpath,
					  FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
					  dir_list_fn, (void *)dir);
			if (!NT_STATUS_IS_OK(status)) {
				int saved_errno;
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				saved_errno = SMBC_errno(context, targetcli);

                                if (saved_errno == EINVAL) {
					struct stat sb = {0};
                                        /*
                                         * See if they asked to opendir
                                         * something other than a directory.
                                         * If so, the converted error value we
                                         * got would have been EINVAL rather
                                         * than ENOTDIR.
                                         */
                                        path[path_len] = '\0'; /* restore original path */

                                        if (SMBC_getatr(context,
							srv,
							path,
							&sb) &&
                                            !S_ISDIR(sb.st_mode)) {

                                                /* It is.  Correct the error value */
                                                saved_errno = ENOTDIR;
                                        }
                                }

                                /*
                                 * If there was an error and the server is no
                                 * good any more...
                                 */
                                if (cli_is_error(targetcli) &&
                                    smbc_getFunctionCheckServer(context)(context, srv)) {

                                        /* ... then remove it. */
                                        if (smbc_getFunctionRemoveUnusedServer(context)(context,
                                                                                        srv)) {
                                                /*
                                                 * We could not remove the
                                                 * server completely, remove
                                                 * it from the cache so we
                                                 * will not get it again. It
                                                 * will be removed when the
                                                 * last file/dir is closed.
                                                 */
                                                smbc_getFunctionRemoveCachedServer(context)(context, srv);
                                        }
                                }

				TALLOC_FREE(frame);
                                errno = saved_errno;
				return NULL;
			}
		}

	}

	DLIST_ADD(context->internal->files, dir);
	TALLOC_FREE(frame);
	return dir;

}

/*
 * Routine to close a directory
 */

int
SMBC_closedir_ctx(SMBCCTX *context,
                  SMBCFILE *dir)
{
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	remove_dir(dir); /* Clean it up */
	remove_dirplus(dir);

	DLIST_REMOVE(context->internal->files, dir);

	if (dir) {

		SAFE_FREE(dir->fname);
		SAFE_FREE(dir);    /* Free the space too */
	}

	TALLOC_FREE(frame);
	return 0;

}

static int
smbc_readdir_internal(SMBCCTX * context,
                      struct smbc_dirent *dest,
                      struct smbc_dirent *src,
                      int max_namebuf_len)
{
        if (smbc_getOptionUrlEncodeReaddirEntries(context)) {
		int remaining_len;

                /* url-encode the name.  get back remaining buffer space */
                remaining_len =
                        smbc_urlencode(dest->name, src->name, max_namebuf_len);

		/* -1 means no null termination. */
		if (remaining_len < 0) {
			return -1;
		}

                /* We now know the name length */
                dest->namelen = strlen(dest->name);

		if (dest->namelen + 1 < 1) {
			/* Integer wrap. */
			return -1;
		}

		if (dest->namelen + 1 >= max_namebuf_len) {
			/* Out of space for comment. */
			return -1;
		}

                /* Save the pointer to the beginning of the comment */
                dest->comment = dest->name + dest->namelen + 1;

		if (remaining_len < 1) {
			/* No room for comment null termination. */
			return -1;
		}

                /* Copy the comment */
                strlcpy(dest->comment, src->comment, remaining_len);

                /* Save other fields */
                dest->smbc_type = src->smbc_type;
                dest->commentlen = strlen(dest->comment);
                dest->dirlen = ((dest->comment + dest->commentlen + 1) -
                                (char *) dest);
        } else {

                /* No encoding.  Just copy the entry as is. */
		if (src->dirlen > max_namebuf_len) {
			return -1;
		}
                memcpy(dest, src, src->dirlen);
		if (src->namelen + 1 < 1) {
			/* Integer wrap */
			return -1;
		}
		if (src->namelen + 1 >= max_namebuf_len) {
			/* Comment off the end. */
			return -1;
		}
                dest->comment = (char *)(&dest->name + src->namelen + 1);
        }
	return 0;
}

/*
 * Routine to get a directory entry
 */

struct smbc_dirent *
SMBC_readdir_ctx(SMBCCTX *context,
                 SMBCFILE *dir)
{
        int maxlen;
	int ret;
	struct smbc_dirent *dirp, *dirent;
	TALLOC_CTX *frame = talloc_stackframe();

	/* Check that all is ok first ... */

	if (!context || !context->internal->initialized) {

		errno = EINVAL;
                DEBUG(0, ("Invalid context in SMBC_readdir_ctx()\n"));
		TALLOC_FREE(frame);
		return NULL;

	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {

		errno = EBADF;
                DEBUG(0, ("Invalid dir in SMBC_readdir_ctx()\n"));
		TALLOC_FREE(frame);
		return NULL;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
                DEBUG(0, ("Found file vs directory in SMBC_readdir_ctx()\n"));
		TALLOC_FREE(frame);
		return NULL;

	}

	if (!dir->dir_next) {
		TALLOC_FREE(frame);
		return NULL;
        }

        dirent = dir->dir_next->dirent;
        if (!dirent) {

                errno = ENOENT;
		TALLOC_FREE(frame);
                return NULL;

        }

        dirp = &context->internal->dirent;
        maxlen = sizeof(context->internal->_dirent_name);

        ret = smbc_readdir_internal(context, dirp, dirent, maxlen);
	if (ret == -1) {
		errno = EINVAL;
		TALLOC_FREE(frame);
                return NULL;
	}

        dir->dir_next = dir->dir_next->next;

	/*
	 * If we are returning file entries, we
	 * have a duplicate list in dirplus.
	 *
	 * Update dirplus_next also so readdir and
	 * readdirplus are kept in sync.
	 */
	if (dir->dirplus_list != NULL) {
		dir->dirplus_next = dir->dirplus_next->next;
	}

	TALLOC_FREE(frame);
        return dirp;
}

/*
 * Routine to get a directory entry with all attributes
 */

const struct libsmb_file_info *
SMBC_readdirplus_ctx(SMBCCTX *context,
                     SMBCFILE *dir)
{
	struct libsmb_file_info *smb_finfo = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	/* Check that all is ok first ... */

	if (context == NULL || !context->internal->initialized) {
		DBG_ERR("Invalid context in SMBC_readdirplus_ctx()\n");
		TALLOC_FREE(frame);
		errno = EINVAL;
		return NULL;
	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {
		DBG_ERR("Invalid dir in SMBC_readdirplus_ctx()\n");
		TALLOC_FREE(frame);
		errno = EBADF;
		return NULL;
	}

	if (dir->dirplus_next == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_finfo = dir->dirplus_next->smb_finfo;
	if (smb_finfo == NULL) {
		TALLOC_FREE(frame);
		errno = ENOENT;
		return NULL;
	}
	dir->dirplus_next = dir->dirplus_next->next;

	/*
	 * If we are returning file entries, we
	 * have a duplicate list in dir_list
	 *
	 * Update dir_next also so readdir and
	 * readdirplus are kept in sync.
	 */
	if (dir->dir_list) {
		dir->dir_next = dir->dir_next->next;
	}

	TALLOC_FREE(frame);
	return smb_finfo;
}

/*
 * Routine to get a directory entry plus a filled in stat structure if
 * requested.
 */

const struct libsmb_file_info *SMBC_readdirplus2_ctx(SMBCCTX *context,
			SMBCFILE *dir,
			struct stat *st)
{
	struct libsmb_file_info *smb_finfo = NULL;
	struct smbc_dirplus_list *dp_list = NULL;
	ino_t ino;
	char *full_pathname = NULL;
	char *workgroup = NULL;
	char *server = NULL;
	uint16_t port = 0;
	char *share = NULL;
	char *path = NULL;
	char *user = NULL;
	char *password = NULL;
	char *options = NULL;
	int rc;
	TALLOC_CTX *frame = NULL;

	/*
	 * Allow caller to pass in NULL for stat pointer if
	 * required. This makes this call identical to
	 * smbc_readdirplus().
	 */

	if (st == NULL) {
		return SMBC_readdirplus_ctx(context, dir);
	}

	frame = talloc_stackframe();

	/* Check that all is ok first ... */
	if (context == NULL || !context->internal->initialized) {
		DBG_ERR("Invalid context in SMBC_readdirplus2_ctx()\n");
		TALLOC_FREE(frame);
		errno = EINVAL;
		return NULL;
	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {
		DBG_ERR("Invalid dir in SMBC_readdirplus2_ctx()\n");
		TALLOC_FREE(frame);
		errno = EBADF;
		return NULL;
	}

	dp_list = dir->dirplus_next;
	if (dp_list == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	ino = (ino_t)dp_list->ino;

	smb_finfo = dp_list->smb_finfo;
	if (smb_finfo == NULL) {
		TALLOC_FREE(frame);
		errno = ENOENT;
		return NULL;
	}

	full_pathname = talloc_asprintf(frame,
				"%s/%s",
				dir->fname,
				smb_finfo->name);
	if (full_pathname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOENT;
		return NULL;
	}

	rc = SMBC_parse_path(frame,
			     context,
			     full_pathname,
			     &workgroup,
			     &server,
			     &port,
			     &share,
			     &path,
			     &user,
			     &password,
			     &options);
	if (rc != 0) {
		TALLOC_FREE(frame);
		errno = ENOENT;
		return NULL;
	}

	setup_stat(st,
		path,
		smb_finfo->size,
		smb_finfo->attrs,
		ino,
		dir->srv->dev,
		smb_finfo->atime_ts,
		smb_finfo->ctime_ts,
		smb_finfo->mtime_ts);

	TALLOC_FREE(full_pathname);

	dir->dirplus_next = dir->dirplus_next->next;

	/*
	 * If we are returning file entries, we
	 * have a duplicate list in dir_list
	 *
	 * Update dir_next also so readdir and
	 * readdirplus are kept in sync.
	 */
	if (dir->dir_list) {
		dir->dir_next = dir->dir_next->next;
	}

	TALLOC_FREE(frame);
	return smb_finfo;
}

/*
 * Routine to get directory entries
 */

int
SMBC_getdents_ctx(SMBCCTX *context,
                  SMBCFILE *dir,
                  struct smbc_dirent *dirp,
                  int count)
{
	int rem = count;
        int reqd;
        int maxlen;
	char *ndir = (char *)dirp;
	struct smbc_dir_list *dirlist;
	TALLOC_CTX *frame = talloc_stackframe();

	/* Check that all is ok first ... */

	if (!context || !context->internal->initialized) {

		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;

	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {

		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		TALLOC_FREE(frame);
		return -1;

	}

	/*
	 * Now, retrieve the number of entries that will fit in what was passed
	 * We have to figure out if the info is in the list, or we need to
	 * send a request to the server to get the info.
	 */

	while ((dirlist = dir->dir_next)) {
		int ret;
		struct smbc_dirent *dirent;
		struct smbc_dirent *currentEntry = (struct smbc_dirent *)ndir;

		if (!dirlist->dirent) {

			errno = ENOENT;  /* Bad error */
			TALLOC_FREE(frame);
			return -1;

		}

                /* Do urlencoding of next entry, if so selected */
                dirent = &context->internal->dirent;
                maxlen = sizeof(context->internal->_dirent_name);
		ret = smbc_readdir_internal(context, dirent,
                                      dirlist->dirent, maxlen);
		if (ret == -1) {
			errno = EINVAL;
			TALLOC_FREE(frame);
			return -1;
		}

                reqd = dirent->dirlen;

		if (rem < reqd) {

			if (rem < count) { /* We managed to copy something */

				errno = 0;
				TALLOC_FREE(frame);
				return count - rem;

			}
			else { /* Nothing copied ... */

				errno = EINVAL;  /* Not enough space ... */
				TALLOC_FREE(frame);
				return -1;

			}

		}

		memcpy(currentEntry, dirent, reqd); /* Copy the data in ... */

		currentEntry->comment = &currentEntry->name[0] +
						dirent->namelen + 1;

		ndir += reqd;
		rem -= reqd;

		/* Try and align the struct for the next entry
		   on a valid pointer boundary by appending zeros */
		while((rem > 0) && ((uintptr_t)ndir & (sizeof(void*) - 1))) {
			*ndir = '\0';
			rem--;
			ndir++;
			currentEntry->dirlen++;
		}

		dir->dir_next = dirlist = dirlist -> next;

		/*
		 * If we are returning file entries, we
		 * have a duplicate list in dirplus.
		 *
		 * Update dirplus_next also so readdir and
		 * readdirplus are kept in sync.
		 */
		if (dir->dirplus_list != NULL) {
			dir->dirplus_next = dir->dirplus_next->next;
		}
	}

	TALLOC_FREE(frame);

	if (rem == count)
		return 0;
	else
		return count - rem;

}

/*
 * Routine to create a directory ...
 */

int
SMBC_mkdir_ctx(SMBCCTX *context,
               const char *fname,
               mode_t mode)
{
	SMBCSRV *srv = NULL;
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *workgroup = NULL;
	char *path = NULL;
	char *targetpath = NULL;
	uint16_t port = 0;
	struct cli_state *targetcli = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	DEBUG(4, ("smbc_mkdir(%s)\n", fname));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);

	if (!srv) {

		TALLOC_FREE(frame);
		return -1;  /* errno set by SMBC_server */

	}

	/*d_printf(">>>mkdir: resolving %s\n", path);*/
	status = cli_resolve_path(frame, "", context->internal->auth_info,
				  srv->cli, path, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path);
                errno = ENOENT;
                TALLOC_FREE(frame);
		return -1;
	}
	/*d_printf(">>>mkdir: resolved path as %s\n", targetpath);*/

	if (!NT_STATUS_IS_OK(cli_mkdir(targetcli, targetpath))) {
		errno = SMBC_errno(context, targetcli);
		TALLOC_FREE(frame);
		return -1;

	}

	TALLOC_FREE(frame);
	return 0;

}

/*
 * Our list function simply checks to see if a directory is not empty
 */

static NTSTATUS
rmdir_list_fn(const char *mnt,
              struct file_info *finfo,
              const char *mask,
              void *state)
{
	if (strncmp(finfo->name, ".", 1) != 0 &&
            strncmp(finfo->name, "..", 2) != 0) {
		bool *smbc_rmdir_dirempty = (bool *)state;
		*smbc_rmdir_dirempty = false;
        }
	return NT_STATUS_OK;
}

/*
 * Routine to remove a directory
 */

int
SMBC_rmdir_ctx(SMBCCTX *context,
               const char *fname)
{
	SMBCSRV *srv = NULL;
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *workgroup = NULL;
	char *path = NULL;
        char *targetpath = NULL;
	uint16_t port = 0;
	struct cli_state *targetcli = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	DEBUG(4, ("smbc_rmdir(%s)\n", fname));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);

	if (!srv) {

		TALLOC_FREE(frame);
		return -1;  /* errno set by SMBC_server */

	}

	/*d_printf(">>>rmdir: resolving %s\n", path);*/
	status = cli_resolve_path(frame, "", context->internal->auth_info,
				  srv->cli, path, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}
	/*d_printf(">>>rmdir: resolved path as %s\n", targetpath);*/

	if (!NT_STATUS_IS_OK(cli_rmdir(targetcli, targetpath))) {

		errno = SMBC_errno(context, targetcli);

		if (errno == EACCES) {  /* Check if the dir empty or not */

                        /* Local storage to avoid buffer overflows */
			char *lpath;
			bool smbc_rmdir_dirempty = true;

			lpath = talloc_asprintf(frame, "%s\\*",
						targetpath);
			if (!lpath) {
				errno = ENOMEM;
				TALLOC_FREE(frame);
				return -1;
			}

			status = cli_list(targetcli, lpath,
					  FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
					  rmdir_list_fn,
					  &smbc_rmdir_dirempty);

			if (!NT_STATUS_IS_OK(status)) {
				/* Fix errno to ignore latest error ... */
				DEBUG(5, ("smbc_rmdir: "
                                          "cli_list returned an error: %d\n",
					  SMBC_errno(context, targetcli)));
				errno = EACCES;

			}

			if (smbc_rmdir_dirempty)
				errno = EACCES;
			else
				errno = ENOTEMPTY;

		}

		TALLOC_FREE(frame);
		return -1;

	}

	TALLOC_FREE(frame);
	return 0;

}

/*
 * Routine to return the current directory position
 */

off_t
SMBC_telldir_ctx(SMBCCTX *context,
                 SMBCFILE *dir)
{
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {

		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;

	}

	if (!SMBC_dlist_contains(context->internal->files, dir)) {

		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		TALLOC_FREE(frame);
		return -1;

	}

        /* See if we're already at the end. */
        if (dir->dir_next == NULL) {
                /* We are. */
		TALLOC_FREE(frame);
                return -1;
        }

	/*
	 * We return the pointer here as the offset
	 */
	TALLOC_FREE(frame);
        return (off_t)(long)dir->dir_next->dirent;
}

/*
 * A routine to run down the list and see if the entry is OK
 * Modifies the dir list and the dirplus list (if it exists)
 * to point at the correct next entry on success.
 */

static bool update_dir_ents(SMBCFILE *dir, struct smbc_dirent *dirent)
{
	struct smbc_dir_list *tmp_dir = dir->dir_list;
	struct smbc_dirplus_list *tmp_dirplus = dir->dirplus_list;

	/*
	 * Run down the list looking for what we want.
	 * If we're enumerating files both dir_list
	 * and dirplus_list contain the same entry
	 * list, as they were seeded from the same
	 * cli_list callback.
	 *
	 * If we're enumerating servers then
	 * dirplus_list will be NULL, so don't
	 * update in that case.
	 */

	while (tmp_dir != NULL) {
		if (tmp_dir->dirent == dirent) {
			dir->dir_next = tmp_dir;
			if (tmp_dirplus != NULL) {
				dir->dirplus_next = tmp_dirplus;
			}
			return true;
		}
		tmp_dir = tmp_dir->next;
		if (tmp_dirplus != NULL) {
			tmp_dirplus = tmp_dirplus->next;
		}
	}
	return false;
}

/*
 * Routine to seek on a directory
 */

int
SMBC_lseekdir_ctx(SMBCCTX *context,
                  SMBCFILE *dir,
                  off_t offset)
{
	long int l_offset = offset;  /* Handle problems of size */
	struct smbc_dirent *dirent = (struct smbc_dirent *)l_offset;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;

	if (!context || !context->internal->initialized) {

		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		TALLOC_FREE(frame);
		return -1;

	}

	/* Now, check what we were passed and see if it is OK ... */

	if (dirent == NULL) {  /* Seek to the begining of the list */

		dir->dir_next = dir->dir_list;

		/* Do the same for dirplus. */
		dir->dirplus_next = dir->dirplus_list;

		TALLOC_FREE(frame);
		return 0;

	}

        if (offset == -1) {     /* Seek to the end of the list */
                dir->dir_next = NULL;

		/* Do the same for dirplus. */
		dir->dirplus_next = NULL;

		TALLOC_FREE(frame);
                return 0;
        }

        /*
         * Run down the list and make sure that the entry is OK.
         * Update the position of both dir and dirplus lists.
         */

	ok = update_dir_ents(dir, dirent);
	if (!ok) {
		errno = EINVAL;   /* Bad entry */
		TALLOC_FREE(frame);
		return -1;
	}

	TALLOC_FREE(frame);
	return 0;
}

/*
 * Routine to fstat a dir
 */

int
SMBC_fstatdir_ctx(SMBCCTX *context,
                  SMBCFILE *dir,
                  struct stat *st)
{

	if (!context || !context->internal->initialized) {

		errno = EINVAL;
		return -1;
	}

	/* No code yet ... */
	return 0;
}

int
SMBC_chmod_ctx(SMBCCTX *context,
               const char *fname,
               mode_t newmode)
{
        SMBCSRV *srv = NULL;
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *workgroup = NULL;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	char *path = NULL;
	uint32_t attr;
	uint16_t port = 0;
	TALLOC_CTX *frame = talloc_stackframe();
        NTSTATUS status;

	if (!context || !context->internal->initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return -1;
	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	DEBUG(4, ("smbc_chmod(%s, 0%3o)\n", fname, (unsigned int)newmode));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);

	if (!srv) {
		TALLOC_FREE(frame);
		return -1;  /* errno set by SMBC_server */
	}
	
	/*d_printf(">>>unlink: resolving %s\n", path);*/
	status = cli_resolve_path(frame, "", context->internal->auth_info,
				  srv->cli, path, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}

	attr = 0;

	if (!(newmode & (S_IWUSR | S_IWGRP | S_IWOTH))) attr |= FILE_ATTRIBUTE_READONLY;
	if ((newmode & S_IXUSR) && lp_map_archive(-1)) attr |= FILE_ATTRIBUTE_ARCHIVE;
	if ((newmode & S_IXGRP) && lp_map_system(-1)) attr |= FILE_ATTRIBUTE_SYSTEM;
	if ((newmode & S_IXOTH) && lp_map_hidden(-1)) attr |= FILE_ATTRIBUTE_HIDDEN;

	if (!NT_STATUS_IS_OK(cli_setatr(targetcli, targetpath, attr, 0))) {
		errno = SMBC_errno(context, targetcli);
		TALLOC_FREE(frame);
		return -1;
	}

	TALLOC_FREE(frame);
        return 0;
}

int
SMBC_utimes_ctx(SMBCCTX *context,
                const char *fname,
                struct timeval *tbuf)
{
        SMBCSRV *srv = NULL;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *workgroup = NULL;
	char *path = NULL;
	struct timespec access_time, write_time;
	uint16_t port = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;

	if (!context || !context->internal->initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return -1;
	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

        if (tbuf == NULL) {
                access_time = write_time = timespec_current();
        } else {
		access_time = convert_timeval_to_timespec(tbuf[0]);
                write_time = convert_timeval_to_timespec(tbuf[1]);
        }

        if (DEBUGLVL(4)) {
		struct timeval_buf abuf, wbuf;

                dbgtext("smbc_utimes(%s, atime = %s mtime = %s)\n",
                        fname,
			timespec_string_buf(&access_time, false, &abuf),
			timespec_string_buf(&write_time, false, &wbuf));
        }

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);

	if (!srv) {
		TALLOC_FREE(frame);
		return -1;      /* errno set by SMBC_server */
	}

	ok = SMBC_setatr(
		context,
		srv,
		path,
		(struct timespec) { .tv_nsec = SAMBA_UTIME_OMIT },
		access_time,
		write_time,
		(struct timespec) { .tv_nsec = SAMBA_UTIME_OMIT },
		0);
	if (!ok) {
		TALLOC_FREE(frame);
                return -1;      /* errno set by SMBC_setatr */
        }

	TALLOC_FREE(frame);
        return 0;
}

/*
 * Routine to unlink() a file
 */

int
SMBC_unlink_ctx(SMBCCTX *context,
                const char *fname)
{
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *workgroup = NULL;
	char *path = NULL;
	char *targetpath = NULL;
	uint16_t port = 0;
	struct cli_state *targetcli = NULL;
	SMBCSRV *srv = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
        NTSTATUS status;

	if (!context || !context->internal->initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return -1;

	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;

	}

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
                return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);

	if (!srv) {
		TALLOC_FREE(frame);
		return -1;  /* SMBC_server sets errno */

	}

	/*d_printf(">>>unlink: resolving %s\n", path);*/
	status = cli_resolve_path(frame, "", context->internal->auth_info,
				  srv->cli, path, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}
	/*d_printf(">>>unlink: resolved path as %s\n", targetpath);*/

	if (!NT_STATUS_IS_OK(cli_unlink(targetcli, targetpath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {

		errno = SMBC_errno(context, targetcli);

		if (errno == EACCES) { /* Check if the file is a directory */

			int saverr = errno;
			struct stat sb = {0};
			bool ok;

			ok = SMBC_getatr(context, srv, path, &sb);
			if (!ok) {
				/* Hmmm, bad error ... What? */

				errno = SMBC_errno(context, targetcli);
				TALLOC_FREE(frame);
				return -1;

			}
			else {

				if (S_ISDIR(sb.st_mode))
					errno = EISDIR;
				else
					errno = saverr;  /* Restore this */

			}
		}

		TALLOC_FREE(frame);
		return -1;

	}

	TALLOC_FREE(frame);
	return 0;  /* Success ... */

}

/*
 * Routine to rename() a file
 */

int
SMBC_rename_ctx(SMBCCTX *ocontext,
                const char *oname,
                SMBCCTX *ncontext,
                const char *nname)
{
	char *server1 = NULL;
        char *share1 = NULL;
        char *server2 = NULL;
        char *share2 = NULL;
        char *user1 = NULL;
        char *user2 = NULL;
        char *password1 = NULL;
        char *password2 = NULL;
        char *workgroup = NULL;
	char *path1 = NULL;
        char *path2 = NULL;
        char *targetpath1 = NULL;
        char *targetpath2 = NULL;
	struct cli_state *targetcli1 = NULL;
        struct cli_state *targetcli2 = NULL;
	SMBCSRV *srv = NULL;
	uint16_t port1 = 0;
	uint16_t port2 = 0;
	TALLOC_CTX *frame = talloc_stackframe();
        NTSTATUS status;

	if (!ocontext || !ncontext ||
	    !ocontext->internal->initialized ||
	    !ncontext->internal->initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return -1;
	}

	if (!oname || !nname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	DEBUG(4, ("smbc_rename(%s,%s)\n", oname, nname));

	if (SMBC_parse_path(frame,
                            ocontext,
                            oname,
                            &workgroup,
                            &server1,
                            &port1,
                            &share1,
                            &path1,
                            &user1,
                            &password1,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!user1 || user1[0] == (char)0) {
		user1 = talloc_strdup(frame, smbc_getUser(ocontext));
		if (!user1) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	if (SMBC_parse_path(frame,
                            ncontext,
                            nname,
                            NULL,
                            &server2,
                            &port2,
                            &share2,
                            &path2,
                            &user2,
                            &password2,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
                return -1;
	}

	if (!user2 || user2[0] == (char)0) {
		user2 = talloc_strdup(frame, smbc_getUser(ncontext));
		if (!user2) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}

	if (strcmp(server1, server2) || strcmp(share1, share2) ||
	    strcmp(user1, user2)) {
		/* Can't rename across file systems, or users?? */
		errno = EXDEV;
		TALLOC_FREE(frame);
		return -1;
	}

	srv = SMBC_server(frame, ocontext, True,
                          server1, port1, share1, &workgroup, &user1, &password1);
	if (!srv) {
		TALLOC_FREE(frame);
		return -1;

	}

	/* set the credentials to make DFS work */
	smbc_set_credentials_with_fallback(ocontext,
					   workgroup,
				     	   user1,
				    	   password1);

	/*d_printf(">>>rename: resolving %s\n", path1);*/
	status = cli_resolve_path(frame, "", ocontext->internal->auth_info,
				  srv->cli, path1, &targetcli1, &targetpath1);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path1);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}
	
	/* set the credentials to make DFS work */
	smbc_set_credentials_with_fallback(ncontext,
					   workgroup,
				           user2,
				           password2);
	
	/*d_printf(">>>rename: resolved path as %s\n", targetpath1);*/
	/*d_printf(">>>rename: resolving %s\n", path2);*/
	status = cli_resolve_path(frame, "", ncontext->internal->auth_info,
				  srv->cli, path2, &targetcli2, &targetpath2);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path2);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}
	/*d_printf(">>>rename: resolved path as %s\n", targetpath2);*/

	if (strcmp(smbXcli_conn_remote_name(targetcli1->conn), smbXcli_conn_remote_name(targetcli2->conn)) ||
            strcmp(targetcli1->share, targetcli2->share))
	{
		/* can't rename across file systems */
		errno = EXDEV;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!NT_STATUS_IS_OK(
		cli_rename(targetcli1, targetpath1, targetpath2, false))) {
		int eno = SMBC_errno(ocontext, targetcli1);

		if (eno != EEXIST ||
		    !NT_STATUS_IS_OK(cli_unlink(targetcli1, targetpath2,
						FILE_ATTRIBUTE_SYSTEM |
						    FILE_ATTRIBUTE_HIDDEN)) ||
		    !NT_STATUS_IS_OK(cli_rename(targetcli1, targetpath1,
						targetpath2, false))) {

			errno = eno;
			TALLOC_FREE(frame);
			return -1;

		}
	}

	TALLOC_FREE(frame);
	return 0; /* Success */
}

struct smbc_notify_cb_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;
	bool recursive;
	uint32_t completion_filter;
	unsigned callback_timeout_ms;
	smbc_notify_callback_fn cb;
	void *private_data;
};

static void smbc_notify_cb_got_changes(struct tevent_req *subreq);
static void smbc_notify_cb_timedout(struct tevent_req *subreq);

static struct tevent_req *smbc_notify_cb_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	uint16_t fnum, bool recursive, uint32_t completion_filter,
	unsigned callback_timeout_ms,
	smbc_notify_callback_fn cb, void *private_data)
{
	struct tevent_req *req, *subreq;
	struct smbc_notify_cb_state *state;

	req = tevent_req_create(mem_ctx, &state, struct smbc_notify_cb_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fnum = fnum;
	state->recursive = recursive;
	state->completion_filter = completion_filter;
	state->callback_timeout_ms = callback_timeout_ms;
	state->cb = cb;
	state->private_data = private_data;

	subreq = cli_notify_send(
		state, state->ev, state->cli, state->fnum, 1000,
		state->completion_filter, state->recursive);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbc_notify_cb_got_changes, req);

	if (state->callback_timeout_ms == 0) {
		return req;
	}

	subreq = tevent_wakeup_send(
		state, state->ev,
		tevent_timeval_current_ofs(state->callback_timeout_ms/1000,
					   state->callback_timeout_ms*1000));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbc_notify_cb_timedout, req);

	return req;
}

static void smbc_notify_cb_got_changes(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbc_notify_cb_state *state = tevent_req_data(
		req, struct smbc_notify_cb_state);
	uint32_t num_changes;
	struct notify_change *changes;
	NTSTATUS status;
	int cb_ret;

	status = cli_notify_recv(subreq, state, &num_changes, &changes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	{
		struct smbc_notify_callback_action actions[num_changes];
		uint32_t i;

		for (i=0; i<num_changes; i++) {
			actions[i].action = changes[i].action;
			actions[i].filename = changes[i].name;
		}

		cb_ret = state->cb(actions, num_changes, state->private_data);
	}

	TALLOC_FREE(changes);

	if (cb_ret != 0) {
		tevent_req_done(req);
		return;
	}

	subreq = cli_notify_send(
		state, state->ev, state->cli, state->fnum, 1000,
		state->completion_filter, state->recursive);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbc_notify_cb_got_changes, req);
}

static void smbc_notify_cb_timedout(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbc_notify_cb_state *state = tevent_req_data(
		req, struct smbc_notify_cb_state);
	int cb_ret;
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}

	cb_ret = state->cb(NULL, 0, state->private_data);
	if (cb_ret != 0) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(
		state, state->ev,
		tevent_timeval_current_ofs(state->callback_timeout_ms/1000,
					   state->callback_timeout_ms*1000));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbc_notify_cb_timedout, req);
}

static NTSTATUS smbc_notify_cb_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS smbc_notify_cb(struct cli_state *cli, uint16_t fnum,
			       bool recursive, uint32_t completion_filter,
			       unsigned callback_timeout_ms,
			       smbc_notify_callback_fn cb, void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smbc_notify_cb_send(frame, ev, cli, fnum, recursive,
				  completion_filter,
				  callback_timeout_ms, cb, private_data);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smbc_notify_cb_recv(req);
	TALLOC_FREE(req);
fail:
	TALLOC_FREE(frame);
	return status;
}

int
SMBC_notify_ctx(SMBCCTX *context, SMBCFILE *dir, smbc_bool recursive,
		uint32_t completion_filter, unsigned callback_timeout_ms,
		smbc_notify_callback_fn cb, void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cli_state *cli;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *options = NULL;
	char *workgroup = NULL;
	char *path = NULL;
	uint16_t port;
	NTSTATUS status;
	uint16_t fnum;

	if ((context == NULL) || !context->internal->initialized) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}
	if (!SMBC_dlist_contains(context->internal->files, dir)) {
		TALLOC_FREE(frame);
		errno = EBADF;
		return -1;
	}

	if (SMBC_parse_path(frame,
                            context,
                            dir->fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            &options)) {
	        DEBUG(4, ("no valid path\n"));
		TALLOC_FREE(frame);
		errno = EINVAL + 8194;
		return -1;
	}

	DEBUG(4, ("parsed path: fname='%s' server='%s' share='%s' "
                  "path='%s' options='%s'\n",
                  dir->fname, server, share, path, options));

	DEBUG(4, ("%s(%p, %d, %"PRIu32")\n", __func__, dir,
		  (int)recursive, completion_filter));

	cli = dir->srv->cli;
	status = cli_ntcreate(
		cli, path, 0, FILE_READ_DATA, 0,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		int err = SMBC_errno(context, cli);
		TALLOC_FREE(frame);
		errno = err;
		return -1;
	}

	status = smbc_notify_cb(cli, fnum, recursive != 0, completion_filter,
				callback_timeout_ms, cb, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		int err = SMBC_errno(context, cli);
		cli_close(cli, fnum);
		TALLOC_FREE(frame);
		errno = err;
		return -1;
	}

	cli_close(cli, fnum);

	TALLOC_FREE(frame);
	return 0;
}
