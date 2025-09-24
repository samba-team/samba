/*
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2007

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
/*
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/

#include "includes.h"
#include "libsmb/namequery.h"
#include "system/filesys.h"
#include "printing.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbd/smbXsrv_open.h"
#include "fake_file.h"
#include "rpc_client/rpc_client.h"
#include "../librpc/gen_ndr/ndr_spoolss_c.h"
#include "rpc_client/cli_spoolss.h"
#include "rpc_client/init_spoolss.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "libcli/security/security.h"
#include "libsmb/nmblib.h"
#include "auth.h"
#include "smbprofile.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/smb/smb_signing.h"
#include "lib/util/sys_rw_data.h"
#include "librpc/gen_ndr/open_files.h"
#include "libcli/smb/smb2_posix.h"
#include "lib/util/string_wrappers.h"
#include "source3/printing/rap_jobid.h"
#include "source3/lib/substitute.h"
#include "source3/smbd/dir.h"

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for a findfirst/findnext
 path or anything including wildcards.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption). '\\' *may* be the second byte in a multibyte char
 set.
****************************************************************************/

/* Custom version for processing POSIX paths. */
#define IS_PATH_SEP(c,posix_only) ((c) == '/' || (!(posix_only) && (c) == '\\'))

NTSTATUS check_path_syntax(char *path, bool posix_path)
{
	char *d = path;
	const char *s = path;
	NTSTATUS ret = NT_STATUS_OK;
	bool start_of_name_component = True;
	bool stream_started = false;
	bool last_component_contains_wcard = false;

	while (*s) {
		if (stream_started) {
			switch (*s) {
			case '/':
			case '\\':
				return NT_STATUS_OBJECT_NAME_INVALID;
			case ':':
				if (s[1] == '\0') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				if (strchr_m(&s[1], ':')) {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				break;
			}
		}

		if ((*s == ':') && !posix_path && !stream_started) {
			if (last_component_contains_wcard) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
			/* Stream names allow more characters than file names.
			   We're overloading posix_path here to allow a wider
			   range of characters. If stream_started is true this
			   is still a Windows path even if posix_path is true.
			   JRA.
			*/
			stream_started = true;
			start_of_name_component = false;
			posix_path = true;

			if (s[1] == '\0') {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}
		}

		if (!stream_started && IS_PATH_SEP(*s,posix_path)) {
			/*
			 * Safe to assume is not the second part of a mb char
			 * as this is handled below.
			 */
			/* Eat multiple '/' or '\\' */
			while (IS_PATH_SEP(*s,posix_path)) {
				s++;
			}
			if ((d != path) && (*s != '\0')) {
				/* We only care about non-leading or trailing '/' or '\\' */
				*d++ = '/';
			}

			start_of_name_component = True;
			/* New component. */
			last_component_contains_wcard = false;
			continue;
		}

		if (start_of_name_component) {
			if ((s[0] == '.') && (s[1] == '.') && (IS_PATH_SEP(s[2],posix_path) || s[2] == '\0')) {
				/* Uh oh - "/../" or "\\..\\"  or "/..\0" or "\\..\0" ! */

				/*
				 * No mb char starts with '.' so we're safe checking the directory separator here.
				 */

				/* If  we just added a '/' - delete it */
				if ((d > path) && (*(d-1) == '/')) {
					*(d-1) = '\0';
					d--;
				}

				/* Are we at the start ? Can't go back further if so. */
				if (d <= path) {
					ret = NT_STATUS_OBJECT_PATH_SYNTAX_BAD;
					break;
				}
				/* Go back one level... */
				/* We know this is safe as '/' cannot be part of a mb sequence. */
				/* NOTE - if this assumption is invalid we are not in good shape... */
				/* Decrement d first as d points to the *next* char to write into. */
				for (d--; d > path; d--) {
					if (*d == '/')
						break;
				}
				s += 2; /* Else go past the .. */
				/* We're still at the start of a name component, just the previous one. */
				continue;

			} else if ((s[0] == '.') && ((s[1] == '\0') || IS_PATH_SEP(s[1],posix_path))) {
				if (posix_path) {
					/* Eat the '.' */
					s++;
					continue;
				}
			} else if (IS_SMBD_TMPNAME(s, NULL)) {
				return NT_STATUS_OBJECT_NAME_INVALID;
			}

		}

		if (!(*s & 0x80)) {
			if (!posix_path) {
				if (*s <= 0x1f || *s == '|') {
					return NT_STATUS_OBJECT_NAME_INVALID;
				}
				switch (*s) {
					case '*':
					case '?':
					case '<':
					case '>':
					case '"':
						last_component_contains_wcard = true;
						break;
					default:
						break;
				}
			}
			*d++ = *s++;
		} else {
			size_t ch_size;
			/* Get the size of the next MB character. */
			next_codepoint(s,&ch_size);
			switch(ch_size) {
				case 5:
					*d++ = *s++;
					FALL_THROUGH;
				case 4:
					*d++ = *s++;
					FALL_THROUGH;
				case 3:
					*d++ = *s++;
					FALL_THROUGH;
				case 2:
					*d++ = *s++;
					FALL_THROUGH;
				case 1:
					*d++ = *s++;
					break;
				default:
					DBG_ERR("character length assumptions invalid !\n");
					*d = '\0';
					return NT_STATUS_INVALID_PARAMETER;
			}
		}
		start_of_name_component = False;
	}

	*d = '\0';

	return ret;
}

/****************************************************************************
 SMB2-only code to strip an MSDFS prefix from an incoming pathname.
****************************************************************************/

NTSTATUS smb2_strip_dfs_path(const char *in_path, const char **out_path)
{
	const char *path = in_path;

	/* Match the Windows 2022 behavior for an empty DFS pathname. */
	if (*path == '\0') {
		return NT_STATUS_INVALID_PARAMETER;
	}
	/* Strip any leading '\\' characters - MacOSX client behavior. */
	while (*path == '\\') {
		path++;
	}
	/* We should now be pointing at the server name. Go past it. */
	for (;;) {
		if (*path == '\0') {
			/* End of complete path. Exit OK. */
			goto out;
		}
		if (*path == '\\') {
			/* End of server name. Go past and break. */
			path++;
			break;
		}
		path++; /* Continue looking for end of server name or string. */
	}

	/* We should now be pointing at the share name. Go past it. */
	for (;;) {
		if (*path == '\0') {
			/* End of complete path. Exit OK. */
			goto out;
		}
		if (*path == '\\') {
			/* End of share name. Go past and break. */
			path++;
			break;
		}
		if (*path == ':') {
			/* Only invalid character in sharename. */
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		path++; /* Continue looking for end of share name or string. */
	}

	/* path now points at the start of the real filename (if any). */

  out:
	/* We have stripped the DFS path prefix (if any). */
	*out_path = path;
	return NT_STATUS_OK;
}

/****************************************************************************
 Pull a string and check the path allowing a wildcard - provide for error return.
 Passes in posix flag.
****************************************************************************/

static size_t srvstr_get_path_internal(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			bool posix_pathnames,
			NTSTATUS *err)
{
	size_t ret;
	char *dst = NULL;

	*pp_dest = NULL;

	ret = srvstr_pull_talloc(ctx, base_ptr, smb_flags2, pp_dest, src,
				 src_len, flags);

	if (!*pp_dest) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return ret;
	}

	dst = *pp_dest;

	if (smb_flags2 & FLAGS2_DFS_PATHNAMES) {
		/*
		 * A valid DFS path looks either like
		 * /server/share
		 * \server\share
		 * (there may be more components after).
		 * Either way it must have at least two separators.
		 *
		 * Ensure we end up as /server/share
		 * so we don't need to special case
		 * separator characters elsewhere in
		 * the code.
		 */
		char *server = NULL;
		char *share = NULL;
		char *remaining_path = NULL;
		char path_sep = 0;
		char *p = NULL;

		if (posix_pathnames && (dst[0] == '/')) {
			path_sep = dst[0];
		} else if (dst[0] == '\\') {
			path_sep = dst[0];
		}

		if (path_sep == 0) {
			goto local_path;
		}
		/*
		 * May be a DFS path.
		 * We need some heuristics here,
		 * as clients differ on what constitutes
		 * a well-formed DFS path. If the path
		 * appears malformed, just fall back to
		 * processing as a local path.
		 */
		server = dst;

		/*
		 * Cosmetic fix for Linux-only DFS clients.
		 * The Linux kernel SMB1 client has a bug - it sends
		 * DFS pathnames as:
		 *
		 * \\server\share\path
		 *
		 * Causing us to mis-parse server,share,remaining_path here
		 * and jump into 'goto local_path' at 'share\path' instead
		 * of 'path'.
		 *
		 * This doesn't cause an error as the limits on share names
		 * are similar to those on pathnames.
		 *
		 * parse_dfs_path() which we call before filename parsing
		 * copes with this by calling trim_char on the leading '\'
		 * characters before processing.
		 * Do the same here so logging of pathnames looks better.
		 */
		if (server[1] == path_sep) {
			trim_char(&server[1], path_sep, '\0');
		}

		/*
		 * Look to see if we also have /share following.
		 */
		share = strchr(server+1, path_sep);
		if (share == NULL) {
			goto local_path;
		}
		/*
		 * Ensure the server name does not contain
		 * any possible path components by converting
		 * them to _'s.
		 */
		for (p = server + 1; p < share; p++) {
			if (*p == '/' || *p == '\\') {
				*p = '_';
			}
		}
		/*
		 * It's a well formed DFS path with
		 * at least server and share components.
		 * Replace the slashes with '/' and
		 * pass the remainder to local_path.
		 */
		*server = '/';
		*share = '/';
		/*
		 * Skip past share so we don't pass the
		 * sharename into check_path_syntax().
		 */
		remaining_path = strchr(share+1, path_sep);
		if (remaining_path == NULL) {
			/*
			 * Ensure the share name does not contain
			 * any possible path components by converting
			 * them to _'s.
			 */
			for (p = share + 1; *p; p++) {
				if (*p == '/' || *p == '\\') {
					*p = '_';
				}
			}
			/*
			 * If no remaining path this was
			 * a bare /server/share path. Just return.
			 */
			*err = NT_STATUS_OK;
			return ret;
		}
		/*
		 * Ensure the share name does not contain
		 * any possible path components by converting
		 * them to _'s.
		 */
		for (p = share + 1; p < remaining_path; p++) {
			if (*p == '/' || *p == '\\') {
				*p = '_';
			}
		}
		*remaining_path = '/';
		dst = remaining_path + 1;
		/* dst now points at any following components. */
	}

  local_path:

	*err = check_path_syntax(dst, posix_pathnames);

	return ret;
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
****************************************************************************/

size_t srvstr_get_path(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err)
{
	return srvstr_get_path_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			false,
			err);
}

/****************************************************************************
 Pull a string and check the path - provide for error return.
 posix_pathnames version.
****************************************************************************/

size_t srvstr_get_path_posix(TALLOC_CTX *ctx,
			const char *base_ptr,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err)
{
	return srvstr_get_path_internal(ctx,
			base_ptr,
			smb_flags2,
			pp_dest,
			src,
			src_len,
			flags,
			true,
			err);
}


size_t srvstr_get_path_req(TALLOC_CTX *mem_ctx, struct smb_request *req,
				 char **pp_dest, const char *src, int flags,
				 NTSTATUS *err)
{
	ssize_t bufrem = smbreq_bufrem(req, src);

	if (bufrem == 0) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return 0;
	}

	if (req->posix_pathnames) {
		return srvstr_get_path_internal(mem_ctx,
				(const char *)req->inbuf,
				req->flags2,
				pp_dest,
				src,
				bufrem,
				flags,
				true,
				err);
	} else {
		return srvstr_get_path_internal(mem_ctx,
				(const char *)req->inbuf,
				req->flags2,
				pp_dest,
				src,
				bufrem,
				flags,
				false,
				err);
	}
}

/**
 * pull a string from the smb_buf part of a packet. In this case the
 * string can either be null terminated or it can be terminated by the
 * end of the smbbuf area
 */
size_t srvstr_pull_req_talloc(TALLOC_CTX *ctx, struct smb_request *req,
			      char **dest, const uint8_t *src, int flags)
{
	ssize_t bufrem = smbreq_bufrem(req, src);

	if (bufrem == 0) {
		*dest = NULL;
		return 0;
	}

	return pull_string_talloc(ctx, req->inbuf, req->flags2, dest, src,
				  bufrem, flags);
}

/****************************************************************************
 Check if we have a correct fsp pointing to a quota fake file. Replacement for
 the CHECK_NTQUOTA_HANDLE_OK macro.
****************************************************************************/

bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp)
{
	if ((fsp == NULL) || (conn == NULL)) {
		return false;
	}

	if ((conn != fsp->conn) || (req->vuid != fsp->vuid)) {
		return false;
	}

	if (fsp->fsp_flags.is_directory) {
		return false;
	}

	if (fsp->fake_file_handle == NULL) {
		return false;
	}

	if (fsp->fake_file_handle->type != FAKE_FILE_TYPE_QUOTA) {
		return false;
	}

	if (fsp->fake_file_handle->private_data == NULL) {
		return false;
	}

	return true;
}

/****************************************************************************
 Return the port number we've bound to on a socket.
****************************************************************************/

static int get_socket_port(int fd)
{
	struct samba_sockaddr saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};

	if (fd == -1) {
		return -1;
	}

	if (getsockname(fd, &saddr.u.sa, &saddr.sa_socklen) < 0) {
		int level = (errno == ENOTCONN) ? 2 : 0;
		DEBUG(level, ("getsockname failed. Error was %s\n",
			       strerror(errno)));
		return -1;
	}

#if defined(HAVE_IPV6)
	if (saddr.u.sa.sa_family == AF_INET6) {
		return ntohs(saddr.u.in6.sin6_port);
	}
#endif
	if (saddr.u.sa.sa_family == AF_INET) {
		return ntohs(saddr.u.in.sin_port);
	}
	return -1;
}

static bool netbios_session_retarget(struct smbXsrv_connection *xconn,
				     const char *name, int name_type)
{
	char *trim_name;
	char *trim_name_type;
	const char *retarget_parm;
	char *retarget;
	char *p;
	int retarget_type = 0x20;
	int retarget_port = NBT_SMB_PORT;
	struct sockaddr_storage retarget_addr;
	struct sockaddr_in *in_addr;
	bool ret = false;
	uint8_t outbuf[10];

	if (get_socket_port(xconn->transport.sock) != NBT_SMB_PORT) {
		return false;
	}

	trim_name = talloc_strdup(talloc_tos(), name);
	if (trim_name == NULL) {
		goto fail;
	}
	trim_char(trim_name, ' ', ' ');

	trim_name_type = talloc_asprintf(trim_name, "%s#%2.2x", trim_name,
					 name_type);
	if (trim_name_type == NULL) {
		goto fail;
	}

	retarget_parm = lp_parm_const_string(-1, "netbios retarget",
					     trim_name_type, NULL);
	if (retarget_parm == NULL) {
		retarget_parm = lp_parm_const_string(-1, "netbios retarget",
						     trim_name, NULL);
	}
	if (retarget_parm == NULL) {
		goto fail;
	}

	retarget = talloc_strdup(trim_name, retarget_parm);
	if (retarget == NULL) {
		goto fail;
	}

	DEBUG(10, ("retargeting %s to %s\n", trim_name_type, retarget));

	p = strchr(retarget, ':');
	if (p != NULL) {
		*p++ = '\0';
		retarget_port = atoi(p);
	}

	p = strchr_m(retarget, '#');
	if (p != NULL) {
		*p++ = '\0';
		if (sscanf(p, "%x", &retarget_type) != 1) {
			goto fail;
		}
	}

	ret = resolve_name(retarget, &retarget_addr, retarget_type, false);
	if (!ret) {
		DEBUG(10, ("could not resolve %s\n", retarget));
		goto fail;
	}

	if (retarget_addr.ss_family != AF_INET) {
		DEBUG(10, ("Retarget target not an IPv4 addr\n"));
		goto fail;
	}

	in_addr = (struct sockaddr_in *)(void *)&retarget_addr;

	_smb_setlen(outbuf, 6);
	SCVAL(outbuf, 0, 0x84);
	*(uint32_t *)(outbuf+4) = in_addr->sin_addr.s_addr;
	*(uint16_t *)(outbuf+8) = htons(retarget_port);

	if (!smb1_srv_send(xconn, (char *)outbuf, false, 0, false)) {
		exit_server_cleanly("netbios_session_retarget: smb1_srv_send "
				    "failed.");
	}

	ret = true;
 fail:
	TALLOC_FREE(trim_name);
	return ret;
}

static void reply_called_name_not_present(char *outbuf)
{
	smb_setlen(outbuf, 1);
	SCVAL(outbuf, 0, 0x83);
	SCVAL(outbuf, 4, 0x82);
}

/****************************************************************************
 Reply to a (netbios-level) special message.
****************************************************************************/

void reply_special(struct smbXsrv_connection *xconn, char *inbuf, size_t inbuf_size)
{
	struct smbd_server_connection *sconn = xconn->client->sconn;
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	/*
	 * We only really use 4 bytes of the outbuf, but for the smb_setlen
	 * calculation & friends (smb1_srv_send uses that) we need the full smb
	 * header.
	 */
	char outbuf[smb_size];

	memset(outbuf, '\0', sizeof(outbuf));

	smb_setlen(outbuf,0);

	switch (msg_type) {
	case NBSSrequest: /* session request */
	{
		/* inbuf_size is guaranteed to be at least 4. */
		fstring name1,name2;
		int name_type1, name_type2;
		int name_len1, name_len2;

		*name1 = *name2 = 0;

		if (xconn->transport.nbt.got_session) {
			exit_server_cleanly("multiple session request not permitted");
		}

		SCVAL(outbuf,0,NBSSpositive);
		SCVAL(outbuf,3,0);

		/* inbuf_size is guaranteed to be at least 4. */
		name_len1 = name_len((unsigned char *)(inbuf+4),inbuf_size - 4);
		if (name_len1 <= 0 || name_len1 > inbuf_size - 4) {
			DEBUG(0,("Invalid name length in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}
		name_len2 = name_len((unsigned char *)(inbuf+4+name_len1),inbuf_size - 4 - name_len1);
		if (name_len2 <= 0 || name_len2 > inbuf_size - 4 - name_len1) {
			DEBUG(0,("Invalid name length in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}

		name_type1 = name_extract((unsigned char *)inbuf,
				inbuf_size,(unsigned int)4,name1);
		name_type2 = name_extract((unsigned char *)inbuf,
				inbuf_size,(unsigned int)(4 + name_len1),name2);

		if (name_type1 == -1 || name_type2 == -1) {
			DEBUG(0,("Invalid name type in session request\n"));
			reply_called_name_not_present(outbuf);
			break;
		}

		DEBUG(2,("netbios connect: name1=%s0x%x name2=%s0x%x\n",
			 name1, name_type1, name2, name_type2));

		if (netbios_session_retarget(xconn, name1, name_type1)) {
			exit_server_cleanly("retargeted client");
		}

		/*
		 * Windows NT/2k uses "*SMBSERVER" and XP uses
		 * "*SMBSERV" arrggg!!!
		 */
		if (strequal(name1, "*SMBSERVER     ")
		    || strequal(name1, "*SMBSERV       "))  {
			char *raddr;

			raddr = tsocket_address_inet_addr_string(sconn->remote_address,
								 talloc_tos());
			if (raddr == NULL) {
				exit_server_cleanly("could not allocate raddr");
			}

			fstrcpy(name1, raddr);
		}

		set_local_machine_name(name1, True);
		set_remote_machine_name(name2, True);

		if (is_ipaddress(sconn->remote_hostname)) {
			char *p = discard_const_p(char, sconn->remote_hostname);

			talloc_free(p);

			sconn->remote_hostname = talloc_strdup(sconn,
						get_remote_machine_name());
			if (sconn->remote_hostname == NULL) {
				exit_server_cleanly("could not copy remote name");
			}
			xconn->remote_hostname = sconn->remote_hostname;
		}

		DEBUG(2,("netbios connect: local=%s remote=%s, name type = %x\n",
			 get_local_machine_name(), get_remote_machine_name(),
			 name_type2));

		if (name_type2 == 'R') {
			/* We are being asked for a pathworks session ---
			   no thanks! */
			reply_called_name_not_present(outbuf);
			break;
		}

		reload_services(sconn, conn_snum_used, true);
		reopen_logs();

		xconn->transport.nbt.got_session = true;
		break;
	}

	case 0x89: /* session keepalive request
		      (some old clients produce this?) */
		SCVAL(outbuf,0,NBSSkeepalive);
		SCVAL(outbuf,3,0);
		break;

	case NBSSpositive: /* positive session response */
	case NBSSnegative: /* negative session response */
	case NBSSretarget: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;

	case NBSSkeepalive: /* session keepalive */
	default:
		return;
	}

	DEBUG(5,("init msg_type=0x%x msg_flags=0x%x\n",
		    msg_type, msg_flags));

	if (!smb1_srv_send(xconn, outbuf, false, 0, false)) {
		exit_server_cleanly("reply_special: smb1_srv_send failed.");
	}

	if (CVAL(outbuf, 0) != 0x82) {
		exit_server_cleanly("invalid netbios session");
	}
	return;
}

/*******************************************************************
 * unlink a file with all relevant access checks
 *******************************************************************/

NTSTATUS unlink_internals(connection_struct *conn,
			struct smb_request *req,
			uint32_t dirtype,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname)
{
	uint32_t fattr;
	files_struct *fsp;
	uint32_t dirtype_orig = dirtype;
	NTSTATUS status;
	int ret;
	struct smb2_create_blobs *posx = NULL;

	if (dirtype == 0) {
		dirtype = FILE_ATTRIBUTE_NORMAL;
	}

	DBG_DEBUG("%s, dirtype = %d\n",
		  smb_fname_str_dbg(smb_fname),
		  dirtype);

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	ret = vfs_stat(conn, smb_fname);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	fattr = fdos_mode(smb_fname->fsp);

	if (dirtype & FILE_ATTRIBUTE_NORMAL) {
		dirtype = FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY;
	}

	dirtype &= (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (!dir_check_ftype(fattr, dirtype)) {
		if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		return NT_STATUS_NO_SUCH_FILE;
	}

	if (dirtype_orig & 0x8000) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

#if 0
	if ((fattr & dirtype) & FILE_ATTRIBUTE_DIRECTORY) {
                return NT_STATUS_FILE_IS_A_DIRECTORY;
        }

        if ((fattr & ~dirtype) & (FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) {
                return NT_STATUS_NO_SUCH_FILE;
        }

	if (dirtype & 0xFF00) {
		/* These will never be set for POSIX. */
		return NT_STATUS_NO_SUCH_FILE;
	}

	dirtype &= 0xFF;
	if (!dirtype) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	/* Can't delete a directory. */
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}
#endif

#if 0 /* JRATEST */
	else if (dirtype & FILE_ATTRIBUTE_DIRECTORY) /* Asked for a directory and it isn't. */
		return NT_STATUS_OBJECT_NAME_INVALID;
#endif /* JRATEST */

	if (smb_fname->flags & SMB_FILENAME_POSIX_PATH) {
		status = make_smb2_posix_create_ctx(
			talloc_tos(), &posx, 0777);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
				    nt_errstr(status));
			return status;
		}
	}

	/* On open checks the open itself will check the share mode, so
	   don't do it here as we'll get it wrong. */

	status = SMB_VFS_CREATE_FILE
		(conn,			/* conn */
		 req,			/* req */
		 dirfsp,			/* dirfsp */
		 smb_fname,		/* fname */
		 DELETE_ACCESS,		/* access_mask */
		 FILE_SHARE_NONE,	/* share_access */
		 FILE_OPEN,		/* create_disposition*/
		 FILE_NON_DIRECTORY_FILE |
			FILE_OPEN_REPARSE_POINT, /* create_options */
		 FILE_ATTRIBUTE_NORMAL,	/* file_attributes */
		 0,			/* oplock_request */
		 NULL,			/* lease */
		 0,			/* allocation_size */
		 0,			/* private_flags */
		 NULL,			/* sd */
		 NULL,			/* ea_list */
		 &fsp,			/* result */
		 NULL,			/* pinfo */
		 posx,			/* in_context_blobs */
		 NULL);			/* out_context_blobs */

	TALLOC_FREE(posx);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("SMB_VFS_CREATEFILE failed: %s\n",
			   nt_errstr(status));
		return status;
	}

	status = can_set_delete_on_close(fsp, fattr);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("can_set_delete_on_close for file %s - "
			"(%s)\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		close_file_free(req, &fsp, NORMAL_CLOSE);
		return status;
	}

	/* The set is across all open files on this dev/inode pair. */
	if (!set_delete_on_close(fsp, True,
				conn->session_info->security_token,
				conn->session_info->unix_token)) {
		close_file_free(req, &fsp, NORMAL_CLOSE);
		return NT_STATUS_ACCESS_DENIED;
	}

	return close_file_free(req, &fsp, NORMAL_CLOSE);
}

/****************************************************************************
 Fake (read/write) sendfile. Returns -1 on read or write fail.
****************************************************************************/

ssize_t fake_sendfile(struct smbXsrv_connection *xconn, files_struct *fsp,
		      off_t startpos, size_t nread)
{
	size_t bufsize;
	size_t tosend = nread;
	char *buf;

	if (nread == 0) {
		return 0;
	}

	bufsize = MIN(nread, 65536);

	if (!(buf = SMB_MALLOC_ARRAY(char, bufsize))) {
		return -1;
	}

	while (tosend > 0) {
		ssize_t ret;
		size_t cur_read;

		cur_read = MIN(tosend, bufsize);
		ret = read_file(fsp,buf,startpos,cur_read);
		if (ret == -1) {
			SAFE_FREE(buf);
			return -1;
		}

		/* If we had a short read, fill with zeros. */
		if (ret < cur_read) {
			memset(buf + ret, '\0', cur_read - ret);
		}

		ret = write_data(xconn->transport.sock, buf, cur_read);
		if (ret != cur_read) {
			int saved_errno = errno;
			/*
			 * Try and give an error message saying what
			 * client failed.
			 */
			DEBUG(0, ("write_data failed for client %s. "
				  "Error %s\n",
				  smbXsrv_connection_dbg(xconn),
				  strerror(saved_errno)));
			SAFE_FREE(buf);
			errno = saved_errno;
			return -1;
		}
		tosend -= cur_read;
		startpos += cur_read;
	}

	SAFE_FREE(buf);
	return (ssize_t)nread;
}

/****************************************************************************
 Deal with the case of sendfile reading less bytes from the file than
 requested. Fill with zeros (all we can do). Returns 0 on success
****************************************************************************/

ssize_t sendfile_short_send(struct smbXsrv_connection *xconn,
			    files_struct *fsp,
			    ssize_t nread,
			    size_t headersize,
			    size_t smb_maxcnt)
{
#define SHORT_SEND_BUFSIZE 1024
	if (nread < headersize) {
		DEBUG(0,("sendfile_short_send: sendfile failed to send "
			"header for file %s (%s). Terminating\n",
			fsp_str_dbg(fsp), strerror(errno)));
		return -1;
	}

	nread -= headersize;

	if (nread < smb_maxcnt) {
		char buf[SHORT_SEND_BUFSIZE] = { 0 };

		DEBUG(0,("sendfile_short_send: filling truncated file %s "
			"with zeros !\n", fsp_str_dbg(fsp)));

		while (nread < smb_maxcnt) {
			/*
			 * We asked for the real file size and told sendfile
			 * to not go beyond the end of the file. But it can
			 * happen that in between our fstat call and the
			 * sendfile call the file was truncated. This is very
			 * bad because we have already announced the larger
			 * number of bytes to the client.
			 *
			 * The best we can do now is to send 0-bytes, just as
			 * a read from a hole in a sparse file would do.
			 *
			 * This should happen rarely enough that I don't care
			 * about efficiency here :-)
			 */
			size_t to_write;
			ssize_t ret;

			to_write = MIN(SHORT_SEND_BUFSIZE, smb_maxcnt - nread);
			ret = write_data(xconn->transport.sock, buf, to_write);
			if (ret != to_write) {
				int saved_errno = errno;
				/*
				 * Try and give an error message saying what
				 * client failed.
				 */
				DEBUG(0, ("write_data failed for client %s. "
					  "Error %s\n",
					  smbXsrv_connection_dbg(xconn),
					  strerror(saved_errno)));
				errno = saved_errno;
				return -1;
			}
			nread += to_write;
		}
	}

	return 0;
}

/*******************************************************************
 Check if a user is allowed to rename a file.
********************************************************************/

static NTSTATUS can_rename(connection_struct *conn, files_struct *fsp,
			uint16_t dirtype)
{
	NTSTATUS status;

	if (fsp->fsp_name->twrp != 0) {
		/* Get the error right, this is what Windows returns. */
		return NT_STATUS_NOT_SAME_DEVICE;
	}

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if ((dirtype & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) !=
			(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
		/* Only bother to read the DOS attribute if we might deny the
		   rename on the grounds of attribute mismatch. */
		uint32_t fmode = fdos_mode(fsp);
		if ((fmode & ~dirtype) & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			return NT_STATUS_NO_SUCH_FILE;
		}
	}

	status = check_any_access_fsp(fsp, DELETE_ACCESS | FILE_WRITE_ATTRIBUTES);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Ensure open files have their names updated. Updated to notify other smbd's
 asynchronously.
****************************************************************************/

static void rename_open_files(connection_struct *conn,
			      struct share_mode_lock *lck,
			      struct file_id id,
			      uint32_t orig_name_hash,
			      const struct smb_filename *smb_fname_dst)
{
	files_struct *fsp;
	bool did_rename = False;
	NTSTATUS status;
	uint32_t new_name_hash = 0;

	for(fsp = file_find_di_first(conn->sconn, id, false); fsp;
	    fsp = file_find_di_next(fsp, false)) {
		SMB_STRUCT_STAT fsp_orig_sbuf;
		struct file_id_buf idbuf;
		/* fsp_name is a relative path under the fsp. To change this for other
		   sharepaths we need to manipulate relative paths. */
		/* TODO - create the absolute path and manipulate the newname
		   relative to the sharepath. */
		if (!strequal(fsp->conn->connectpath, conn->connectpath)) {
			continue;
		}
		if (fsp->name_hash != orig_name_hash) {
			continue;
		}
		DBG_DEBUG("renaming file %s "
			  "(file_id %s) from %s -> %s\n",
			  fsp_fnum_dbg(fsp),
			  file_id_str_buf(fsp->file_id, &idbuf),
			  fsp_str_dbg(fsp),
			  smb_fname_str_dbg(smb_fname_dst));

		/*
		 * The incoming smb_fname_dst here has an
		 * invalid stat struct (it must not have
		 * existed for the rename to succeed).
		 * Preserve the existing stat from the
		 * open fsp after fsp_set_smb_fname()
		 * overwrites with the invalid stat.
		 *
		 * We will do an fstat before returning
		 * any of this metadata to the client anyway.
		 */
		fsp_orig_sbuf = fsp->fsp_name->st;
		status = fsp_set_smb_fname(fsp, smb_fname_dst);
		if (NT_STATUS_IS_OK(status)) {
			did_rename = True;
			new_name_hash = fsp->name_hash;
			/* Restore existing stat. */
			fsp->fsp_name->st = fsp_orig_sbuf;
		}
	}

	if (!did_rename) {
		struct file_id_buf idbuf;
		DBG_DEBUG("no open files on file_id %s "
			  "for %s\n",
			  file_id_str_buf(id, &idbuf),
			  smb_fname_str_dbg(smb_fname_dst));
	}

	/* Send messages to all smbd's (not ourself) that the name has changed. */
	rename_share_filename(conn->sconn->msg_ctx, lck, id, conn->connectpath,
			      orig_name_hash, new_name_hash,
			      smb_fname_dst);

}

/****************************************************************************
 We need to check if the source path is a parent directory of the destination
 (ie. a rename of /foo/bar/baz -> /foo/bar/baz/bibble/bobble. If so we must
 refuse the rename with a sharing violation. Under UNIX the above call can
 *succeed* if /foo/bar/baz is a symlink to another area in the share. We
 probably need to check that the client is a Windows one before disallowing
 this as a UNIX client (one with UNIX extensions) can know the source is a
 symlink and make this decision intelligently. Found by an excellent bug
 report from <AndyLiebman@aol.com>.
****************************************************************************/

static bool rename_path_prefix_equal(const struct smb_filename *smb_fname_src,
				     const struct smb_filename *smb_fname_dst)
{
	const char *psrc = smb_fname_src->base_name;
	const char *pdst = smb_fname_dst->base_name;
	size_t slen;

	if (psrc[0] == '.' && psrc[1] == '/') {
		psrc += 2;
	}
	if (pdst[0] == '.' && pdst[1] == '/') {
		pdst += 2;
	}
	if ((slen = strlen(psrc)) > strlen(pdst)) {
		return False;
	}
	return ((memcmp(psrc, pdst, slen) == 0) && pdst[slen] == '/');
}

/*
 * Do the notify calls from a rename
 */

static void notify_rename(struct connection_struct *conn,
			  struct files_struct *fsp,
			  const struct smb_filename *smb_fname_src,
			  const struct smb_filename *smb_fname_dst)
{
	bool is_dir = fsp->fsp_flags.is_directory;
	char *parent_dir_src = NULL;
	char *parent_dir_dst = NULL;
	uint32_t mask;

	mask = is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME
		: FILE_NOTIFY_CHANGE_FILE_NAME;

	if (!parent_dirname(talloc_tos(), smb_fname_src->base_name,
			    &parent_dir_src, NULL) ||
	    !parent_dirname(talloc_tos(), smb_fname_dst->base_name,
			    &parent_dir_dst, NULL)) {
		goto out;
	}

	if (strcmp(parent_dir_src, parent_dir_dst) == 0) {
		notify_fname(conn,
			     NOTIFY_ACTION_OLD_NAME,
			     mask,
			     smb_fname_src,
			     NULL);
		notify_fname(conn,
			     NOTIFY_ACTION_NEW_NAME |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     mask,
			     smb_fname_dst,
			     fsp_get_smb2_lease(fsp));
	}
	else {
		notify_fname(conn,
			     NOTIFY_ACTION_REMOVED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     mask,
			     smb_fname_src,
			     fsp_get_smb2_lease(fsp));
		notify_fname(conn,
			     NOTIFY_ACTION_ADDED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     mask,
			     smb_fname_dst,
			     fsp_get_smb2_lease(fsp));
	}

	/* this is a strange one. w2k3 gives an additional event for
	   CHANGE_ATTRIBUTES and CHANGE_CREATION on the new file when renaming
	   files, but not directories */
	if (!is_dir) {
		notify_fname(conn,
			     NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES |
				     FILE_NOTIFY_CHANGE_CREATION,
			     smb_fname_dst,
			     NULL);
	}
 out:
	TALLOC_FREE(parent_dir_src);
	TALLOC_FREE(parent_dir_dst);
}

struct rename_check_open_state {
	struct files_struct *dst_fsp;
	struct file_id fileid;
};

static struct files_struct *rename_check_open_fn(struct files_struct *fsp,
						 void *private_data)
{
	struct rename_check_open_state *state = private_data;

	if (fsp == state->dst_fsp) {
		return NULL;
	}

	if (!fsp->fsp_flags.is_fsa) {
		return NULL;
	}

	if (!file_id_equal(&fsp->file_id, &state->fileid)) {
		return NULL;
	}

	return fsp;
}

/****************************************************************************
 Rename an open file - given an fsp.
****************************************************************************/

NTSTATUS rename_internals_fsp(connection_struct *conn,
			      struct files_struct *src_dirfsp,
			      files_struct *fsp,
			      struct smb_filename *smb_fname_src_rel,
			      struct share_mode_lock **_lck,
			      struct smb_filename *smb_fname_dst_in,
			      const char *dst_original_lcomp,
			      uint32_t attrs,
			      const char *newname,
			      bool replace_if_exists)
{
	TALLOC_CTX *ctx = talloc_stackframe();
	struct smb_filename *smb_fname_src = fsp->fsp_name;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	struct smb_filename *smb_fname_dst_rel = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct share_mode_lock *lck = NULL;
	int ret;
	bool case_preserve = fsp->fsp_flags.posix_open || conn->case_preserve;
	struct vfs_rename_how rhow = { .flags = 0, };

	if (file_has_open_streams(fsp)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	if (fsp_is_alternate_stream(fsp)) {
		if (newname[0] != ':') {
			return NT_STATUS_INVALID_PARAMETER;
		}

		smb_fname_dst = synthetic_smb_fname(ctx,
						    smb_fname_src->base_name,
						    newname,
						    NULL,
						    0,
						    smb_fname_src->flags);
		if (smb_fname_dst == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (is_ntfs_default_stream_smb_fname(smb_fname_dst)) {
			status = replace_if_exists
					 ? NT_STATUS_NOT_SUPPORTED
					 : NT_STATUS_OBJECT_NAME_COLLISION;
			goto out;
		}

		ret = SMB_VFS_RENAME_STREAM(fsp->conn,
					    fsp,
					    newname,
					    replace_if_exists);
		goto inform_others;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 newname,
					 fsp->fsp_flags.posix_open
						 ? UCF_POSIX_PATHNAMES |
							   UCF_LCOMP_LNK_OK
						 : 0,
					 smb_fname_src->twrp,
					 &dst_dirfsp,
					 &smb_fname_dst);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (is_ntfs_stream_smb_fname(smb_fname_dst)) {
		/*
		 * We handled streams above
		 */
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto out;
	}

	{
		/*
		 * Get the lcomp as the client sent it. For a pure
		 * case change smb_fname_dst exists, but
		 * filename_convert_dirfsp has removed the client's
		 * intent by doing the case-insensitive lookup.
		 */

		char *lcomp = get_original_lcomp(ctx, conn, newname, 0);
		if (lcomp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		smb_fname_dst_rel = synthetic_smb_fname(
			ctx, lcomp, NULL, NULL, 0, 0);
		TALLOC_FREE(lcomp);

		if (smb_fname_dst_rel == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (!case_preserve &&
	    strequal(smb_fname_src->base_name, smb_fname_dst->base_name))
	{
		/*
		 * src and dst are the same except for the
		 * case. Because we don't preserve the case, we can
		 * just return success. Streams handled above.
		 */
		status = NT_STATUS_OK;
		goto out;
	}

	if (strcsequal(src_dirfsp->fsp_name->base_name,
		       dst_dirfsp->fsp_name->base_name))
	{
		/*
		 * Same directory
		 */
		if (strcsequal(smb_fname_src_rel->base_name,
			       smb_fname_dst_rel->base_name))
		{
			/*
			 * No file name change
			 */
			status = NT_STATUS_OK;
			goto out;
		}

		if (strequal(smb_fname_src_rel->base_name,
			     smb_fname_dst_rel->base_name))
		{
			/*
			 * Change the case of a file, mark the dst as
			 * nonexisting.
			 */
			SET_STAT_INVALID(smb_fname_dst->st);
		}
	}

	if (VALID_STAT(smb_fname_dst->st)) {

		struct rename_check_open_state check_state = {
			.dst_fsp = smb_fname_dst->fsp,
		};
		struct files_struct *found_open = NULL;

		if (!replace_if_exists) {
			DBG_NOTICE("dest exists doing rename "
				   "%s -> %s\n",
				   smb_fname_str_dbg(smb_fname_src),
				   smb_fname_str_dbg(smb_fname_dst));
			status = NT_STATUS_OBJECT_NAME_COLLISION;
			goto out;
		}

		check_state.fileid = vfs_file_id_from_sbuf(conn,
							   &smb_fname_dst->st);

		found_open = files_forall(conn->sconn,
					  rename_check_open_fn,
					  &check_state);
		if (found_open != NULL) {
			DBG_NOTICE("Target file open\n");
			status = NT_STATUS_ACCESS_DENIED;
			goto out;
		}
	}

	status = can_rename(conn, fsp, attrs);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Error %s rename %s -> %s\n",
			   nt_errstr(status),
			   fsp_str_dbg(fsp),
			   smb_fname_str_dbg(smb_fname_dst));
		if (NT_STATUS_EQUAL(status,NT_STATUS_SHARING_VIOLATION))
			status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	if (rename_path_prefix_equal(fsp->fsp_name, smb_fname_dst)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	status = check_parent_access_fsp(dst_dirfsp,
					 S_ISDIR(fsp->fsp_name->st.st_ex_mode)
						 ? SEC_DIR_ADD_SUBDIR
						 : SEC_DIR_ADD_FILE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("check_parent_access_fsp on "
			"dst %s returned %s\n",
			smb_fname_str_dbg(smb_fname_dst),
			nt_errstr(status));
		goto out;
	}

	ret = SMB_VFS_RENAMEAT(conn,
			       src_dirfsp,
			       smb_fname_src_rel,
			       dst_dirfsp,
			       smb_fname_dst_rel,
			       &rhow);

inform_others:

	if (_lck != NULL) {
		lck = talloc_move(talloc_tos(), _lck);
	} else {
		lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	}

	/*
	 * We have the file open ourselves, so not being able to get the
	 * corresponding share mode lock is a fatal error.
	 */

	SMB_ASSERT(lck != NULL);

	if (ret == 0) {
		struct smb_filename *old_fname = NULL;

		DBG_NOTICE("succeeded doing rename on "
			   "%s -> %s\n",
			   smb_fname_str_dbg(fsp->fsp_name),
			   smb_fname_str_dbg(smb_fname_dst));

		old_fname = cp_smb_filename(talloc_tos(), fsp->fsp_name);
		if (old_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			TALLOC_FREE(lck);
			goto out;
		}
		rename_open_files(conn, lck, fsp->file_id, fsp->name_hash,
				  smb_fname_dst);

		if (!fsp->fsp_flags.is_directory &&
		    (lp_map_archive(SNUM(conn)) ||
		     lp_store_dos_attributes(SNUM(conn))))
		{
			/*
			 * We must set the archive bit on the newly renamed
			 * file.
			 */
			status = vfs_stat_fsp(fsp);
			if (NT_STATUS_IS_OK(status)) {
				uint32_t old_dosmode;
				old_dosmode = fdos_mode(fsp);
				/*
				 * We can use fsp->fsp_name here as it has
				 * already been changed to the new name.
				 */
				SMB_ASSERT(fsp->fsp_name->fsp == fsp);
				file_set_dosmode(conn,
						fsp->fsp_name,
						old_dosmode | FILE_ATTRIBUTE_ARCHIVE,
						NULL,
						true);
			}
		}

		TALLOC_FREE(lck);

		notify_rename(conn,
			      fsp,
			      old_fname,
			      smb_fname_dst);

		TALLOC_FREE(old_fname);
		status = NT_STATUS_OK;
		goto out;
	}

	TALLOC_FREE(lck);

	if (errno == ENOTDIR || errno == EISDIR) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
	} else {
		status = map_nt_error_from_unix(errno);
	}

	DBG_NOTICE("Error %s rename %s -> %s\n",
		   nt_errstr(status),
		   smb_fname_str_dbg(fsp->fsp_name),
		   smb_fname_str_dbg(smb_fname_dst));

 out:
	TALLOC_FREE(ctx);
	return status;
}

/****************************************************************************
 The guts of the rename command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS rename_internals(TALLOC_CTX *ctx,
			  connection_struct *conn,
			  struct smb_request *req,
			  struct files_struct *src_dirfsp,
			  struct smb_filename *smb_fname_src,
			  struct smb_filename *smb_fname_src_rel,
			  struct smb_filename *smb_fname_dst,
			  const char *dst_original_lcomp,
			  uint32_t attrs,
			  const char *newname,
			  bool replace_if_exists,
			  uint32_t access_mask)
{
	NTSTATUS status = NT_STATUS_OK;
	int create_options = FILE_OPEN_REPARSE_POINT;
	struct smb2_create_blobs *posx = NULL;
	struct files_struct *fsp = NULL;
	bool posix_pathname = (smb_fname_src->flags & SMB_FILENAME_POSIX_PATH);
	bool case_sensitive = posix_pathname || conn->case_sensitive;
	bool case_preserve = posix_pathname || conn->case_preserve;
	bool short_case_preserve = posix_pathname || conn->short_case_preserve;

	if (posix_pathname) {
		status = make_smb2_posix_create_ctx(talloc_tos(), &posx, 0777);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
				    nt_errstr(status));
			goto out;
		}
	}

	DBG_NOTICE("case_sensitive = %d, "
		  "case_preserve = %d, short case preserve = %d, "
		  "directory = %s, newname = %s, "
		  "last_component_dest = %s\n",
		  case_sensitive, case_preserve,
		  short_case_preserve,
		  smb_fname_str_dbg(smb_fname_src),
		  smb_fname_str_dbg(smb_fname_dst),
		  dst_original_lcomp);

	ZERO_STRUCT(smb_fname_src->st);

	status = openat_pathref_fsp(conn->cwd_fsp, smb_fname_src);
	if (!NT_STATUS_IS_OK(status)) {
		if (!NT_STATUS_EQUAL(status,
				NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			goto out;
		}
		/*
		 * Possible symlink src.
		 */
		if (!(smb_fname_src->flags & SMB_FILENAME_POSIX_PATH)) {
			goto out;
		}
		if (!S_ISLNK(smb_fname_src->st.st_ex_mode)) {
			goto out;
		}
	}

	if (S_ISDIR(smb_fname_src->st.st_ex_mode)) {
		create_options |= FILE_DIRECTORY_FILE;
	}

	status = SMB_VFS_CREATE_FILE(
			conn,				/* conn */
			req,				/* req */
			src_dirfsp,			/* dirfsp */
			smb_fname_src,			/* fname */
			access_mask,			/* access_mask */
			(FILE_SHARE_READ |		/* share_access */
			    FILE_SHARE_WRITE),
			FILE_OPEN,			/* create_disposition*/
			create_options,			/* create_options */
			0,				/* file_attributes */
			0,				/* oplock_request */
			NULL,				/* lease */
			0,				/* allocation_size */
			0,				/* private_flags */
			NULL,				/* sd */
			NULL,				/* ea_list */
			&fsp,				/* result */
			NULL,				/* pinfo */
			posx,				/* in_context_blobs */
			NULL);				/* out_context_blobs */

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Could not open rename source %s: %s\n",
			  smb_fname_str_dbg(smb_fname_src),
			  nt_errstr(status));
		goto out;
	}

	/*
	 * If no pathnames are open below this directory, allow the rename.
	 */
	if (have_file_open_below(fsp)) {
		status = NT_STATUS_ACCESS_DENIED;
		close_file_free(req, &fsp, NORMAL_CLOSE);
		goto out;
	}

	status = rename_internals_fsp(conn,
				      src_dirfsp,
				      fsp,
				      smb_fname_src_rel,
				      NULL,
				      smb_fname_dst,
				      dst_original_lcomp,
				      attrs,
				      newname,
				      replace_if_exists);

	close_file_free(req, &fsp, NORMAL_CLOSE);

	DBG_NOTICE("Error %s rename %s -> %s\n",
		  nt_errstr(status), smb_fname_str_dbg(smb_fname_src),
		  smb_fname_str_dbg(smb_fname_dst));

 out:
	TALLOC_FREE(posx);
	return status;
}

/*******************************************************************
 Copy a file as part of a reply_copy.
******************************************************************/

/*
 * TODO: check error codes on all callers
 */

NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			uint32_t new_create_disposition)
{
	struct smb_filename *smb_fname_dst_tmp = NULL;
	off_t ret=-1;
	files_struct *fsp1,*fsp2;
	uint32_t dosattrs;
	NTSTATUS status;


	smb_fname_dst_tmp = cp_smb_filename(ctx, smb_fname_dst);
	if (smb_fname_dst_tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = openat_pathref_fsp(conn->cwd_fsp, smb_fname_src);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* Open the src file for reading. */
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		NULL,					/* dirfsp */
		smb_fname_src,	       			/* fname */
		FILE_GENERIC_READ,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		FILE_OPEN,				/* create_disposition*/
		FILE_NON_DIRECTORY_FILE,		/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp1,					/* result */
		NULL,					/* psbuf */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	dosattrs = fdos_mode(fsp1);

	if (SMB_VFS_STAT(conn, smb_fname_dst_tmp) == -1) {
		ZERO_STRUCTP(&smb_fname_dst_tmp->st);
	}

	status = openat_pathref_fsp(conn->cwd_fsp, smb_fname_dst);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND))
	{
		goto out;
	}

	/* Open the dst file for writing. */
	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		NULL,					/* req */
		NULL,					/* dirfsp */
		smb_fname_dst,				/* fname */
		FILE_GENERIC_WRITE,			/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE,	/* share_access */
		new_create_disposition,			/* create_disposition*/
		0,					/* create_options */
		dosattrs,				/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp2,					/* result */
		NULL,					/* psbuf */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		close_file_free(NULL, &fsp1, ERROR_CLOSE);
		goto out;
	}

	/* Do the actual copy. */
	if (smb_fname_src->st.st_ex_size) {
		ret = vfs_transfer_file(fsp1, fsp2, smb_fname_src->st.st_ex_size);
	} else {
		ret = 0;
	}

	close_file_free(NULL, &fsp1, NORMAL_CLOSE);

	/* Ensure the modtime is set correctly on the destination file. */
	set_close_write_time(fsp2, smb_fname_src->st.st_ex_mtime);

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	status = close_file_free(NULL, &fsp2, NORMAL_CLOSE);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (ret != (off_t)smb_fname_src->st.st_ex_size) {
		status = NT_STATUS_DISK_FULL;
		goto out;
	}

	status = NT_STATUS_OK;

 out:
	TALLOC_FREE(smb_fname_dst_tmp);
	return status;
}

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

uint64_t get_lock_offset(const uint8_t *data, int data_offset,
			 bool large_file_format)
{
	uint64_t offset = 0;

	if(!large_file_format) {
		offset = (uint64_t)IVAL(data,SMB_LKOFF_OFFSET(data_offset));
	} else {
		/*
		 * No BVAL, this is reversed!
		 */
		offset = (((uint64_t) IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) << 32) |
				((uint64_t) IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset)));
	}

	return offset;
}

static void smbd_do_unlocking_fn(struct share_mode_lock *lck,
				 struct byte_range_lock *br_lck,
				 void *private_data)
{
	struct smbd_do_locks_state *state = private_data;
	struct files_struct *fsp = brl_fsp(br_lck);
	uint16_t i;

	/*
	 * The caller has checked fsp->fsp_flags.can_lock and lp_locking so
	 * br_lck has to be there!
	 */
	SMB_ASSERT(br_lck != NULL);

	for (i = 0; i < state->num_locks; i++) {
		struct smbd_lock_element *e = &state->locks[i];

		DBG_DEBUG("unlock start=%"PRIu64", len=%"PRIu64" for "
			  "pid %"PRIu64", file %s\n",
			  e->offset,
			  e->count,
			  e->smblctx,
			  fsp_str_dbg(fsp));

		if (e->brltype != UNLOCK_LOCK) {
			/* this can only happen with SMB2 */
			state->status = NT_STATUS_INVALID_PARAMETER;
			return;
		}

		state->status = do_unlock(
			br_lck, e->smblctx, e->count, e->offset, e->lock_flav);

		DBG_DEBUG("do_unlock returned %s\n",
			  nt_errstr(state->status));

		if (!NT_STATUS_IS_OK(state->status)) {
			return;
		}
	}

	share_mode_wakeup_waiters(fsp->file_id);
}

NTSTATUS smbd_do_unlocking(struct smb_request *req,
			   files_struct *fsp,
			   uint16_t num_ulocks,
			   struct smbd_lock_element *ulocks)
{
	struct smbd_do_locks_state state = {
		.num_locks = num_ulocks,
		.locks = ulocks,
	};
	NTSTATUS status;

	DBG_NOTICE("%s num_ulocks=%"PRIu16"\n", fsp_fnum_dbg(fsp), num_ulocks);

	if (!fsp->fsp_flags.can_lock) {
		if (fsp->fsp_flags.is_directory) {
			return NT_STATUS_INVALID_DEVICE_REQUEST;
		}
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!lp_locking(fsp->conn->params)) {
		return NT_STATUS_OK;
	}

	status = share_mode_do_locked_brl(fsp,
					  smbd_do_unlocking_fn,
					  &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("share_mode_do_locked_brl failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("smbd_do_unlocking_fn failed: %s\n",
			  nt_errstr(status));
		return state.status;
	}

	return NT_STATUS_OK;
}
