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
#include "smb1_utils.h"
#include "libcli/smb/smb2_posix.h"
#include "lib/util/string_wrappers.h"
#include "source3/printing/rap_jobid.h"
#include "source3/lib/substitute.h"

/****************************************************************************
 Ensure we check the path in *exactly* the same way as W2K for a findfirst/findnext
 path or anything including wildcards.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption). '\\' *may* be the second byte in a multibyte char
 set.
****************************************************************************/

/* Custom version for processing POSIX paths. */
#define IS_PATH_SEP(c,posix_only) ((c) == '/' || (!(posix_only) && (c) == '\\'))

static NTSTATUS check_path_syntax_internal(char *path,
					   bool posix_path)
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
			size_t siz;
			/* Get the size of the next MB character. */
			next_codepoint(s,&siz);
			switch(siz) {
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
					DEBUG(0,("check_path_syntax_internal: character length assumptions invalid !\n"));
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
 Ensure we check the path in *exactly* the same way as W2K for regular pathnames.
 No wildcards allowed.
****************************************************************************/

NTSTATUS check_path_syntax(char *path)
{
	return check_path_syntax_internal(path, false);
}

/****************************************************************************
 Check the path for a POSIX client.
 We're assuming here that '/' is not the second byte in any multibyte char
 set (a safe assumption).
****************************************************************************/

NTSTATUS check_path_syntax_posix(char *path)
{
	return check_path_syntax_internal(path, true);
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

	*pp_dest = NULL;

	ret = srvstr_pull_talloc(ctx, base_ptr, smb_flags2, pp_dest, src,
				 src_len, flags);

	if (!*pp_dest) {
		*err = NT_STATUS_INVALID_PARAMETER;
		return ret;
	}

	if (smb_flags2 & FLAGS2_DFS_PATHNAMES) {
		/*
		 * For a DFS path the function parse_dfs_path()
		 * will do the path processing, just make a copy.
		 */
		*err = NT_STATUS_OK;
		return ret;
	}

	if (posix_pathnames) {
		*err = check_path_syntax_posix(*pp_dest);
	} else {
		*err = check_path_syntax(*pp_dest);
	}

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

	if (bufrem < 0) {
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

	if (bufrem < 0) {
		return 0;
	}

	return pull_string_talloc(ctx, req->inbuf, req->flags2, dest, src,
				  bufrem, flags);
}
