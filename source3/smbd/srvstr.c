/* 
   Unix SMB/CIFS implementation.
   server specific string routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
   
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
#include "smbd/smbd.h"
#include "smbd/globals.h"

/* Make sure we can't write a string past the end of the buffer */

NTSTATUS srvstr_push_fn(const char *base_ptr, uint16 smb_flags2, void *dest,
		      const char *src, int dest_len, int flags, size_t *ret_len)
{
	size_t len;
	int saved_errno;
	NTSTATUS status;

	if (dest_len < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	saved_errno = errno;
	errno = 0;

	/* 'normal' push into size-specified buffer */
	len = push_string_base(base_ptr, smb_flags2, dest, src,
				dest_len, flags);

	if (errno != 0) {
		/*
		 * Special case E2BIG, EILSEQ, EINVAL
		 * as they mean conversion errors here,
		 * but we don't generically map them as
		 * they can mean different things in
		 * generic filesystem calls (such as
		 * read xattrs).
		 */
		if (errno == E2BIG || errno == EILSEQ || errno == EINVAL) {
			status = NT_STATUS_ILLEGAL_CHARACTER;
		} else {
			status = map_nt_error_from_unix_common(errno);
			/*
			 * Paranoia - Filter out STATUS_MORE_ENTRIES.
			 * I don't think we can get this but it has a
			 * specific meaning to the client.
			 */
			if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				status = NT_STATUS_UNSUCCESSFUL;
			}
		}
		DEBUG(10,("character conversion failure "
			"on string (%s) (%s)\n",
			src, strerror(errno)));
	} else {
		/* Success - restore untouched errno. */
		errno = saved_errno;
		*ret_len = len;
		status = NT_STATUS_OK;
	}
	return status;
}

/*******************************************************************
 Add a string to the end of a smb_buf, adjusting bcc and smb_len.
 Return the bytes added
********************************************************************/

ssize_t message_push_string(uint8 **outbuf, const char *str, int flags)
{
	size_t buf_size = smb_len(*outbuf) + 4;
	size_t grow_size;
	size_t result = 0;
	uint8 *tmp;
	NTSTATUS status;

	/*
	 * We need to over-allocate, now knowing what srvstr_push will
	 * actually use. This is very generous by incorporating potential
	 * padding, the terminating 0 and at most 4 chars per UTF-16 code
	 * point.
	 */
	grow_size = (strlen(str) + 2) * 4;

	if (!(tmp = talloc_realloc(NULL, *outbuf, uint8,
					 buf_size + grow_size))) {
		DEBUG(0, ("talloc failed\n"));
		return -1;
	}

	status = srvstr_push((char *)tmp, SVAL(tmp, smb_flg2),
			     tmp + buf_size, str, grow_size, flags, &result);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("srvstr_push failed\n"));
		return -1;
	}
	set_message_bcc((char *)tmp, smb_buflen(tmp) + result);

	*outbuf = tmp;

	return result;
}
