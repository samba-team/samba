/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (c) 2025      John Mulligan <jmulligan@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _VARLINK_KEYBRIDGE_H
#define _VARLINK_KEYBRIDGE_H
/*
 * The keybridge is a simple varlink based protocol used to fetch
 * configuration data, in particular key material for encrypted
 * cephfs, that samba can use when setting up a share.
 * The keybridge server may or may not be a proxy for more complex
 * remote protocols that use (m)TLS HTTPS APIs to remote servers.
 * keybridge aims to hide all that from samba and use a simple
 * local API that is an existing samba dependency.
 */

/* kind describes how the data is stored:
 * DEFAULT - unspecified - typically VALUE
 * B64 - base64 encoded binary data
 * VALUE - plain (UTF8) string
 */
enum varlink_keybridge_kind {
	VARLINK_KEYBRIDGE_KIND_DEFAULT = 0,
	VARLINK_KEYBRIDGE_KIND_B64,
	VARLINK_KEYBRIDGE_KIND_VALUE
};

/* status of a keybridge api call */
enum varlink_keybridge_status {
	/* protocol/connection error */
	VARLINK_KEYBRIDGE_STATUS_FAILURE = 0,
	/* result is successful */
	VARLINK_KEYBRIDGE_STATUS_OK,
	/* server returned an error message */
	VARLINK_KEYBRIDGE_STATUS_ERROR,
};

/* parameters for an outgoing api Get entry call */
struct varlink_keybridge_config {
	/* path to socket with unix: prefix */
	char *path;
	/* keybridge scope */
	char *scope;
	/* keybridge entry name */
	char *name;
	/* keybridge entry kind (data format) */
	enum varlink_keybridge_kind kind;
};

/* Get entry call results */
struct varlink_keybridge_result {
	enum varlink_keybridge_status status;
	/* data kind */
	enum varlink_keybridge_kind kind;
	/* result data or error string */
	char *data;
};

/* Get a requested entry.
 * returns true if result was populated
 * result will be assigned a newly allocated result (from mem_ctx)
 */
bool varlink_keybridge_entry_get(TALLOC_CTX *mem_ctx,
				 const struct varlink_keybridge_config *kbc,
				 struct varlink_keybridge_result **resp);

#endif /* _VARLINK_KEYBRIDGE_H */
