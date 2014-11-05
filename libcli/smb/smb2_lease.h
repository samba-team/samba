/*
   Unix SMB/CIFS implementation.

   SMB2 Lease context handling

   Copyright (C) Stefan Metzmacher 2012
   Copyright (C) Volker Lendecke 2013

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

#ifndef _LIBCLI_SMB_SMB2_LEASE_H_
#define _LIBCLI_SMB_SMB2_LEASE_H_

#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/smb2_lease_struct.h"

/*
 * Parse a smb2 lease create context. Return -1 on error, buffer.length on
 * success. V1 and V2 differ only by length of buffer.length
 */
ssize_t smb2_lease_pull(const uint8_t *buf, size_t len,
			struct smb2_lease *lease);
bool smb2_lease_push(const struct smb2_lease *lease, uint8_t *buf, size_t len);
bool smb2_lease_key_equal(const struct smb2_lease_key *k1,
			  const struct smb2_lease_key *k2);
bool smb2_lease_equal(const struct GUID *g1,
		      const struct smb2_lease_key *k1,
		      const struct GUID *g2,
		      const struct smb2_lease_key *k2);

#endif /* _LIBCLI_SMB_SMB2_LEASE_H_ */
