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

/*
  SMB2 lease structure (per MS-SMB2 2.2.13)
*/
struct smb2_lease_key {
	uint64_t data[2];
};

struct smb2_lease {
	struct smb2_lease_key lease_key;
	uint32_t lease_state;
	uint32_t lease_flags;
	uint64_t lease_duration; /* should be 0 */
	/* only for v2 */
	struct smb2_lease_key parent_lease_key;
	uint16_t lease_epoch;
};

#endif /* _LIBCLI_SMB_SMB2_LEASE_H_ */
