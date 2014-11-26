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

#include "includes.h"
#include "../libcli/smb/smb_common.h"

ssize_t smb2_lease_pull(const uint8_t *buf, size_t len,
			struct smb2_lease *lease)
{
	int version;

	switch (len) {
	case 32:
		version = 1;
		break;
	case 52:
		version = 2;
		break;
	default:
		return -1;
	}

	memcpy(&lease->lease_key, buf, 16);
	lease->lease_state = IVAL(buf, 16);
	lease->lease_flags = IVAL(buf, 20);
	lease->lease_duration = BVAL(buf, 24);
	lease->lease_version = version;

	switch (version) {
	case 1:
		ZERO_STRUCT(lease->parent_lease_key);
		lease->lease_epoch = 0;
		break;
	case 2:
		memcpy(&lease->parent_lease_key, buf+32, 16);
		lease->lease_epoch = SVAL(buf, 48);
		break;
	}

	return len;
}

bool smb2_lease_push(const struct smb2_lease *lease, uint8_t *buf, size_t len)
{
	int version;

	switch (len) {
	case 32:
		version = 1;
		break;
	case 52:
		version = 2;
		break;
	default:
		return false;
	}

	memcpy(&buf[0], &lease->lease_key, 16);
	SIVAL(buf, 16, lease->lease_state);
	SIVAL(buf, 20, lease->lease_flags);
	SBVAL(buf, 24, lease->lease_duration);

	if (version == 2) {
		memcpy(&buf[32], &lease->parent_lease_key, 16);
		SIVAL(buf, 48, lease->lease_epoch);
	}

	return true;
}

bool smb2_lease_key_equal(const struct smb2_lease_key *k1,
			  const struct smb2_lease_key *k2)
{
	return ((k1->data[0] == k2->data[0]) && (k1->data[1] == k2->data[1]));
}

bool smb2_lease_equal(const struct GUID *g1,
		      const struct smb2_lease_key *k1,
		      const struct GUID *g2,
		      const struct smb2_lease_key *k2)
{
	return GUID_equal(g1, g2) && smb2_lease_key_equal(k1, k2);
}
