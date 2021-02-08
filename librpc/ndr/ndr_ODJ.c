/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special ODJ structures

   Copyright (C) Guenther Deschner 2021

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
#include "../librpc/gen_ndr/ndr_ODJ.h"
#include "../librpc/ndr/ndr_ODJ.h"

uint32_t odj_switch_level_from_guid(const struct GUID *r)
{
	struct {
		uint16_t level;
		const char *guid;
	} levels[] = {
		{
			.level	= 1,
			.guid	= ODJ_GUID_JOIN_PROVIDER
		},{
			.level	= 2,
			.guid	= ODJ_GUID_JOIN_PROVIDER2
		},{
			.level	= 3,
			.guid	= ODJ_GUID_JOIN_PROVIDER3
		},{
			.level	= 4,
			.guid	= ODJ_GUID_CERT_PROVIDER
		},{
			.level	= 5,
			.guid	= ODJ_GUID_POLICY_PROVIDER
		}
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		struct GUID guid;
		NTSTATUS status;

		status = GUID_from_string(levels[i].guid, &guid);
		if (!NT_STATUS_IS_OK(status)) {
			return 0;
		}
		if (GUID_equal(&guid, r)) {
			return levels[i].level;
		}
	}

	return 0;
}
