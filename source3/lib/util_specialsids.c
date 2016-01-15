/*
   Unix SMB/CIFS implementation.
   Copyright (C) Guenther Deschner 2016

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
#include "../libcli/security/security.h"

bool sid_check_is_asserted_identity(const struct dom_sid *sid)
{
	return dom_sid_equal(sid, &global_sid_Asserted_Identity);
}

bool sid_check_is_in_asserted_identity(const struct dom_sid *sid)
{
	struct dom_sid dom_sid;

	sid_copy(&dom_sid, sid);
	sid_split_rid(&dom_sid, NULL);

	return sid_check_is_asserted_identity(&dom_sid);
}

const char *asserted_identity_domain_name(void)
{
	return "Asserted Identity";
}
