/*
   Unix SMB/CIFS implementation.
   net ads setspn routines
   Copyright (C) Noel Power 2018

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
#include "ads.h"

#ifdef HAVE_ADS
bool ads_setspn_list(ADS_STRUCT *ads, const char *machine_name)
{
	size_t i = 0;
	TALLOC_CTX *frame = NULL;
	char **spn_array = NULL;
	size_t num_spns = 0;
	bool ok = false;
	ADS_STATUS status;

	frame = talloc_stackframe();
	status = ads_get_service_principal_names(frame,
						 ads,
						 machine_name,
						 &spn_array,
						 &num_spns);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	d_printf("Registered SPNs for %s\n", machine_name);
	for (i = 0; i < num_spns; i++) {
		d_printf("\t%s\n", spn_array[i]);
	}

	ok = true;
done:
	TALLOC_FREE(frame);
	return ok;
}

#endif /* HAVE_ADS */
