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

/* returns true if spn exists in spn_array (match is NOT case-sensitive) */
static bool find_spn_in_spnlist(TALLOC_CTX *ctx,
				const char *spn,
				char **spn_array,
				size_t num_spns)
{
	char *lc_spn = NULL;
	size_t i = 0;

	lc_spn = strlower_talloc(ctx, spn);
	if (lc_spn == NULL) {
		DBG_ERR("Out of memory, lowercasing %s.\n",
			spn);
		return false;
	}

	for (i = 0; i < num_spns; i++) {
		char *lc_spn_attr = strlower_talloc(ctx, spn_array[i]);
		if (lc_spn_attr == NULL) {
			DBG_ERR("Out of memory, lowercasing %s.\n",
				spn_array[i]);
			return false;
		}

		if (strequal(lc_spn, lc_spn_attr)) {
			return true;
		}
	}

	return false;
}

bool ads_setspn_add(ADS_STRUCT *ads, const char *machine_name, const char * spn)
{
	bool ret = false;
	TALLOC_CTX *frame = NULL;
	ADS_STATUS status;
	struct spn_struct *spn_struct = NULL;
	const char *spns[2] = {NULL, NULL};
	char **existing_spns = NULL;
	size_t num_spns = 0;
	bool found = false;

	frame = talloc_stackframe();
	spns[0] = spn;
	spn_struct = parse_spn(frame, spn);
	if (spn_struct == NULL) {
		goto done;
	}

	status = ads_get_service_principal_names(frame,
						 ads,
						 machine_name,
						 &existing_spns,
						 &num_spns);

	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	found = find_spn_in_spnlist(frame, spn, existing_spns, num_spns);
	if (found) {
		d_printf("Duplicate SPN found, aborting operation.\n");
		goto done;
	}

	d_printf("Registering SPN %s for object %s\n", spn, machine_name);
	status = ads_add_service_principal_names(ads, machine_name, spns);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}
	ret = true;
	d_printf("Updated object\n");
done:
	TALLOC_FREE(frame);
	return ret;
}

#endif /* HAVE_ADS */
