/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "libwbclient.h"


/** @brief Convert a binary SID to a character string
 *
 * @param sid           Binary Security Identifier
 * @param **sid_string  Resulting character string
 *
 * @return #wbcErr
 **/

wbcErr wbcSidToString(const struct wbcDomainSid *sid,
		      char **sid_string)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	uint32_t id_auth;
	int i;
	char *tmp = NULL;
	TALLOC_CTX *ctx = NULL;

	if (!sid) {
		wbc_status = WBC_ERR_INVALID_SID;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	ctx = talloc_init("wbcSidToString");
	BAIL_ON_PTR_ERROR(ctx, wbc_status);

	id_auth = sid->id_auth[5] +
		(sid->id_auth[4] << 8) +
		(sid->id_auth[3] << 16) +
		(sid->id_auth[2] << 24);

	tmp = talloc_asprintf(ctx, "S-%d-%d", sid->sid_rev_num, id_auth);
	BAIL_ON_PTR_ERROR(tmp, wbc_status);

	for (i=0; i<sid->num_auths; i++) {
		char *tmp2 =
		tmp2 = talloc_asprintf_append(tmp, "-%u", sid->sub_auths[i]);
		BAIL_ON_PTR_ERROR(tmp2, wbc_status);

		tmp = tmp2;
	}

	*sid_string=talloc_strdup(NULL, tmp);
	BAIL_ON_PTR_ERROR((*sid_string), wbc_status);

	wbc_status = WBC_ERR_SUCCESS;

done:
	talloc_free(ctx);

	return wbc_status;
}

/** @brief Convert a character string to a binary SID
 *
 * @param *str          Character string in the form of S-...
 * @param sid           Resulting binary SID
 *
 * @return #wbcErr
 **/

wbcErr wbcStringToSid(const char *str,
		      struct wbcDomainSid *sid)
{
	const char *p;
	char *q;
	uint32_t x;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!sid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Sanity check for either "S-" or "s-" */

	if (!str
	    || (str[0]!='S' && str[0]!='s')
	    || (str[1]!='-')
	    || (strlen(str)<2))
	{
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Get the SID revision number */

	p = str+2;
	x = (uint32_t)strtol(p, &q, 10);
	if (x==0 || !q || *q!='-') {
		wbc_status = WBC_ERR_INVALID_SID;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	sid->sid_rev_num = (uint8_t)x;

	/* Next the Identifier Authority.  This is stored in big-endian
	   in a 6 byte array. */

	p = q+1;
	x = (uint32_t)strtol(p, &q, 10);
	if (x==0 || !q || *q!='-') {
		wbc_status = WBC_ERR_INVALID_SID;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	sid->id_auth[5] = (x & 0x000000ff);
	sid->id_auth[4] = (x & 0x0000ff00) >> 8;
	sid->id_auth[3] = (x & 0x00ff0000) >> 16;
	sid->id_auth[2] = (x & 0xff000000) >> 24;
	sid->id_auth[1] = 0;
	sid->id_auth[0] = 0;

	/* now read the the subauthorities */

	p = q +1;
	sid->num_auths = 0;
	while (sid->num_auths < MAXSUBAUTHS) {
		if ((x=(uint32_t)strtoul(p, &q, 10)) == 0)
			break;
		sid->sub_auths[sid->num_auths++] = x;

		if (q && ((*q!='-') || (*q=='\0')))
			break;
		p = q + 1;
	}

	/* IF we ended early, then the SID could not be converted */

	if (q && *q!='\0') {
		wbc_status = WBC_ERR_INVALID_SID;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = WBC_ERR_SUCCESS;

done:
	return wbc_status;

}

/** @brief Convert a domain and name to SID
 *
 * @param domain      Domain name (possibly "")
 * @param name        User or group name
 * @param *sid        Pointer to the resolved domain SID
 * @param *name_type  Pointet to the SID type
 *
 * @return #wbcErr
 *
 **/

wbcErr wbcLookupName(const char *domain,
		     const char *name,
		     struct wbcDomainSid *sid,
		     enum wbcSidType *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!sid || !name_type) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* dst is already null terminated from the memset above */

	strncpy(request.data.name.dom_name, domain,
		sizeof(request.data.name.dom_name)-1);
	strncpy(request.data.name.name, name,
		sizeof(request.data.name.name)-1);

	wbc_status = wbcRequestResponse(WINBINDD_LOOKUPNAME,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	wbc_status = wbcStringToSid(response.data.sid.sid, sid);
	BAIL_ON_WBC_ERROR(wbc_status);

	*name_type = (enum wbcSidType)response.data.sid.type;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/** @brief Convert a SID to a domain and name
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param domain      Resolved Domain name (possibly "")
 * @param name        Resolved User or group name
 * @param *name_type  Pointet to the resolved SID type
 *
 * @return #wbcErr
 *
 **/

wbcErr wbcLookupSid(const struct wbcDomainSid *sid,
		    char **domain,
		    char **name,
		    enum wbcSidType *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* dst is already null terminated from the memset above */

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.sid, sid_string, sizeof(request.data.sid)-1);
	wbcFreeMemory(sid_string);

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_LOOKUPSID,
					   &request,
					   &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Copy out result */

	if (domain != NULL) {
		*domain = talloc_strdup(NULL, response.data.name.dom_name);
		BAIL_ON_PTR_ERROR((*domain), wbc_status);
	}

	if (name != NULL) {
		*name = talloc_strdup(NULL, response.data.name.name);
		BAIL_ON_PTR_ERROR((*name), wbc_status);
	}

	if (name_type) {
		*name_type = (enum wbcSidType)response.data.name.type;
	}

	wbc_status = WBC_ERR_SUCCESS;

 done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		if (*domain)
			talloc_free(*domain);
		if (*name)
			talloc_free(*name);
	}

	return wbc_status;
}

/** @brief Translate a collection of RIDs within a domain to names
 *
 **/

wbcErr wbcLookupRids(struct wbcDomainSid *dom_sid,
		     int num_rids,
		     uint32_t *rids,
		     const char **pp_domain_name,
		     const char ***names,
		     enum wbcSidType **types)
{
	size_t i, len, ridbuf_size;
	char *ridlist;
	char *p;
	struct winbindd_request request;
	struct winbindd_response response;
	char *sid_string = NULL;
	char *domain_name = NULL;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!dom_sid || (num_rids == 0)) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = wbcSidToString(dom_sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.sid, sid_string, sizeof(request.data.sid)-1);
	wbcFreeMemory(sid_string);

	/* Even if all the Rids were of maximum 32bit values,
	   we would only have 11 bytes per rid in the final array
	   ("4294967296" + \n).  Add one more byte for the
	   terminating '\0' */

	ridbuf_size = (sizeof(char)*11) * num_rids + 1;

	ridlist = talloc_zero_array(NULL, char, ridbuf_size);
	BAIL_ON_PTR_ERROR(ridlist, wbc_status);

	len = 0;
	for (i=0; i<num_rids && (len-1)>0; i++) {
		char ridstr[12];

		len = strlen(ridlist);
		p = ridlist + len;

		snprintf( ridstr, sizeof(ridstr)-1, "%u\n", rids[i]);
		strncat(p, ridstr, ridbuf_size-len-1);
	}

	request.extra_data.data = ridlist;
	request.extra_len = strlen(ridlist)+1;

	wbc_status = wbcRequestResponse(WINBINDD_LOOKUPRIDS,
					&request,
					&response);
	talloc_free(ridlist);
	BAIL_ON_WBC_ERROR(wbc_status);

	domain_name = talloc_strdup(NULL, response.data.domain_name);
	BAIL_ON_PTR_ERROR(domain_name, wbc_status);

	*names = talloc_array(NULL, const char*, num_rids);
	BAIL_ON_PTR_ERROR((*names), wbc_status);

	*types = talloc_array(NULL, enum wbcSidType, num_rids);
	BAIL_ON_PTR_ERROR((*types), wbc_status);

	p = (char *)response.extra_data.data;

	for (i=0; i<num_rids; i++) {
		char *q;

		if (*p == '\0') {
			wbc_status = WBC_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		(*types)[i] = (enum wbcSidType)strtoul(p, &q, 10);

		if (*q != ' ') {
			wbc_status = WBC_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		p = q+1;

		if ((q = strchr(p, '\n')) == NULL) {
			wbc_status = WBC_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		*q = '\0';

		(*names)[i] = talloc_strdup((*names), p);
		BAIL_ON_PTR_ERROR(((*names)[i]), wbc_status);

		p = q+1;
	}

	if (*p != '\0') {
		wbc_status = WBC_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = WBC_ERR_SUCCESS;

 done:
	if (response.extra_data.data) {
		free(response.extra_data.data);
	}

	if (!WBC_ERROR_IS_OK(wbc_status)) {
		if (domain_name)
			talloc_free(domain_name);
		if (*names)
			talloc_free(*names);
		if (*types)
			talloc_free(*types);
	} else {
		*pp_domain_name = domain_name;
	}

	return wbc_status;
}
