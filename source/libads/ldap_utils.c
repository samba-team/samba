/* 
   Unix SMB/CIFS implementation.

   Some Helpful wrappers on LDAP 

   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#ifdef HAVE_LDAP
/*
  a wrapper around ldap_search_s that retries depending on the error code
  this is supposed to catch dropped connections and auto-reconnect
*/
ADS_STATUS ads_do_search_retry(ADS_STRUCT *ads, const char *bind_path, int scope, 
			       const char *expr,
			       const char **attrs, void **res)
{
	ADS_STATUS status;
	int count = 3;
	char *bp;

	*res = NULL;

	if (!ads->ld &&
	    time(NULL) - ads->last_attempt < ADS_RECONNECT_TIME) {
		return ADS_ERROR(LDAP_SERVER_DOWN);
	}

	bp = strdup(bind_path);

	if (!bp) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	while (count--) {
		*res = NULL;
		status = ads_do_search_all(ads, bp, scope, expr, attrs, res);
		if (ADS_ERR_OK(status)) {
			DEBUG(5,("Search for %s gave %d replies\n",
				 expr, ads_count_replies(ads, *res)));
			SAFE_FREE(bp);
			return status;
		}

		if (*res) 
			ads_msgfree(ads, *res);
		*res = NULL;
		
		DEBUG(3,("Reopening ads connection to realm '%s' after error %s\n", 
			 ads->config.realm, ads_errstr(status)));
			 
		if (ads->ld) {
			ldap_unbind(ads->ld); 
		}
		
		ads->ld = NULL;
		status = ads_connect(ads);
		
		if (!ADS_ERR_OK(status)) {
			DEBUG(1,("ads_search_retry: failed to reconnect (%s)\n",
				 ads_errstr(status)));
			ads_destroy(&ads);
			SAFE_FREE(bp);
			return status;
		}
	}
        SAFE_FREE(bp);

	if (!ADS_ERR_OK(status))
		DEBUG(1,("ads reopen failed after error %s\n", 
			 ads_errstr(status)));

	return status;
}


ADS_STATUS ads_search_retry(ADS_STRUCT *ads, void **res, 
			    const char *expr, 
			    const char **attrs)
{
	return ads_do_search_retry(ads, ads->config.bind_path, LDAP_SCOPE_SUBTREE,
				   expr, attrs, res);
}

ADS_STATUS ads_search_retry_dn(ADS_STRUCT *ads, void **res, 
			       const char *dn, 
			       const char **attrs)
{
	return ads_do_search_retry(ads, dn, LDAP_SCOPE_BASE,
				   "(objectclass=*)", attrs, res);
}
#endif
