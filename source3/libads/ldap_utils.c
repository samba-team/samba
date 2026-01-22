/*
   Unix SMB/CIFS implementation.

   Some Helpful wrappers on LDAP

   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Guenther Deschner 2006,2007

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
#include "lib/param/loadparm.h"
#include "auth/credentials/credentials.h"

#ifdef HAVE_LDAP

void ads_set_reconnect_fn(ADS_STRUCT *ads,
			  NTSTATUS (*fn)(struct ads_struct *ads,
					 void *private_data,
					 TALLOC_CTX *mem_ctx,
					 struct cli_credentials **creds),
			  void *private_data)
{
	ads->auth.reconnect_state->fn = fn;
	ads->auth.reconnect_state->private_data = private_data;
}

static ADS_STATUS ads_ranged_search_internal(ADS_STRUCT *ads,
					     TALLOC_CTX *mem_ctx,
					     int scope,
					     const char *base,
					     const char *filter,
					     const char **attrs,
					     void *args,
					     const char *range_attr,
					     char ***strings,
					     size_t *num_strings,
					     uint32_t *first_usn,
					     int *num_retries,
					     bool *more_values);

/*
 * Do not reduce the page size in case of immediate timeouts. E.g. kernel
 * detected broken connection but samba hasn't tried to use the socket yet.
 * time() uses resolution in seconds, so it is avoided for timeouts < 1s and
 * might be avoided for timeouts < 2s.
 */
static inline void adjust_ldap_page_size(ADS_STRUCT *ads,
					 time_t start,
					 time_t end)
{
	if (ads->config.ldap_page_size >= (lp_ldap_page_size() / 4) &&
	    lp_ldap_page_size() > 4 && end - start > 1)
	{
		int new_page_size = (ads->config.ldap_page_size / 2);
		DBG_WARNING("Reducing LDAP page size from %d to %d due to "
			    "IO_TIMEOUT\n",
			    ads->config.ldap_page_size,
			    new_page_size);
		ads->config.ldap_page_size = new_page_size;
	}
}

/*
  a wrapper around ldap_search_s that retries depending on the error code
  this is supposed to catch dropped connections and auto-reconnect
*/
static ADS_STATUS ads_do_search_retry_internal(ADS_STRUCT *ads, const char *bind_path, int scope,
					       const char *expr,
					       const char **attrs, void *args,
					       LDAPMessage **res)
{
	ADS_STATUS status;
	int count = 3;
	char *bp;
	time_t search_start, search_end;

	*res = NULL;

	if (!ads->ldap.ld &&
	    time_mono(NULL) - ads->ldap.last_attempt < ADS_RECONNECT_TIME) {
		return ADS_ERROR(LDAP_SERVER_DOWN);
	}

	bp = SMB_STRDUP(bind_path);

	if (!bp) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	*res = NULL;

	/* when binding anonymously, we cannot use the paged search LDAP
	 * control - Guenther */

	search_start = time(NULL);
	if (ads->auth.flags & ADS_AUTH_ANON_BIND) {
		status = ads_do_search(ads, bp, scope, expr, attrs, res);
	} else {
		status = ads_do_search_all_args(ads, bp, scope, expr, attrs, args, res);
	}
	if (ADS_ERR_OK(status)) {
               DEBUG(5,("Search for %s in <%s> gave %d replies\n",
                        expr, bp, ads_count_replies(ads, *res)));
		SAFE_FREE(bp);
		return status;
	}

	while (--count) {
		struct cli_credentials *creds = NULL;
		char *cred_name = NULL;
		NTSTATUS ntstatus;
		TALLOC_CTX *frame = talloc_stackframe();

		search_end = time(NULL);
		if (NT_STATUS_EQUAL(ads_ntstatus(status), NT_STATUS_IO_TIMEOUT))
		{
			adjust_ldap_page_size(ads, search_start, search_end);
		}

		if (*res)
			ads_msgfree(ads, *res);
		*res = NULL;

		ads_disconnect(ads);

		if (ads->auth.reconnect_state->fn == NULL) {
			DBG_NOTICE("Search for %s in <%s> failed: %s\n",
				   expr, bp, ads_errstr(status));
			SAFE_FREE(bp);
			TALLOC_FREE(frame);
			return status;
		}

		ntstatus = ads->auth.reconnect_state->fn(ads,
				ads->auth.reconnect_state->private_data,
				frame, &creds);
		if (!NT_STATUS_IS_OK(ntstatus)) {
			DBG_WARNING("Failed to get creds for realm(%s): %s\n",
				    ads->server.realm, nt_errstr(ntstatus));
			DBG_WARNING("Search for %s in <%s> failed: %s\n",
				   expr, bp, ads_errstr(status));
			SAFE_FREE(bp);
			TALLOC_FREE(frame);
			return status;
		}

		cred_name = cli_credentials_get_unparsed_name(creds, creds);
		DBG_NOTICE("Reopening ads connection as %s to "
			   "realm '%s' after error %s\n",
			   cred_name, ads->server.realm, ads_errstr(status));

		status = ads_connect_creds(ads, creds);
		if (!ADS_ERR_OK(status)) {
			DBG_WARNING("Reconnect ads connection as %s to "
				    "realm '%s' failed: %s\n",
				    cred_name, ads->server.realm,
				    ads_errstr(status));
			/*
			 * We need to keep the ads pointer
			 * from being freed here as we don't own it and
			 * callers depend on it being around.
			 */
			ads_disconnect(ads);
			TALLOC_FREE(frame);
			SAFE_FREE(bp);
			return status;
		}
		TALLOC_FREE(frame);

		*res = NULL;

		/* when binding anonymously, we cannot use the paged search LDAP
		 * control - Guenther */

		search_start = time(NULL);
		if (ads->auth.flags & ADS_AUTH_ANON_BIND) {
			status = ads_do_search(ads, bp, scope, expr, attrs, res);
		} else {
			status = ads_do_search_all_args(ads, bp, scope, expr, attrs, args, res);
		}

		if (ADS_ERR_OK(status)) {
			DEBUG(5,("Search for filter: %s, base: %s gave %d replies\n",
				 expr, bp, ads_count_replies(ads, *res)));
			SAFE_FREE(bp);
			return status;
		}
	}
        SAFE_FREE(bp);

	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("ads reopen failed after error %s\n",
			 ads_errstr(status)));
	}
	return status;
}

 ADS_STATUS ads_do_search_retry(ADS_STRUCT *ads, const char *bind_path,
				int scope, const char *expr,
				const char **attrs, LDAPMessage **res)
{
	return ads_do_search_retry_internal(ads, bind_path, scope, expr, attrs, NULL, res);
}

static ADS_STATUS ads_do_search_retry_args(ADS_STRUCT *ads, const char *bind_path,
					   int scope, const char *expr,
					   const char **attrs, void *args,
					   LDAPMessage **res)
{
	return ads_do_search_retry_internal(ads, bind_path, scope, expr, attrs, args, res);
}


 ADS_STATUS ads_search_retry(ADS_STRUCT *ads, LDAPMessage **res,
			     const char *expr, const char **attrs)
{
	return ads_do_search_retry(ads, ads->config.bind_path, LDAP_SCOPE_SUBTREE,
				   expr, attrs, res);
}

 ADS_STATUS ads_search_retry_dn(ADS_STRUCT *ads, LDAPMessage **res,
				const char *dn,
				const char **attrs)
{
	return ads_do_search_retry(ads, dn, LDAP_SCOPE_BASE,
				   "(objectclass=*)", attrs, res);
}

 ADS_STATUS ads_search_retry_dn_sd_flags(ADS_STRUCT *ads, LDAPMessage **res,
					 uint32_t sd_flags,
					 const char *dn,
					 const char **attrs)
{
	ads_control args;

	args.control = ADS_SD_FLAGS_OID;
	args.val = sd_flags;
	args.critical = True;

	return ads_do_search_retry_args(ads, dn, LDAP_SCOPE_BASE,
					"(objectclass=*)", attrs, &args, res);
}

 ADS_STATUS ads_search_retry_extended_dn_ranged(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
						const char *dn,
						const char **attrs,
						enum ads_extended_dn_flags flags,
						char ***strings,
						size_t *num_strings)
{
	ads_control args;

	args.control = ADS_EXTENDED_DN_OID;
	args.val = flags;
	args.critical = True;

	/* we can only range process one attribute */
	if (!attrs || !attrs[0] || attrs[1]) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	return ads_ranged_search(ads, mem_ctx, LDAP_SCOPE_BASE, dn,
				 "(objectclass=*)", &args, attrs[0],
				 strings, num_strings);

}

 ADS_STATUS ads_search_retry_sid(ADS_STRUCT *ads, LDAPMessage **res,
				 const struct dom_sid *sid,
				 const char **attrs)
{
	char *dn, *sid_string;
	ADS_STATUS status;

	sid_string = sid_binstring_hex_talloc(talloc_tos(), sid);
	if (sid_string == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (!asprintf(&dn, "<SID=%s>", sid_string)) {
		TALLOC_FREE(sid_string);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_do_search_retry(ads, dn, LDAP_SCOPE_BASE,
				   "(objectclass=*)", attrs, res);
	SAFE_FREE(dn);
	TALLOC_FREE(sid_string);
	return status;
}

ADS_STATUS ads_ranged_search(ADS_STRUCT *ads,
			     TALLOC_CTX *mem_ctx,
			     int scope,
			     const char *base,
			     const char *filter,
			     void *args,
			     const char *range_attr,
			     char ***strings,
			     size_t *num_strings)
{
	ADS_STATUS status;
	uint32_t first_usn;
	int num_retries = 0;
	const char **attrs;
	bool more_values = False;

	*num_strings = 0;
	*strings = NULL;

	attrs = talloc_array(mem_ctx, const char *, 3);
	ADS_ERROR_HAVE_NO_MEMORY(attrs);

	attrs[0] = talloc_strdup(mem_ctx, range_attr);
	attrs[1] = talloc_strdup(mem_ctx, "usnChanged");
	attrs[2] = NULL;

	ADS_ERROR_HAVE_NO_MEMORY(attrs[0]);
	ADS_ERROR_HAVE_NO_MEMORY(attrs[1]);

	do {
		status = ads_ranged_search_internal(ads, mem_ctx,
						    scope, base, filter,
						    attrs, args, range_attr,
						    strings, num_strings,
						    &first_usn, &num_retries,
						    &more_values);

		if (NT_STATUS_EQUAL(STATUS_MORE_ENTRIES, ads_ntstatus(status))) {
			continue;
		}

		if (!ADS_ERR_OK(status)) {
			*num_strings = 0;
			strings = NULL;
			goto done;
		}

	} while (more_values);

 done:
	DEBUG(10,("returning with %d strings\n", (int)*num_strings));

	return status;
}

static ADS_STATUS ads_ranged_search_internal(ADS_STRUCT *ads,
				      TALLOC_CTX *mem_ctx,
				      int scope,
				      const char *base,
				      const char *filter,
				      const char **attrs,
				      void *args,
				      const char *range_attr,
				      char ***strings,
				      size_t *num_strings,
				      uint32_t *first_usn,
				      int *num_retries,
				      bool *more_values)
{
	LDAPMessage *res = NULL;
	ADS_STATUS status;
	int count;
	uint32_t current_usn;

	DEBUG(10, ("Searching for attrs[0] = %s, attrs[1] = %s\n", attrs[0], attrs[1]));

	*more_values = False;

	status = ads_do_search_retry_internal(ads, base, scope, filter, attrs, args, &res);

	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("ads_search: %s\n",
			 ads_errstr(status)));
		return status;
	}

	if (!res) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_SUCCESS);
	}

	if (*num_strings == 0) {
		if (!ads_pull_uint32(ads, res, "usnChanged", first_usn)) {
			DEBUG(1, ("could not pull first usnChanged!\n"));
			ads_msgfree(ads, res);
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
	}

	if (!ads_pull_uint32(ads, res, "usnChanged", &current_usn)) {
		DEBUG(1, ("could not pull current usnChanged!\n"));
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (*first_usn != current_usn) {
		DEBUG(5, ("USN on this record changed"
			  " - restarting search\n"));
		if (*num_retries < 5) {
			(*num_retries)++;
			*num_strings = 0;
			ads_msgfree(ads, res);
			return ADS_ERROR_NT(STATUS_MORE_ENTRIES);
		} else {
			DEBUG(5, ("USN on this record changed"
				  " - restarted search too many times, aborting!\n"));
			ads_msgfree(ads, res);
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
	}

	*strings = ads_pull_strings_range(ads, mem_ctx, res,
					 range_attr,
					 *strings,
					 &attrs[0],
					 num_strings,
					 more_values);

	ads_msgfree(ads, res);

	/* paranoia checks */
	if (*strings == NULL && *more_values) {
		DEBUG(0,("no strings found but more values???\n"));
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	if (*num_strings == 0 && *more_values) {
		DEBUG(0,("no strings found but more values???\n"));
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	return (*more_values) ? ADS_ERROR_NT(STATUS_MORE_ENTRIES) : ADS_ERROR(LDAP_SUCCESS);
}

#endif
