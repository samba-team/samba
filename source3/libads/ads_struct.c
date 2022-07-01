/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2001

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

/* return a ldap dn path from a string, given separators and field name
   caller must free
*/
ADS_STATUS ads_build_path(const char *realm,
			  const char *sep,
			  const char *field,
			  int reverse,
			  char **_path)
{
	char *p, *r;
	int numbits = 0;
	char *ret;
	int len;
	char *saveptr;

	*_path = NULL;

	r = SMB_STRDUP(realm);
	if (r == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	for (p=r; *p; p++) {
		if (strchr(sep, *p)) {
			numbits++;
		}
	}

	len = (numbits+1)*(strlen(field)+1) + strlen(r) + 1;

	ret = (char *)SMB_MALLOC(len);
	if (!ret) {
		free(r);
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	if (strlcpy(ret,field, len) >= len) {
		/* Truncate ! */
		free(r);
		free(ret);
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	p=strtok_r(r, sep, &saveptr);
	if (p) {
		if (strlcat(ret, p, len) >= len) {
			free(r);
			free(ret);
			return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		}

		while ((p=strtok_r(NULL, sep, &saveptr)) != NULL) {
			int retval;
			char *s = NULL;
			if (reverse)
				retval = asprintf(&s, "%s%s,%s", field, p, ret);
			else
				retval = asprintf(&s, "%s,%s%s", ret, field, p);
			free(ret);
			if (retval == -1) {
				free(r);
				return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			}
			ret = SMB_STRDUP(s);
			free(s);
		}
	}

	free(r);

	*_path = ret;

	return ADS_ERROR_NT(NT_STATUS_OK);
}

/* return a dn of the form "dc=AA,dc=BB,dc=CC" from a 
   realm of the form AA.BB.CC 
   caller must free
*/
ADS_STATUS ads_build_dn(const char *realm, TALLOC_CTX *mem_ctx, char **_dn)
{
	ADS_STATUS status;
	char *dn = NULL;

	status = ads_build_path(realm, ".", "dc=", 0, &dn);
	if (!ADS_ERR_OK(status)) {
		SAFE_FREE(dn);
		return status;
	}

	*_dn = talloc_strdup(mem_ctx, dn);
	SAFE_FREE(dn);
	if (*_dn == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	return ADS_ERROR_NT(NT_STATUS_OK);
}

/* return a DNS name in the for aa.bb.cc from the DN  
   "dc=AA,dc=BB,dc=CC".  caller must free
*/
char *ads_build_domain(const char *dn)
{
	char *dnsdomain = NULL;

	/* result should always be shorter than the DN */

	if ( (dnsdomain = SMB_STRDUP( dn )) == NULL ) {
		DEBUG(0,("ads_build_domain: malloc() failed!\n"));		
		return NULL;		
	}	

	if (!strlower_m( dnsdomain )) {
		SAFE_FREE(dnsdomain);
		return NULL;
	}

	all_string_sub( dnsdomain, "dc=", "", 0);
	all_string_sub( dnsdomain, ",", ".", 0 );

	return dnsdomain;	
}

static int ads_destructor(ADS_STRUCT *ads)
{
#ifdef HAVE_LDAP
	ads_disconnect(ads);
#endif
	return 0;
}

/*
  initialise a ADS_STRUCT, ready for some ads_ ops
*/
ADS_STRUCT *ads_init(TALLOC_CTX *mem_ctx,
		     const char *realm,
		     const char *workgroup,
		     const char *ldap_server,
		     enum ads_sasl_state_e sasl_state)
{
	ADS_STRUCT *ads = NULL;
	int wrap_flags;

	ads = talloc_zero(mem_ctx, ADS_STRUCT);
	if (ads == NULL) {
		return NULL;
	}
	talloc_set_destructor(ads, ads_destructor);

#ifdef HAVE_LDAP
	ads_zero_ldap(ads);
#endif

	ads->server.realm = talloc_strdup(ads, realm);
	if (realm != NULL && ads->server.realm == NULL) {
		DBG_WARNING("Out of memory\n");
		TALLOC_FREE(ads);
		return NULL;
	}

	ads->server.workgroup = talloc_strdup(ads, workgroup);
	if (workgroup != NULL && ads->server.workgroup == NULL) {
		DBG_WARNING("Out of memory\n");
		TALLOC_FREE(ads);
		return NULL;
	}

	ads->server.ldap_server = talloc_strdup(ads, ldap_server);
	if (ldap_server != NULL && ads->server.ldap_server == NULL) {
		DBG_WARNING("Out of memory\n");
		TALLOC_FREE(ads);
		return NULL;
	}

	wrap_flags = lp_client_ldap_sasl_wrapping();
	if (wrap_flags == -1) {
		wrap_flags = 0;
	}

	switch (sasl_state) {
	case ADS_SASL_PLAIN:
		break;
	case ADS_SASL_SIGN:
		wrap_flags |= ADS_AUTH_SASL_SIGN;
		break;
	case ADS_SASL_SEAL:
		wrap_flags |= ADS_AUTH_SASL_SEAL;
		break;
	}

	ads->auth.flags = wrap_flags;

	/* Start with the configured page size when the connection is new,
	 * we will drop it by half we get a timeout.   */
	ads->config.ldap_page_size     = lp_ldap_page_size();

	return ads;
}

/****************************************************************
****************************************************************/

bool ads_set_sasl_wrap_flags(ADS_STRUCT *ads, unsigned flags)
{
	unsigned other_flags;

	if (!ads) {
		return false;
	}

	other_flags = ads->auth.flags & ~(ADS_AUTH_SASL_SIGN|ADS_AUTH_SASL_SEAL);

	ads->auth.flags = flags | other_flags;

	return true;
}
