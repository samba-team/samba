/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2001
   
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

/* return a ldap dn path from a string, given separators and field name
   caller must free
*/
char *ads_build_path(const char *realm, const char *sep, const char *field, int reverse)
{
	char *p, *r;
	int numbits = 0;
	char *ret;
	int len;
	
	r = strdup(realm);

	if (!r || !*r) return r;

	for (p=r; *p; p++) {
		if (strchr(sep, *p)) numbits++;
	}

	len = (numbits+1)*(strlen(field)+1) + strlen(r) + 1;

	ret = malloc(len);
	strlcpy(ret,field, len);
	p=strtok(r,sep); 
	strlcat(ret, p, len);

	while ((p=strtok(NULL,sep))) {
		char *s;
		if (reverse) {
			asprintf(&s, "%s%s,%s", field, p, ret);
		} else {
			asprintf(&s, "%s,%s%s", ret, field, p);
		}
		free(ret);
		ret = s;
	}

	free(r);

	return ret;
}

/* return a dn of the form "dc=AA,dc=BB,dc=CC" from a 
   realm of the form AA.BB.CC 
   caller must free
*/
char *ads_build_dn(const char *realm)
{
	return ads_build_path(realm, ".", "dc=", 0);
}


#ifdef HAVE_LDAP
/*
  find the ldap server from DNS
*/
static char *find_ldap_server(ADS_STRUCT *ads)
{
	char *list = NULL;
	struct in_addr ip;

	if (ads->realm &&
	    strcasecmp(ads->workgroup, lp_workgroup()) == 0 &&
	    ldap_domain2hostlist(ads->realm, &list) == LDAP_SUCCESS) {
		char *p;
		p = strchr(list, ':');
		if (p) *p = 0;
		return list;
	}

	/* get desperate, find the domain controller IP */
	if (resolve_name(ads->workgroup, &ip, 0x1B)) {
		return strdup(inet_ntoa(ip));
	}
	
	/* or a BDC ... */
	if (resolve_name(ads->workgroup, &ip, 0x1C)) {
		return strdup(inet_ntoa(ip));
	}

	return NULL;
}

#else 

static char *find_ldap_server(ADS_STRUCT *ads)
{
	/* Without LDAP this doesn't make much sense */
	return NULL;
}

#endif 

#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif

/*
  initialise a ADS_STRUCT, ready for some ads_ ops
*/
ADS_STRUCT *ads_init(const char *realm, 
		     const char *workgroup,
		     const char *ldap_server,
		     const char *bind_path,
		     const char *password)
{
	ADS_STRUCT *ads;
	
	ads = (ADS_STRUCT *)smb_xmalloc(sizeof(*ads));
	ZERO_STRUCTP(ads);
	
	if (!workgroup) {
		workgroup = lp_workgroup();
	}

	ads->realm = realm? strdup(realm) : NULL;
	ads->workgroup = strdup(workgroup);
	ads->ldap_server = ldap_server? strdup(ldap_server) : NULL;
	ads->bind_path = bind_path? strdup(bind_path) : NULL;
	ads->ldap_port = LDAP_PORT;
	if (password) ads->password = strdup(password);

	if (!ads->realm) {
		ads->realm = strdup(lp_realm());
		if (!ads->realm[0]) {
			SAFE_FREE(ads->realm);
		}
	}
	if (!ads->bind_path && ads->realm) {
		ads->bind_path = ads_build_dn(ads->realm);
	}
	if (!ads->ldap_server) {
		if (strcasecmp(ads->workgroup, lp_workgroup()) == 0) {
			ads->ldap_server = strdup(lp_ads_server());
		}
		if (!ads->ldap_server || !ads->ldap_server[0]) {
			ads->ldap_server = find_ldap_server(ads);
		}
	}
	if (!ads->kdc_server) {
		/* assume its the same as LDAP */
		ads->kdc_server = ads->ldap_server? strdup(ads->ldap_server) : NULL;
	}

	return ads;
}

/* a simpler ads_init() interface using all defaults */
ADS_STRUCT *ads_init_simple(void)
{
	return ads_init(NULL, NULL, NULL, NULL, NULL);
}

/*
  free the memory used by the ADS structure initialized with 'ads_init(...)'
*/
void ads_destroy(ADS_STRUCT **ads)
{
	if (ads && *ads) {
#if HAVE_LDAP
		if ((*ads)->ld) ldap_unbind((*ads)->ld);
#endif
		SAFE_FREE((*ads)->realm);
		SAFE_FREE((*ads)->ldap_server);
		SAFE_FREE((*ads)->ldap_server_name);
		SAFE_FREE((*ads)->kdc_server);
		SAFE_FREE((*ads)->bind_path);
		SAFE_FREE((*ads)->password);
		SAFE_FREE((*ads)->user_name);
		ZERO_STRUCTP(*ads);
		SAFE_FREE(*ads);
	}
}
