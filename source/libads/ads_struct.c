/* 
   Unix SMB/Netbios implementation.
   Version 3.0
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

static char *ads_build_dn(const char *realm)
{
	char *p, *r;
	int numdots = 0;
	char *ret;
	int len;
	
	r = strdup(realm);

	if (!r || !*r) return r;

	for (p=r; *p; p++) {
		if (*p == '.') numdots++;
	}

	len = (numdots+1)*4 + strlen(r) + 1;

	ret = malloc(len);
	strlcpy(ret,"dc=", len);
	p=strtok(r,"."); 
	strlcat(ret, p, len);

	while ((p=strtok(NULL,"."))) {
		strlcat(ret,",dc=", len);
		strlcat(ret, p, len);
	}

	free(r);

	return ret;
}

#ifdef HAVE_KRB5

/*
  get the default relm from krb5.conf
*/
static char *get_default_realm(ADS_STRUCT *ads)
{
	BOOL ret;
	krb5_context context;
	char *realm;

	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("krb5_init_context failed (%s)\n", error_message(ret)));
		return NULL;
	}

	ret = krb5_get_default_realm(context, &realm);
	if (ret) {
		DEBUG(1,("krb5_get_default_realm failed (%s)\n", error_message(ret)));
		krb5_free_context(context);
		return NULL;
	} else {
		DEBUG(5,("krb5_get_default_realm got (%s)\n", realm));
	}
	krb5_free_context(context);
		
	return realm;
}

#else 
static char *get_default_realm(ADS_STRUCT *ads)
{
	/* We can't do this if we don't have krb5, 
	   but save linking nightmares */
	DEBUG(5,("get_default_realm:  not compiled with krb5.\n"));
	return NULL;
}

#endif

#ifdef HAVE_LDAP
/*
  find the ldap server from DNS
*/
static char *find_ldap_server(ADS_STRUCT *ads)
{
	char *list = NULL;

	if (ldap_domain2hostlist(ads->realm, &list) == LDAP_SUCCESS) {
		char *p;
		p = strchr(list, ':');
		if (p) *p = 0;
		return list;
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


/*
  initialise a ADS_STRUCT, ready for some ads_ ops
*/
ADS_STRUCT *ads_init(const char *realm, 
		     const char *ldap_server,
		     const char *bind_path)
{
	ADS_STRUCT *ads;
	
	ads = (ADS_STRUCT *)smb_xmalloc(sizeof(*ads));
	memset(ads, 0, sizeof(*ads));
	
	ads->realm = realm? strdup(realm) : NULL;
	ads->ldap_server = ldap_server? strdup(ldap_server) : NULL;
	ads->bind_path = bind_path? strdup(bind_path) : NULL;
	ads->ldap_port = LDAP_PORT;

	if (!ads->realm) {
		ads->realm = lp_realm();
		if (!ads->realm[0]) {
			ads->realm = get_default_realm(ads);
		}
	}
	if (!ads->bind_path) {
		ads->bind_path = ads_build_dn(ads->realm);
	}
	if (!ads->ldap_server) {
		ads->ldap_server = lp_ads_server();
		if (!ads->ldap_server[0]) {
			ads->ldap_server = find_ldap_server(ads);
		}
	}
	if (!ads->kdc_server) {
		/* assume its the same as LDAP */
		ads->kdc_server = ads->ldap_server? strdup(ads->ldap_server) : NULL;
	}

	return ads;
}

/*
  free the memory used by the ADS structure initialized with 'ads_init(...)'
*/
void ads_destroy(ADS_STRUCT **ads)
{
	if (False && (ads) && (*ads)) {
		if ((*ads)->ld) ldap_unbind((*ads)->ld);
		SAFE_FREE((*ads)->realm);
		SAFE_FREE((*ads)->ldap_server);
		SAFE_FREE((*ads)->kdc_server);
		SAFE_FREE((*ads)->bind_path);
		ZERO_STRUCTP(*ads);
		SAFE_FREE(*ads);
	}
}

