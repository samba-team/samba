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

char *ads_build_dn(const char *realm)
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


#ifdef HAVE_LDAP
/*
  find the ldap server from DNS
*/
static char *find_ldap_server(ADS_STRUCT *ads)
{
	char *list = NULL;
	struct in_addr ip;

	if (ads->realm && 
	    ldap_domain2hostlist(ads->realm, &list) == LDAP_SUCCESS) {
		char *p;
		p = strchr(list, ':');
		if (p) *p = 0;
		return list;
	}

	/* get desperate, find the domain controller IP */
	if (resolve_name(lp_workgroup(), &ip, 0x1B)) {
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
		     const char *ldap_server,
		     const char *bind_path,
		     const char *password)
{
	ADS_STRUCT *ads;
	
	ads = (ADS_STRUCT *)smb_xmalloc(sizeof(*ads));
	ZERO_STRUCTP(ads);
	
	ads->realm = realm? strdup(realm) : NULL;
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
		ads->ldap_server = strdup(lp_ads_server());
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


static void ads_display_status_helper(char *m, OM_uint32 code, int type)
{
     int maj_stat, min_stat;
     gss_buffer_desc msg;
     int msg_ctx;
     
     msg_ctx = 0;
     while (1) {
	  maj_stat = gss_display_status(&min_stat, code,
				       type, GSS_C_NULL_OID,
				       &msg_ctx, &msg);
	  DEBUG(1, ("GSS-API error %s: %s\n", m,
		      (char *)msg.value)); 
	  (void) gss_release_buffer(&min_stat, &msg);
	  
	  if (!msg_ctx)
	       break;
     }
}

void ads_display_status(char * msg, int maj_stat,int min_stat)
{
     ads_display_status_helper(msg, maj_stat, GSS_C_GSS_CODE);
     ads_display_status_helper(msg, min_stat, GSS_C_MECH_CODE);
}
