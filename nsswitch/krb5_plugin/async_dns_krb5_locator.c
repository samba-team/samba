/*
   Unix SMB/CIFS implementation.
   Async DNS kerberos locator plugin
   Copyright (C) Guenther Deschner 2007-2008
   Copyright (C) Jeremy Allison 2020.

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

#include "../../source3/include/includes.h"
#include "../../source3/libsmb/namequery.h"

#ifndef DEBUG_KRB5
#undef DEBUG_KRB5
#endif

/* Uncomment to debug. */
/* #define DEBUG_KRB5 1 */

#if defined(HAVE_KRB5) && defined(HAVE_KRB5_LOCATE_PLUGIN_H)

#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif

#include <krb5.h>
#include <krb5/locate_plugin.h>

#ifndef KRB5_PLUGIN_NO_HANDLE
#define KRB5_PLUGIN_NO_HANDLE KRB5_KDC_UNREACH /* Heimdal */
#endif

struct singleton_realm_kdc_list_cache {
	char *realm;
	struct samba_sockaddr *kdc_list;
	size_t num_kdcs;
};

static struct singleton_realm_kdc_list_cache *scache;

static const char *get_service_from_locate_service_type(enum locate_service_type svc)
{
	switch (svc) {
		case locate_service_kdc:
		case locate_service_master_kdc:
			return "88";
		case locate_service_kadmin:
		case locate_service_krb524:
			/* not supported */
			return NULL;
		case locate_service_kpasswd:
			return "464";
		default:
			break;
	}
	return NULL;

}

#ifdef DEBUG_KRB5
static const char *locate_service_type_name(enum locate_service_type svc)
{
	switch (svc) {
		case locate_service_kdc:
			return "locate_service_kdc";
		case locate_service_master_kdc:
			return "locate_service_master_kdc";
		case locate_service_kadmin:
			return "locate_service_kadmin";
		case locate_service_krb524:
			return "locate_service_krb524";
		case locate_service_kpasswd:
			return "locate_service_kpasswd";
		default:
			break;
	}
	return NULL;
}

static const char *socktype_name(int socktype)
{
	switch (socktype) {
		case SOCK_STREAM:
			return "SOCK_STREAM";
		case SOCK_DGRAM:
			return "SOCK_DGRAM";
		default:
			break;
	}
	return "unknown";
}

static const char *family_name(int family)
{
	switch (family) {
		case AF_UNSPEC:
			return "AF_UNSPEC";
		case AF_INET:
			return "AF_INET";
#if defined(HAVE_IPV6)
		case AF_INET6:
			return "AF_INET6";
#endif
		default:
			break;
	}
	return "unknown";
}
#endif

/**
 * Check input parameters, return KRB5_PLUGIN_NO_HANDLE for unsupported ones
 *
 * @param svc
 * @param realm string
 * @param socktype integer
 * @param family integer
 *
 * @return integer.
 */

static int smb_krb5_adns_locator_lookup_sanity_check(
				enum locate_service_type svc,
				const char *realm,
				int socktype,
				int family)
{
	if (!realm || strlen(realm) == 0) {
		return EINVAL;
	}

	switch (svc) {
		case locate_service_kdc:
		case locate_service_master_kdc:
			break;
		case locate_service_kadmin:
		case locate_service_krb524:
		case locate_service_kpasswd:
			return KRB5_PLUGIN_NO_HANDLE;
		default:
			return EINVAL;
	}

	switch (family) {
		case AF_UNSPEC:
		case AF_INET:
#if defined(HAVE_IPV6)
		case AF_INET6:
#endif
			break;
		default:
			return EINVAL;
	}

	switch (socktype) {
		case SOCK_STREAM:
		case SOCK_DGRAM:
		case 0: /* Heimdal uses that */
			break;
		default:
			return EINVAL;
	}

	return 0;
}

/**
 * Call back into the MIT libraries with each address
 * we found. Assume AD-DC's always support both UDP and
 * TCP port 88 for KDC service.
 */

static krb5_error_code smb_krb5_adns_locator_call_cbfunc(
				struct samba_sockaddr *kdcs,
				size_t num_kdcs,
				const char *service,
				int socktype,
				int (*cbfunc)(void *, int, struct sockaddr *),
				void *cbdata)
{
	int ret = 0;
	size_t i;

	for (i = 0; i < num_kdcs; i++) {
		struct sockaddr *sa = NULL;

		if (kdcs[i].u.ss.ss_family == AF_INET) {
			struct sockaddr_in *sin = &kdcs[i].u.in;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(88);
			sa = &kdcs[i].u.sa;
		}
#if defined(HAVE_IPV6)
		if (kdcs[i].u.ss.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = &kdcs[i].u.in6;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(88);
			sa = &kdcs[i].u.sa;
		}
#else
		else {
			return KRB5_PLUGIN_NO_HANDLE;
		}
#endif

#ifdef DEBUG_KRB5
		{
			char addr[INET6_ADDRSTRLEN];
			fprintf(stderr, "[%5u]: "
				"smb_krb5_adns_locator_call_cbfunc: "
				"IP[%zu] %s\n",
				(unsigned int)getpid(),
				i,
				print_sockaddr(addr,
					sizeof(addr),
					&kdcs[i].u.ss));
		}
#endif

		/* Assume all AD-DC's do both UDP and TCP on port 88. */
		ret = cbfunc(cbdata, socktype, sa);
		if (ret) {
#ifdef DEBUG_KRB5
			fprintf(stderr, "[%5u]: "
				"smb_krb5_adns_locator_call_cbfunc: "
				"failed to call callback: %s (%d)\n",
				(unsigned int)getpid(),
				error_message(ret),
				ret);
#endif
			break;
		}
	}
	return ret;
}

/**
 * PUBLIC INTERFACE: locate init
 *
 * @param context krb5_context
 * @param privata_data pointer to private data pointer
 *
 * @return krb5_error_code.
 */

static krb5_error_code smb_krb5_adns_locator_init(krb5_context context,
					     void **private_data)
{
	static bool loaded_config;
	if (!loaded_config) {
		lp_load_global(get_dyn_CONFIGFILE());
		loaded_config = true;
	}
#ifdef DEBUG_KRB5
	fprintf(stderr,"[%5u]: smb_krb5_adns_locator_init\n",
			(unsigned int)getpid());
#endif
	return 0;
}

/**
 * PUBLIC INTERFACE: close locate
 *
 * @param private_data pointer to private data
 *
 * @return void.
 */

static void smb_krb5_adns_locator_close(void *private_data)
{
#ifdef DEBUG_KRB5
	fprintf(stderr,"[%5u]: smb_krb5_adns_locator_close\n",
			(unsigned int)getpid());
#endif
	return;
}

/**
 * PUBLIC INTERFACE: locate lookup
 *
 * @param private_data pointer to private data
 * @param svc enum locate_service_type.
 * @param realm string
 * @param socktype integer
 * @param family integer
 * @param cbfunc callback function to send back entries
 * @param cbdata void pointer to cbdata
 *
 * @return krb5_error_code.
 */

static krb5_error_code smb_krb5_adns_locator_lookup(void *private_data,
			enum locate_service_type svc,
			const char *realm,
			int socktype,
			int family,
			int (*cbfunc)(void *, int, struct sockaddr *),
			void *cbdata)
{
	krb5_error_code ret;
	const char *service = get_service_from_locate_service_type(svc);

#ifdef DEBUG_KRB5
	fprintf(stderr,"[%5u]: smb_krb5_adns_locator_lookup: called for '%s' "
			"svc: '%s' (%d) "
			"socktype: '%s' (%d), family: '%s' (%d)\n",
			(unsigned int)getpid(),
			realm,
			locate_service_type_name(svc),
			svc,
			socktype_name(socktype),
			socktype,
		        family_name(family),
			family);
#endif
	ret = smb_krb5_adns_locator_lookup_sanity_check(svc,
						realm,
						socktype,
						family);
	if (ret) {
#ifdef DEBUG_KRB5
		fprintf(stderr, "[%5u]: smb_krb5_adns_locator_lookup: "
			"returning ret: %s (%d)\n",
			(unsigned int)getpid(),
			error_message(ret),
			ret);
#endif
		return ret;
	}

	/*
	 * If is a subsequent lookup for the same realm
	 * and we have a cache for this already, don't re-do
	 * the DNS SRV -> A/AAAA lookups.
	 *
	 * kinit does this a lot, it looks for UDP then TCP.
	 */

	if ((scache == NULL) || strcmp(realm, scache->realm) != 0) {
		/* Cache is NULL or a different realm lookup. */
		NTSTATUS status;

		/*
		 * We have a new lookup to do. As it's a singleton
		 * cache make sure we have no old cache.
		 */
		TALLOC_FREE(scache);

		scache = talloc_zero(NULL,
				struct singleton_realm_kdc_list_cache);
		if (scache == NULL) {
			return KRB5_PLUGIN_NO_HANDLE;
		}
		scache->realm = talloc_strdup(scache, realm);
		if (scache->realm == NULL) {
			TALLOC_FREE(scache);
			return KRB5_PLUGIN_NO_HANDLE;
		}

		status = get_kdc_list(scache,
					realm,
					NULL,
					&scache->kdc_list,
					&scache->num_kdcs);
		if (!NT_STATUS_IS_OK(status)) {
#ifdef DEBUG_KRB5
			fprintf(stderr, "[%5u]: "
				"smb_krb5_adns_locator_lookup: "
				"get_kdc_list() for realm %s failed "
				"with %s\n",
				(unsigned int)getpid(),
				realm,
				nt_errstr(status));
#endif
			TALLOC_FREE(scache);
			return KRB5_PLUGIN_NO_HANDLE;
		}
		if (scache->num_kdcs == 0) {
			TALLOC_FREE(scache);
			return KRB5_PLUGIN_NO_HANDLE;
		}
	}
#ifdef DEBUG_KRB5
	else {
		fprintf(stderr, "[%5u]: "
			"smb_krb5_adns_locator_lookup: "
			"returning cached data for realm %s\n",
			(unsigned int)getpid(),
			realm);
	}
#endif
	/*
	 * If we get here we know scache contains the right
	 * realm and non-null address list.
	 */

#ifdef DEBUG_KRB5
	fprintf(stderr, "[%5u]: smb_krb5_adns_locator_lookup: "
		"got %zu IP addresses for realm %s\n",
		(unsigned int)getpid(),
		scache->num_kdcs,
		scache->realm);
#endif

	/*
	 * Don't free kdc list on success, we're
	 * always returning from the cache.
	 */
	return smb_krb5_adns_locator_call_cbfunc(scache->kdc_list,
					   scache->num_kdcs,
					   service,
					   socktype,
					   cbfunc,
					   cbdata);
}

#ifdef HEIMDAL_KRB5_LOCATE_PLUGIN_H
#define SMB_KRB5_LOCATOR_SYMBOL_NAME resolve /* Heimdal */
#else
#define SMB_KRB5_LOCATOR_SYMBOL_NAME service_locator /* MIT */
#endif

_PUBLIC_ const krb5plugin_service_locate_ftable SMB_KRB5_LOCATOR_SYMBOL_NAME = {
	.minor_version	= 0,
	.init		= smb_krb5_adns_locator_init,
	.fini		= smb_krb5_adns_locator_close,
#ifdef KRB5_PLUGIN_LOCATE_VERSION_2
	.old_lookup	= smb_krb5_adns_locator_lookup,
#else
	.lookup	= smb_krb5_adns_locator_lookup,
#endif
};

#endif
