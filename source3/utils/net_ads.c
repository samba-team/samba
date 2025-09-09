/*
   Samba Unix/Linux SMB client library
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Remus Koos (remuskoos@yahoo.com)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2006 Gerald (Jerry) Carter (jerry@samba.org)

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
#include "utils/net.h"
#include "libsmb/namequery.h"
#include "rpc_client/cli_pipe.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "../librpc/gen_ndr/ndr_spoolss.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "ads.h"
#include "libads/cldap.h"
#include "../lib/addns/dnsquery.h"
#include "../libds/common/flags.h"
#include "librpc/gen_ndr/libnet_join.h"
#include "libnet/libnet_join.h"
#include "smb_krb5.h"
#include "secrets.h"
#include "../libcli/security/security.h"
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "lib/param/loadparm.h"
#include "utils/net_dns.h"
#include "auth/kerberos/pac_utils.h"
#include "lib/util/string_wrappers.h"
#include "lib/util/util_file.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"
#endif /* [HAVE_JANSSON] */

#ifdef HAVE_ADS

/* when we do not have sufficient input parameters to contact a remote domain
 * we always fall back to our own realm - Guenther*/

static const char *assume_own_realm(struct net_context *c)
{
	if (!c->opt_host && strequal(lp_workgroup(), c->opt_target_workgroup)) {
		return lp_realm();
	}

	return NULL;
}

#ifdef HAVE_JANSSON

/*
 * note: JSON output deliberately bypasses gettext so as to provide the same
 * output irrespective of the locale.
 */

static int output_json(const struct json_object *jsobj)
{
	TALLOC_CTX *ctx = NULL;
	char *json = NULL;

	if (json_is_invalid(jsobj)) {
		return -1;
	}

	ctx = talloc_new(NULL);
	if (ctx == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		return -1;
	}

	json = json_to_string(ctx, jsobj);
	if (!json) {
		d_fprintf(stderr, _("error encoding to JSON\n"));
		return -1;
	}

	d_printf("%s\n", json);
	TALLOC_FREE(ctx);

	return 0;
}

static int net_ads_cldap_netlogon_json
	(ADS_STRUCT *ads,
	 const char *addr,
	 const struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply)
{
	struct json_object jsobj = json_new_object();
	struct json_object flagsobj = json_new_object();
	char response_type [32] = { '\0' };
	int ret = 0;

	if (json_is_invalid(&jsobj) || json_is_invalid(&flagsobj)) {
		d_fprintf(stderr, _("error setting up JSON value\n"));

		goto failure;
	}

	switch (reply->command) {
		case LOGON_SAM_LOGON_USER_UNKNOWN_EX:
			strncpy(response_type,
				"LOGON_SAM_LOGON_USER_UNKNOWN_EX",
				sizeof(response_type));
			break;
		case LOGON_SAM_LOGON_RESPONSE_EX:
			strncpy(response_type,
				"LOGON_SAM_LOGON_RESPONSE_EX",
				sizeof(response_type));
			break;
		default:
			snprintf(response_type,
				 sizeof(response_type),
				 "0x%x",
				 reply->command);
			break;
	}

	ret = json_add_string(&jsobj, "Information for Domain Controller",
			      addr);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Response Type", response_type);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_guid(&jsobj, "GUID", &reply->domain_uuid);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is a PDC",
			    reply->server_type & NBT_SERVER_PDC);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is a GC of the forest",
			    reply->server_type & NBT_SERVER_GC);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is an LDAP server",
			    reply->server_type & NBT_SERVER_LDAP);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Supports DS",
			    reply->server_type & NBT_SERVER_DS);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is running a KDC",
			    reply->server_type & NBT_SERVER_KDC);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is running time services",
			    reply->server_type & NBT_SERVER_TIMESERV);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is the closest DC",
			    reply->server_type & NBT_SERVER_CLOSEST);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is writable",
			    reply->server_type & NBT_SERVER_WRITABLE);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Has a hardware clock",
			    reply->server_type & NBT_SERVER_GOOD_TIMESERV);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj,
			    "Is a non-domain NC serviced by LDAP server",
			    reply->server_type & NBT_SERVER_NDNC);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool
		(&flagsobj, "Is NT6 DC that has some secrets",
		 reply->server_type & NBT_SERVER_SELECT_SECRET_DOMAIN_6);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool
		(&flagsobj, "Is NT6 DC that has all secrets",
		 reply->server_type & NBT_SERVER_FULL_SECRET_DOMAIN_6);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Runs Active Directory Web Services",
			    reply->server_type & NBT_SERVER_ADS_WEB_SERVICE);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Runs on Windows 2012 or later",
			    reply->server_type & NBT_SERVER_DS_8);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Runs on Windows 2012R2 or later",
			    reply->server_type & NBT_SERVER_DS_9);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Runs on Windows 2016 or later",
			    reply->server_type & NBT_SERVER_DS_10);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Has a DNS name",
			    reply->server_type & NBT_SERVER_HAS_DNS_NAME);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is a default NC",
			    reply->server_type & NBT_SERVER_IS_DEFAULT_NC);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_bool(&flagsobj, "Is the forest root",
			    reply->server_type & NBT_SERVER_FOREST_ROOT);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Forest", reply->forest);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Domain", reply->dns_domain);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Domain Controller", reply->pdc_dns_name);
	if (ret != 0) {
		goto failure;
	}


	ret = json_add_string(&jsobj, "Pre-Win2k Domain", reply->domain_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Pre-Win2k Hostname", reply->pdc_name);
	if (ret != 0) {
		goto failure;
	}

	if (*reply->user_name) {
		ret = json_add_string(&jsobj, "User name", reply->user_name);
		if (ret != 0) {
			goto failure;
		}
	}

	ret = json_add_string(&jsobj, "Server Site Name", reply->server_site);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "Client Site Name", reply->client_site);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&jsobj, "NT Version", reply->nt_version);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&jsobj, "LMNT Token", reply->lmnt_token);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&jsobj, "LM20 Token", reply->lm20_token);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "Flags", &flagsobj);
	if (ret != 0) {
		goto failure;
	}

	ret = output_json(&jsobj);
	json_free(&jsobj); /* frees flagsobj recursively */

	return ret;

failure:
	json_free(&flagsobj);
	json_free(&jsobj);

	return ret;
}

#else /* [HAVE_JANSSON] */

static int net_ads_cldap_netlogon_json
	(ADS_STRUCT *ads,
	 const char *addr,
	 const struct NETLOGON_SAM_LOGON_RESPONSE_EX * reply)
{
	d_fprintf(stderr, _("JSON support not available\n"));

	return -1;
}

#endif /* [HAVE_JANSSON] */

/*
  do a cldap netlogon query
*/
static int net_ads_cldap_netlogon(struct net_context *c, ADS_STRUCT *ads)
{
	char addr[INET6_ADDRSTRLEN];
	struct NETLOGON_SAM_LOGON_RESPONSE_EX reply;
	bool ok;

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);

	ok = ads_cldap_netlogon_5(
		talloc_tos(), &ads->ldap.ss, ads->server.realm, 0, &reply);
	if (!ok) {
		d_fprintf(stderr, _("CLDAP query failed!\n"));
		return -1;
	}

	if (c->opt_json) {
		return net_ads_cldap_netlogon_json(ads, addr, &reply);
	}

	d_printf(_("Information for Domain Controller: %s\n\n"),
		addr);

	d_printf(_("Response Type: "));
	switch (reply.command) {
	case LOGON_SAM_LOGON_USER_UNKNOWN_EX:
		d_printf("LOGON_SAM_LOGON_USER_UNKNOWN_EX\n");
		break;
	case LOGON_SAM_LOGON_RESPONSE_EX:
		d_printf("LOGON_SAM_LOGON_RESPONSE_EX\n");
		break;
	default:
		d_printf("0x%x\n", reply.command);
		break;
	}

	d_printf(_("GUID: %s\n"), GUID_string(talloc_tos(),&reply.domain_uuid));

	d_printf(_("Flags:\n"
		   "\tIs a PDC:                                   %s\n"
		   "\tIs a GC of the forest:                      %s\n"
		   "\tIs an LDAP server:                          %s\n"
		   "\tSupports DS:                                %s\n"
		   "\tIs running a KDC:                           %s\n"
		   "\tIs running time services:                   %s\n"
		   "\tIs the closest DC:                          %s\n"
		   "\tIs writable:                                %s\n"
		   "\tHas a hardware clock:                       %s\n"
		   "\tIs a non-domain NC serviced by LDAP server: %s\n"
		   "\tIs NT6 DC that has some secrets:            %s\n"
		   "\tIs NT6 DC that has all secrets:             %s\n"
		   "\tRuns Active Directory Web Services:         %s\n"
		   "\tRuns on Windows 2012 or later:              %s\n"
		   "\tRuns on Windows 2012R2 or later:            %s\n"
		   "\tRuns on Windows 2016 or later:              %s\n"
		   "\tHas a DNS name:                             %s\n"
		   "\tIs a default NC:                            %s\n"
		   "\tIs the forest root:                         %s\n"),
		   (reply.server_type & NBT_SERVER_PDC) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_GC) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_LDAP) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_DS) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_KDC) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_TIMESERV) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_CLOSEST) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_WRITABLE) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_GOOD_TIMESERV) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_NDNC) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_SELECT_SECRET_DOMAIN_6) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_FULL_SECRET_DOMAIN_6) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_ADS_WEB_SERVICE) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_DS_8) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_DS_9) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_DS_10) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_HAS_DNS_NAME) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_IS_DEFAULT_NC) ? _("yes") : _("no"),
		   (reply.server_type & NBT_SERVER_FOREST_ROOT) ? _("yes") : _("no"));


	printf(_("Forest: %s\n"), reply.forest);
	printf(_("Domain: %s\n"), reply.dns_domain);
	printf(_("Domain Controller: %s\n"), reply.pdc_dns_name);

	printf(_("Pre-Win2k Domain: %s\n"), reply.domain_name);
	printf(_("Pre-Win2k Hostname: %s\n"), reply.pdc_name);

	if (*reply.user_name) printf(_("User name: %s\n"), reply.user_name);

	printf(_("Server Site Name: %s\n"), reply.server_site);
	printf(_("Client Site Name: %s\n"), reply.client_site);

	d_printf(_("NT Version: %d\n"), reply.nt_version);
	d_printf(_("LMNT Token: %.2x\n"), reply.lmnt_token);
	d_printf(_("LM20 Token: %.2x\n"), reply.lm20_token);

	return 0;
}

/*
  this implements the CLDAP based netlogon lookup requests
  for finding the domain controller of a ADS domain
*/
static int net_ads_lookup(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	int ret = -1;

	if (c->display_usage) {
		d_printf("%s\n"
			 "net ads lookup\n"
			 "    %s",
			 _("Usage:"),
			 _("Find the ADS DC using CLDAP lookup.\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup_nobind(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Didn't find the cldap server!\n"));
		goto out;
	}

	if (!ads->config.realm) {
		ads->config.realm = talloc_strdup(ads, c->opt_target_workgroup);
		if (ads->config.realm == NULL) {
			d_fprintf(stderr, _("Out of memory\n"));
			goto out;
		}
		ads->ldap.port = 389;
	}

	ret = net_ads_cldap_netlogon(c, ads);
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}


#ifdef HAVE_JANSSON

static int net_ads_info_json(ADS_STRUCT *ads)
{
	int ret = 0;
	char addr[INET6_ADDRSTRLEN];
	time_t pass_time;
	struct json_object jsobj = json_new_object();

	if (json_is_invalid(&jsobj)) {
		d_fprintf(stderr, _("error setting up JSON value\n"));

		goto failure;
	}

	pass_time = secrets_fetch_pass_last_set_time(ads->server.workgroup);

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);

	ret = json_add_string (&jsobj, "LDAP server", addr);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string (&jsobj, "LDAP server name",
			       ads->config.ldap_server_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string (&jsobj, "Workgroup", ads->config.workgroup);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string (&jsobj, "Realm", ads->config.realm);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string (&jsobj, "Bind Path", ads->config.bind_path);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int (&jsobj, "LDAP port", ads->ldap.port);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int (&jsobj, "Server time", ads->config.current_time);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string (&jsobj, "KDC server", ads->auth.kdc_server);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int (&jsobj, "Server time offset",
			    ads->config.time_offset);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int (&jsobj, "Last machine account password change",
			    pass_time);
	if (ret != 0) {
		goto failure;
	}

	ret = output_json(&jsobj);
failure:
	json_free(&jsobj);

	return ret;
}

#else /* [HAVE_JANSSON] */

static int net_ads_info_json(ADS_STRUCT *ads)
{
	d_fprintf(stderr, _("JSON support not available\n"));

	return -1;
}

#endif /* [HAVE_JANSSON] */



static int net_ads_info(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	char addr[INET6_ADDRSTRLEN];
	time_t pass_time;
	int ret = -1;

	if (c->display_usage) {
		d_printf("%s\n"
			 "net ads info\n"
			 "    %s",
			 _("Usage:"),
			 _("Display information about an Active Directory "
			   "server.\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup_nobind(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Didn't find the ldap server!\n"));
		goto out;
	}

	if (!ads || !ads->config.realm) {
		d_fprintf(stderr, _("Didn't find the ldap server!\n"));
		goto out;
	}

	/* Try to set the server's current time since we didn't do a full
	   TCP LDAP session initially */

	if ( !ADS_ERR_OK(ads_current_time( ads )) ) {
		d_fprintf( stderr, _("Failed to get server's current time!\n"));
	}

	if (c->opt_json) {
		ret = net_ads_info_json(ads);
		goto out;
	}

	pass_time = secrets_fetch_pass_last_set_time(ads->server.workgroup);

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);

	d_printf(_("LDAP server: %s\n"), addr);
	d_printf(_("LDAP server name: %s\n"), ads->config.ldap_server_name);
	d_printf(_("Workgroup: %s\n"), ads->config.workgroup);
	d_printf(_("Realm: %s\n"), ads->config.realm);
	d_printf(_("Bind Path: %s\n"), ads->config.bind_path);
	d_printf(_("LDAP port: %d\n"), ads->ldap.port);
	d_printf(_("Server time: %s\n"),
			 http_timestring(tmp_ctx, ads->config.current_time));

	d_printf(_("KDC server: %s\n"), ads->auth.kdc_server );
	d_printf(_("Server time offset: %d\n"), ads->config.time_offset );

	d_printf(_("Last machine account password change: %s\n"),
		 http_timestring(tmp_ctx, pass_time));

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static ADS_STATUS ads_startup_int(struct net_context *c,
				  bool only_own_domain,
				  uint32_t auth_flags,
				  TALLOC_CTX *mem_ctx,
				  ADS_STRUCT **ads_ret)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *realm = NULL;
	const char *workgroup = NULL;
	bool tried_closest_dc = false;

	/* lp_realm() should be handled by a command line param,
	   However, the join requires that realm be set in smb.conf
	   and compares our realm with the remote server's so this is
	   ok until someone needs more flexibility */

	*ads_ret = NULL;

retry_connect:
 	if (only_own_domain) {
		realm = lp_realm();
		workgroup = lp_workgroup();
	} else {
		realm = assume_own_realm(c);
		workgroup = c->opt_target_workgroup;
	}

	ads = ads_init(mem_ctx,
		       realm,
		       workgroup,
		       c->opt_host,
		       ADS_SASL_SEAL);
	if (ads == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	ads->auth.flags |= auth_flags;

	if (auth_flags & ADS_AUTH_NO_BIND) {
		status = ads_connect_cldap_only(ads);
		if (!ADS_ERR_OK(status)) {
			DBG_ERR("ads_connect_cldap_only: %s\n",
				ads_errstr(status));
			TALLOC_FREE(ads);
			return status;
		}
	} else {
		status = ads_connect_creds(ads, c->creds);
		if (!ADS_ERR_OK(status)) {
			DBG_ERR("ads_connect_creds: %s\n",
				ads_errstr(status));
			TALLOC_FREE(ads);
			return status;
		}
	}

	/* when contacting our own domain, make sure we use the closest DC.
	 * This is done by reconnecting to ADS because only the first call to
	 * ads_connect will give us our own sitename */

	if ((only_own_domain || !c->opt_host) && !tried_closest_dc) {

		tried_closest_dc = true; /* avoid loop */

		if (!ads_closest_dc(ads)) {

			namecache_delete(ads->server.realm, 0x1C);
			namecache_delete(ads->server.workgroup, 0x1C);

			TALLOC_FREE(ads);

			goto retry_connect;
		}
	}

	*ads_ret = talloc_move(mem_ctx, &ads);
	return status;
}

ADS_STATUS ads_startup(struct net_context *c,
		       bool only_own_domain,
		       TALLOC_CTX *mem_ctx,
		       ADS_STRUCT **ads)
{
	return ads_startup_int(c, only_own_domain, 0, mem_ctx, ads);
}

ADS_STATUS ads_startup_nobind(struct net_context *c,
			      bool only_own_domain,
			      TALLOC_CTX *mem_ctx,
			      ADS_STRUCT **ads)
{
	return ads_startup_int(c,
			       only_own_domain,
			       ADS_AUTH_NO_BIND,
			       mem_ctx,
			       ads);
}

/*
  Check to see if connection can be made via ads.
  ads_startup() stores the password in opt_password if it needs to so
  that rpc or rap can use it without re-prompting.
*/
static int net_ads_check_int(struct net_context *c,
			     const char *realm,
			     const char *workgroup,
			     const char *host)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads;
	ADS_STATUS status;
	int ret = -1;

	ads = ads_init(tmp_ctx, realm, workgroup, host, ADS_SASL_PLAIN);
	if (ads == NULL) {
		goto out;
	}

	status = ads_connect_cldap_only(ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int net_ads_check_our_domain(struct net_context *c)
{
	return net_ads_check_int(c, lp_realm(), lp_workgroup(), NULL);
}

int net_ads_check(struct net_context *c)
{
	return net_ads_check_int(c, NULL, c->opt_workgroup, c->opt_host);
}

/*
   determine the netbios workgroup name for a domain
 */
static int net_ads_workgroup(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	struct NETLOGON_SAM_LOGON_RESPONSE_EX reply;
	bool ok = false;
	int ret = -1;

	if (c->display_usage) {
		d_printf  ("%s\n"
			   "net ads workgroup\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Print the workgroup name"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup_nobind(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Didn't find the cldap server!\n"));
		goto out;
	}

	if (!ads->config.realm) {
		ads->config.realm = talloc_strdup(ads, c->opt_target_workgroup);
		if (ads->config.realm == NULL) {
			d_fprintf(stderr, _("Out of memory\n"));
			goto out;
		}
		ads->ldap.port = 389;
	}

	ok = ads_cldap_netlogon_5(
		tmp_ctx, &ads->ldap.ss, ads->server.realm, 0, &reply);
	if (!ok) {
		d_fprintf(stderr, _("CLDAP query failed!\n"));
		goto out;
	}

	d_printf(_("Workgroup: %s\n"), reply.domain_name);

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);

	return ret;
}



static bool usergrp_display(ADS_STRUCT *ads, char *field, void **values, void *data_area)
{
	char **disp_fields = (char **) data_area;

	if (!field) { /* must be end of record */
		if (disp_fields[0]) {
			if (!strchr_m(disp_fields[0], '$')) {
				if (disp_fields[1])
					d_printf("%-21.21s %s\n",
					       disp_fields[0], disp_fields[1]);
				else
					d_printf("%s\n", disp_fields[0]);
			}
		}
		SAFE_FREE(disp_fields[0]);
		SAFE_FREE(disp_fields[1]);
		return true;
	}
	if (!values) /* must be new field, indicate string field */
		return true;
	if (strcasecmp_m(field, "sAMAccountName") == 0) {
		disp_fields[0] = SMB_STRDUP((char *) values[0]);
	}
	if (strcasecmp_m(field, "description") == 0)
		disp_fields[1] = SMB_STRDUP((char *) values[0]);
	return true;
}

static int net_ads_user_usage(struct net_context *c, int argc, const char **argv)
{
	return net_user_usage(c, argc, argv);
}

static int ads_user_add(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	char *upn, *userdn;
	LDAPMessage *res=NULL;
	char *creds_ccname = NULL;
	int rc = -1;
	char *ou_str = NULL;
	bool ok;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_user_usage(c, argc, argv);
	}

	if (argc > 1) {
		/*
		 * We rely on ads_krb5_set_password() to
		 * set the password below.
		 *
		 * We could pass the password to
		 * ads_add_user_acct()
		 * and set the unicodePwd attribute there...
		 */
		cli_credentials_set_kerberos_state(c->creds,
						   CRED_USE_KERBEROS_REQUIRED,
						   CRED_SPECIFIED);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_user_add: %s\n"), ads_errstr(status));
		goto done;
	}

	if (ads_count_replies(ads, res)) {
		d_fprintf(stderr, _("ads_user_add: User %s already exists\n"),
			  argv[0]);
		goto done;
	}

	if (c->opt_container) {
		ou_str = SMB_STRDUP(c->opt_container);
	} else {
		ou_str = ads_default_ou_string(ads, DS_GUID_USERS_CONTAINER);
	}

	status = ads_add_user_acct(ads, argv[0], ou_str, c->opt_comment);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Could not add user %s: %s\n"), argv[0],
			 ads_errstr(status));
		goto done;
	}

	/* if no password is to be set, we're done */
	if (argc == 1) {
		d_printf(_("User %s added\n"), argv[0]);
		rc = 0;
		goto done;
	}

	/* try setting the password */
	upn = talloc_asprintf(tmp_ctx,
			      "%s@%s",
			      argv[0],
			      ads->config.realm);
	if (upn == NULL) {
		goto done;
	}

	ok = cli_credentials_get_ccache_name_obtained(c->creds,
						      tmp_ctx,
						      &creds_ccname,
						      NULL);
	if (!ok) {
		d_printf(_("No valid krb5 ccache for: %s\n"),
			 cli_credentials_get_unparsed_name(c->creds, tmp_ctx));
		goto done;
	}

	status = ads_krb5_set_password(upn, argv[1], creds_ccname);
	if (ADS_ERR_OK(status)) {
		d_printf(_("User %s added\n"), argv[0]);
		rc = 0;
		goto done;
	}
	TALLOC_FREE(upn);

	/* password didn't set, delete account */
	d_fprintf(stderr, _("Could not add user %s. "
			    "Error setting password %s\n"),
		 argv[0], ads_errstr(status));

	ads_msgfree(ads, res);
	res = NULL;

	status=ads_find_user_acct(ads, &res, argv[0]);
	if (ADS_ERR_OK(status)) {
		userdn = ads_get_dn(ads, tmp_ctx, res);
		ads_del_dn(ads, userdn);
		TALLOC_FREE(userdn);
	}

 done:
	ads_msgfree(ads, res);
	SAFE_FREE(ou_str);
	TALLOC_FREE(tmp_ctx);
	return rc;
}

static int ads_user_info(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int ret = -1;
	wbcErr wbc_status;
	const char *attrs[] = {"memberOf", "primaryGroupID", NULL};
	char *searchstring = NULL;
	char **grouplist = NULL;
	char *primary_group = NULL;
	char *escaped_user = NULL;
	struct dom_sid primary_group_sid;
	uint32_t group_rid;
	enum wbcSidType type;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_user_usage(c, argc, argv);
	}

	escaped_user = escape_ldap_string(tmp_ctx, argv[0]);
	if (!escaped_user) {
		d_fprintf(stderr,
			  _("ads_user_info: failed to escape user %s\n"),
			  argv[0]);
		goto out;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	searchstring = talloc_asprintf(tmp_ctx,
				       "(sAMAccountName=%s)",
				       escaped_user);
	if (searchstring == NULL) {
		goto out;
	}

	status = ads_search(ads, &res, searchstring, attrs);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_search: %s\n"), ads_errstr(status));
		goto out;
	}

	if (!ads_pull_uint32(ads, res, "primaryGroupID", &group_rid)) {
		d_fprintf(stderr, _("ads_pull_uint32 failed\n"));
		goto out;
	}

	status = ads_domain_sid(ads, &primary_group_sid);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_domain_sid: %s\n"), ads_errstr(status));
		goto out;
	}

	sid_append_rid(&primary_group_sid, group_rid);

	wbc_status = wbcLookupSid((struct wbcDomainSid *)&primary_group_sid,
				  NULL, /* don't look up domain */
				  &primary_group,
				  &type);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		d_fprintf(stderr, "wbcLookupSid: %s\n",
			  wbcErrorString(wbc_status));
		goto out;
	}

	d_printf("%s\n", primary_group);

	wbcFreeMemory(primary_group);

	grouplist = ldap_get_values((LDAP *)ads->ldap.ld,
				    (LDAPMessage *)res, "memberOf");

	if (grouplist) {
		int i;
		char **groupname;
		for (i=0;grouplist[i];i++) {
			groupname = ldap_explode_dn(grouplist[i], 1);
			d_printf("%s\n", groupname[0]);
			ldap_value_free(groupname);
		}
		ldap_value_free(grouplist);
	}

	ret = 0;
out:
	TALLOC_FREE(escaped_user);
	TALLOC_FREE(searchstring);
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int ads_user_delete(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	char *userdn = NULL;
	int ret = -1;

	if (argc < 1) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_user_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(status) || ads_count_replies(ads, res) != 1) {
		d_printf(_("User %s does not exist.\n"), argv[0]);
		goto out;
	}

	userdn = ads_get_dn(ads, tmp_ctx, res);
	if (userdn == NULL) {
		goto out;
	}

	status = ads_del_dn(ads, userdn);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Error deleting user %s: %s\n"), argv[0],
			  ads_errstr(status));
		goto out;
	}

	d_printf(_("User %s deleted\n"), argv[0]);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int net_ads_user(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			ads_user_add,
			NET_TRANSPORT_ADS,
			N_("Add an AD user"),
			N_("net ads user add\n"
			   "    Add an AD user")
		},
		{
			"info",
			ads_user_info,
			NET_TRANSPORT_ADS,
			N_("Display information about an AD user"),
			N_("net ads user info\n"
			   "    Display information about an AD user")
		},
		{
			"delete",
			ads_user_delete,
			NET_TRANSPORT_ADS,
			N_("Delete an AD user"),
			N_("net ads user delete\n"
			   "    Delete an AD user")
		},
		{NULL, NULL, 0, NULL, NULL}
	};
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};
	int ret = -1;

	if (argc > 0) {
		TALLOC_FREE(tmp_ctx);
		return net_run_function(c, argc, argv, "net ads user", func);
	}

	if (c->display_usage) {
		d_printf(  "%s\n"
		           "net ads user\n"
			   "    %s\n",
			 _("Usage:"),
			 _("List AD users"));
		net_display_usage_from_functable(func);
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (c->opt_long_list_entries)
		d_printf(_("\nUser name             Comment"
			   "\n-----------------------------\n"));

	status = ads_do_search_all_fn(ads,
				      ads->config.bind_path,
				      LDAP_SCOPE_SUBTREE,
				      "(objectCategory=user)",
				      c->opt_long_list_entries ?
				              longattrs : shortattrs,
				      usergrp_display,
				      disp_fields);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_group_usage(struct net_context *c, int argc, const char **argv)
{
	return net_group_usage(c, argc, argv);
}

static int ads_group_add(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int ret = -1;
	char *ou_str = NULL;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_group_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_group_add: %s\n"), ads_errstr(status));
		goto out;
	}

	if (ads_count_replies(ads, res)) {
		d_fprintf(stderr, _("ads_group_add: Group %s already exists\n"), argv[0]);
		goto out;
	}

	if (c->opt_container) {
		ou_str = SMB_STRDUP(c->opt_container);
	} else {
		ou_str = ads_default_ou_string(ads, DS_GUID_USERS_CONTAINER);
	}

	status = ads_add_group_acct(ads, argv[0], ou_str, c->opt_comment);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Could not add group %s: %s\n"), argv[0],
			  ads_errstr(status));
		goto out;
	}

	d_printf(_("Group %s added\n"), argv[0]);

	ret = 0;
 out:
	ads_msgfree(ads, res);
	SAFE_FREE(ou_str);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int ads_group_delete(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	char *groupdn = NULL;
	int ret = -1;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_group_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(status) || ads_count_replies(ads, res) != 1) {
		d_printf(_("Group %s does not exist.\n"), argv[0]);
		goto out;
	}

	groupdn = ads_get_dn(ads, tmp_ctx, res);
	if (groupdn == NULL) {
		goto out;
	}

	status = ads_del_dn(ads, groupdn);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Error deleting group %s: %s\n"), argv[0],
			  ads_errstr(status));
		goto out;
	}
	d_printf(_("Group %s deleted\n"), argv[0]);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int net_ads_group(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			ads_group_add,
			NET_TRANSPORT_ADS,
			N_("Add an AD group"),
			N_("net ads group add\n"
			   "    Add an AD group")
		},
		{
			"delete",
			ads_group_delete,
			NET_TRANSPORT_ADS,
			N_("Delete an AD group"),
			N_("net ads group delete\n"
			   "    Delete an AD group")
		},
		{NULL, NULL, 0, NULL, NULL}
	};
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};
	int ret = -1;

	if (argc > 0) {
		TALLOC_FREE(tmp_ctx);
		return net_run_function(c, argc, argv, "net ads group", func);
	}

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads group\n"
			   "    %s\n",
			 _("Usage:"),
			 _("List AD groups"));
		net_display_usage_from_functable(func);
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (c->opt_long_list_entries)
		d_printf(_("\nGroup name            Comment"
			   "\n-----------------------------\n"));

	status = ads_do_search_all_fn(ads,
				      ads->config.bind_path,
				      LDAP_SCOPE_SUBTREE,
				      "(objectCategory=group)",
				      c->opt_long_list_entries ?
				              longattrs : shortattrs,
				      usergrp_display,
				      disp_fields);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_status(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads status\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Display machine account details"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	net_warn_member_options();

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_machine_acct(ads, &res, lp_netbios_name());
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_find_machine_acct: %s\n"),
			  ads_errstr(status));
		goto out;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, _("No machine account for '%s' found\n"),
			  lp_netbios_name());
		goto out;
	}

	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*******************************************************************
 Leave an AD domain.  Windows XP disables the machine account.
 We'll try the same.  The old code would do an LDAP delete.
 That only worked using the machine creds because added the machine
 with full control to the computer object's ACL.
*******************************************************************/

static int net_ads_leave(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct libnet_UnjoinCtx *r = NULL;
	WERROR werr;
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads leave [--keep-account]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Leave an AD domain"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (!*lp_realm()) {
		d_fprintf(stderr, _("No realm set, are we joined ?\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (!c->msg_ctx) {
		d_fprintf(stderr, _("Could not initialise message context. "
			"Try running as root\n"));
		goto done;
	}

	werr = libnet_init_UnjoinCtx(tmp_ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("Could not initialise unjoin context.\n"));
		goto done;
	}

	r->in.debug		= true;
	r->in.dc_name		= c->opt_host;
	r->in.domain_name	= lp_dnsdomain();
	r->in.admin_credentials	= c->creds;
	r->in.modify_config	= lp_config_backend_is_registry();

	/* Try to delete it, but if that fails, disable it.  The
	   WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE really means "disable */
	r->in.unjoin_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE;
	if (c->opt_keep_account) {
		r->in.delete_machine_account = false;
	} else {
		r->in.delete_machine_account = true;
	}

	r->in.msg_ctx		= c->msg_ctx;

	werr = libnet_Unjoin(tmp_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf(_("Failed to leave domain: %s\n"),
			 r->out.error_string ? r->out.error_string :
			 get_friendly_werror_msg(werr));
		goto done;
	}

	if (r->out.deleted_machine_account) {
		d_printf(_("Deleted account for '%s' in realm '%s'\n"),
			r->in.machine_name, r->out.dns_domain_name);
		ret = 0;
		goto done;
	}

	/* We couldn't delete it - see if the disable succeeded. */
	if (r->out.disabled_machine_account) {
		d_printf(_("Disabled account for '%s' in realm '%s'\n"),
			r->in.machine_name, r->out.dns_domain_name);
		ret = 0;
		goto done;
	}

	/* Based on what we requested, we shouldn't get here, but if
	   we did, it means the secrets were removed, and therefore
	   we have left the domain */
	d_fprintf(stderr, _("Machine '%s' Left domain '%s'\n"),
		  r->in.machine_name, r->out.dns_domain_name);

	ret = 0;
 done:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static ADS_STATUS net_ads_join_ok(struct net_context *c)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	fstring dc_name;
	struct sockaddr_storage dcip;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		TALLOC_FREE(tmp_ctx);
		return ADS_ERROR_NT(NT_STATUS_ACCESS_DENIED);
	}

	net_warn_member_options();

	net_use_krb_machine_account(c);

	if (!cli_credentials_authentication_requested(c->creds)) {
		DBG_ERR("Failed to get machine credentials\n");
		TALLOC_FREE(tmp_ctx);
		return ADS_ERROR_NT(NT_STATUS_ACCESS_DENIED);
	}

	get_dc_name(lp_workgroup(), lp_realm(), dc_name, &dcip);

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ADS_ERROR_NT(NT_STATUS_OK);
out:
	TALLOC_FREE(tmp_ctx);
	return  status;
}

/*
  check that an existing join is OK
 */
int net_ads_testjoin(struct net_context *c, int argc, const char **argv)
{
	ADS_STATUS status;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads testjoin\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Test if the existing join is ok"));
		return -1;
	}

	net_warn_member_options();

	/* Display success or failure */
	status = net_ads_join_ok(c);
	if (!ADS_ERR_OK(status)) {
		fprintf(stderr, _("Join to domain is not valid: %s\n"),
			get_friendly_nt_error_msg(ads_ntstatus(status)));
		return -1;
	}

	printf(_("Join is OK\n"));
	return 0;
}

/*******************************************************************
  Simple config checks before beginning the join
 ********************************************************************/

static WERROR check_ads_config( void )
{
	if (lp_server_role() != ROLE_DOMAIN_MEMBER ) {
		d_printf(_("Host is not configured as a member server.\n"));
		return WERR_INVALID_DOMAIN_ROLE;
	}

	if (strlen(lp_netbios_name()) > 15) {
		d_printf(_("Our netbios name can be at most 15 chars long, "
			   "\"%s\" is %u chars long\n"), lp_netbios_name(),
			 (unsigned int)strlen(lp_netbios_name()));
		return WERR_INVALID_COMPUTERNAME;
	}

	if ( lp_security() == SEC_ADS && !*lp_realm()) {
		d_fprintf(stderr, _("realm must be set in %s for ADS "
			  "join to succeed.\n"), get_dyn_CONFIGFILE());
		return WERR_INVALID_PARAMETER;
	}

	return WERR_OK;
}

/*******************************************************************
 ********************************************************************/

static int net_ads_join_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("net ads join [--no-dns-updates] [options]\n"
	           "Valid options:\n"));
	d_printf(_("   dnshostname=FQDN      Set the dnsHostName attribute during the join.\n"
		   "                         The default is in the form netbiosname.dnsdomain\n"));
	d_printf(_("   createupn[=UPN]       Set the userPrincipalName attribute during the join.\n"
		   "                         The default UPN is in the form host/netbiosname@REALM.\n"));
	d_printf(_("   createcomputer=OU     Precreate the computer account in a specific OU.\n"
		   "                         The OU string read from top to bottom without RDNs\n"
		   "                         and delimited by a '/'.\n"
		   "                         E.g. \"createcomputer=Computers/Servers/Unix\"\n"
		   "                         NB: A backslash '\\' is used as escape at multiple\n"
		   "                             levels and may need to be doubled or even\n"
		   "                             quadrupled. It is not used as a separator.\n"));
	d_printf(_("   machinepass=PASS      Set the machine password to a specific value during\n"
		   "                         the join. The default password is random.\n"));
	d_printf(_("   osName=string         Set the operatingSystem attribute during the join.\n"));
	d_printf(_("   osVer=string          Set the operatingSystemVersion attribute during join.\n"
		   "                         NB: osName and osVer must be specified together for\n"
		   "                             either to take effect. The operatingSystemService\n"
		   "                             attribute is then also set along with the two\n"
		   "                             other attributes.\n"));
	d_printf(_("   osServicePack=string  Set the operatingSystemServicePack attribute\n"
		   "                         during the join.\n"
		   "                         NB: If not specified then by default the samba\n"
		   "                             version string is used instead.\n"));
	return -1;
}


int net_ads_join(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct libnet_JoinCtx *r = NULL;
	const char *domain = lp_realm();
	WERROR werr = WERR_NERR_SETUPNOTJOINED;
	bool createupn = false;
	const char *dnshostname = NULL;
	const char *machineupn = NULL;
	const char *machine_password = NULL;
	const char *create_in_ou = NULL;
	int i;
	const char *os_name = NULL;
	const char *os_version = NULL;
	const char *os_servicepack = NULL;
	bool modify_config = lp_config_backend_is_registry();
	enum libnetjoin_JoinDomNameType domain_name_type = JoinDomNameTypeDNS;
	int ret = -1;

	if (c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_join_usage(c, argc, argv);
	}

	net_warn_member_options();

	if (!modify_config) {
		werr = check_ads_config();
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, _("Invalid configuration.  Exiting....\n"));
			goto fail;
		}
	}

	werr = libnet_init_JoinCtx(tmp_ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	/* process additional command line args */

	for ( i=0; i<argc; i++ ) {
		if ( !strncasecmp_m(argv[i], "dnshostname", strlen("dnshostname")) ) {
			dnshostname = get_string_param(argv[i]);
		}
		else if ( !strncasecmp_m(argv[i], "createupn", strlen("createupn")) ) {
			createupn = true;
			machineupn = get_string_param(argv[i]);
		}
		else if ( !strncasecmp_m(argv[i], "createcomputer", strlen("createcomputer")) ) {
			if ( (create_in_ou = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, _("Please supply a valid OU path.\n"));
				werr = WERR_INVALID_PARAMETER;
				goto fail;
			}
		}
		else if ( !strncasecmp_m(argv[i], "osName", strlen("osName")) ) {
			if ( (os_name = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, _("Please supply a operating system name.\n"));
				werr = WERR_INVALID_PARAMETER;
				goto fail;
			}
		}
		else if ( !strncasecmp_m(argv[i], "osVer", strlen("osVer")) ) {
			if ( (os_version = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, _("Please supply a valid operating system version.\n"));
				werr = WERR_INVALID_PARAMETER;
				goto fail;
			}
		}
		else if ( !strncasecmp_m(argv[i], "osServicePack", strlen("osServicePack")) ) {
			if ( (os_servicepack = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, _("Please supply a valid servicepack identifier.\n"));
				werr = WERR_INVALID_PARAMETER;
				goto fail;
			}
		}
		else if ( !strncasecmp_m(argv[i], "machinepass", strlen("machinepass")) ) {
			if ( (machine_password = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, _("Please supply a valid password to set as trust account password.\n"));
				werr = WERR_INVALID_PARAMETER;
				goto fail;
			}
		} else {
			domain = argv[i];
			if (strchr(domain, '.') == NULL) {
				domain_name_type = JoinDomNameTypeUnknown;
			} else {
				domain_name_type = JoinDomNameTypeDNS;
			}
		}
	}

	if (!*domain) {
		d_fprintf(stderr, _("Please supply a valid domain name\n"));
		werr = WERR_INVALID_PARAMETER;
		goto fail;
	}

	if (!c->msg_ctx) {
		d_fprintf(stderr, _("Could not initialise message context. "
			"Try running as root\n"));
		werr = WERR_ACCESS_DENIED;
		goto fail;
	}

	/* Do the domain join here */

	r->in.domain_name	= domain;
	r->in.domain_name_type	= domain_name_type;
	r->in.create_upn	= createupn;
	r->in.upn		= machineupn;
	r->in.dnshostname	= dnshostname;
	r->in.account_ou	= create_in_ou;
	r->in.os_name		= os_name;
	r->in.os_version	= os_version;
	r->in.os_servicepack	= os_servicepack;
	r->in.dc_name		= c->opt_host;
	r->in.admin_credentials	= c->creds;
	r->in.machine_password  = machine_password;
	r->in.debug		= true;
	r->in.modify_config	= modify_config;
	r->in.join_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE |
				  WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED;
	r->in.msg_ctx		= c->msg_ctx;

	werr = libnet_Join(tmp_ctx, r);
	if (W_ERROR_EQUAL(werr, WERR_NERR_DCNOTFOUND) &&
	    strequal(domain, lp_realm())) {
		r->in.domain_name = lp_workgroup();
		r->in.domain_name_type = JoinDomNameTypeNBT;
		werr = libnet_Join(tmp_ctx, r);
	}
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	/* Check the short name of the domain */

	if (!modify_config && !strequal(lp_workgroup(), r->out.netbios_domain_name)) {
		d_printf(_("The workgroup in %s does not match the short\n"
			   "domain name obtained from the server.\n"
			   "Using the name [%s] from the server.\n"
			   "You should set \"workgroup = %s\" in %s.\n"),
			 get_dyn_CONFIGFILE(), r->out.netbios_domain_name,
			 r->out.netbios_domain_name, get_dyn_CONFIGFILE());
	}

	d_printf(_("Using short domain name -- %s\n"), r->out.netbios_domain_name);

	if (r->out.dns_domain_name) {
		d_printf(_("Joined '%s' to dns domain '%s'\n"), r->in.machine_name,
			r->out.dns_domain_name);
	} else {
		d_printf(_("Joined '%s' to domain '%s'\n"), r->in.machine_name,
			r->out.netbios_domain_name);
	}

	/* print out informative error string in case there is one */
	if (r->out.error_string != NULL) {
		d_printf("%s\n", r->out.error_string);
	}

	/*
	 * We try doing the dns update (if it was compiled in
	 * and if it was not disabled on the command line).
	 * If the dns update fails, we still consider the join
	 * operation as succeeded if we came this far.
	 */
	if (!c->opt_no_dns_updates) {
		net_ads_join_dns_updates(c, tmp_ctx, r);
	}

	ret = 0;

fail:
	if (ret != 0) {
		/* issue an overall failure message at the end. */
		d_printf(_("Failed to join domain: %s\n"),
			r && r->out.error_string ? r->out.error_string :
			get_friendly_werror_msg(werr));
	}

	TALLOC_FREE(tmp_ctx);

	return ret;
}

/*******************************************************************
 ********************************************************************/

static int net_ads_dns_register(struct net_context *c, int argc, const char **argv)
{
#if defined(HAVE_KRB5)
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	NTSTATUS ntstatus;
	const char *hostname = NULL;
	const char **addrs_list = NULL;
	struct sockaddr_storage *addrs = NULL;
	int num_addrs = 0;
	int count;
	int ret = -1;

#ifdef DEVELOPER
	talloc_enable_leak_report();
#endif

	if (argc <= 1 && lp_clustering() && lp_cluster_addresses() == NULL) {
		d_fprintf(stderr, _("Refusing DNS updates with automatic "
				    "detection of addresses in a clustered "
				    "setup.\n"));
		c->display_usage = true;
	}

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads dns register [hostname [IP [IP...]]] "
			   "[--force] [--dns-ttl TTL]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Register hostname with DNS\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (argc >= 1) {
		hostname = argv[0];
	}

	if (argc > 1) {
		num_addrs = argc - 1;
		addrs_list = &argv[1];
	} else if (lp_clustering()) {
		addrs_list = lp_cluster_addresses();
		num_addrs = str_list_length(addrs_list);
	}

	if (num_addrs > 0) {
		addrs = talloc_zero_array(tmp_ctx,
					  struct sockaddr_storage,
					  num_addrs);
		if (addrs == NULL) {
			d_fprintf(stderr, _("Error allocating memory!\n"));
			goto out;
		}
	}

	for (count = 0; count < num_addrs; count++) {
		if (!interpret_string_addr(&addrs[count], addrs_list[count], 0)) {
			d_fprintf(stderr, "%s '%s'.\n",
					  _("Cannot interpret address"),
					  addrs_list[count]);
			goto out;
		}
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if ( !ADS_ERR_OK(status) ) {
		DEBUG(1, ("error on ads_startup: %s\n", ads_errstr(status)));
		goto out;
	}

	ntstatus = net_update_dns_ext(c,
				      tmp_ctx,
				      ads,
				      c->creds,
				      hostname,
				      addrs,
				      num_addrs,
				      false);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		d_fprintf( stderr, _("DNS update failed!\n") );
		goto out;
	}

	d_fprintf( stderr, _("Successfully registered hostname with DNS\n") );

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);

	return ret;
#else
	d_fprintf(stderr,
		  _("DNS update support not enabled at compile time!\n"));
	return -1;
#endif
}

static int net_ads_dns_unregister(struct net_context *c,
				  int argc,
				  const char **argv)
{
#if defined(HAVE_KRB5)
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	NTSTATUS ntstatus;
	const char *hostname = NULL;
	int ret = -1;

#ifdef DEVELOPER
	talloc_enable_leak_report();
#endif

	if (argc != 1) {
		c->display_usage = true;
	}

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads dns unregister [hostname]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Remove all IP Address entries for a given\n"
                           "    hostname from the Active Directory server.\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	/* Get the hostname for un-registering */
	hostname = argv[0];

	status = ads_startup(c, true, tmp_ctx, &ads);
	if ( !ADS_ERR_OK(status) ) {
		DEBUG(1, ("error on ads_startup: %s\n", ads_errstr(status)));
		goto out;
	}

	ntstatus = net_update_dns_ext(c,
				      tmp_ctx,
				      ads,
				      c->creds,
				      hostname,
				      NULL,
				      0,
				      true);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		d_fprintf( stderr, _("DNS update failed!\n") );
		goto out;
	}

	d_fprintf( stderr, _("Successfully un-registered hostname from DNS\n"));

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);

	return ret;
#else
	d_fprintf(stderr,
		  _("DNS update support not enabled at compile time!\n"));
	return -1;
#endif
}


static int net_ads_dns_async(struct net_context *c, int argc, const char **argv)
{
	size_t num_names = 0;
	char **hostnames = NULL;
	size_t i = 0;
	struct samba_sockaddr *addrs = NULL;
	NTSTATUS status;

	if (argc != 1 || c->display_usage) {
		d_printf(  "%s\n"
			   "    %s\n"
			   "    %s\n",
			 _("Usage:"),
			 _("net ads dns async <name>\n"),
			 _("  Async look up hostname from the DNS server\n"
			   "    hostname\tName to look up\n"));
		return -1;
	}

	status = ads_dns_lookup_a(talloc_tos(),
				  argv[0],
				  &num_names,
				  &hostnames,
				  &addrs);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Looking up A record for %s got error %s\n",
			 argv[0],
			 nt_errstr(status));
		return -1;
	}
	d_printf("Async A record lookup - got %u names for %s\n",
		 (unsigned int)num_names,
		 argv[0]);
	for (i = 0; i < num_names; i++) {
		char addr_buf[INET6_ADDRSTRLEN];
		print_sockaddr(addr_buf,
			       sizeof(addr_buf),
			       &addrs[i].u.ss);
		d_printf("hostname[%u] = %s, IPv4addr = %s\n",
			(unsigned int)i,
			hostnames[i],
			addr_buf);
	}

#if defined(HAVE_IPV6)
	status = ads_dns_lookup_aaaa(talloc_tos(),
				     argv[0],
				     &num_names,
				     &hostnames,
				     &addrs);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Looking up AAAA record for %s got error %s\n",
			 argv[0],
			 nt_errstr(status));
		return -1;
	}
	d_printf("Async AAAA record lookup - got %u names for %s\n",
		 (unsigned int)num_names,
		 argv[0]);
	for (i = 0; i < num_names; i++) {
		char addr_buf[INET6_ADDRSTRLEN];
		print_sockaddr(addr_buf,
			       sizeof(addr_buf),
			       &addrs[i].u.ss);
		d_printf("hostname[%u] = %s, IPv6addr = %s\n",
			(unsigned int)i,
			hostnames[i],
			addr_buf);
	}
#endif
	return 0;
}


static int net_ads_dns(struct net_context *c, int argc, const char *argv[])
{
	struct functable func[] = {
		{
			"register",
			net_ads_dns_register,
			NET_TRANSPORT_ADS,
			N_("Add FQDN dns entry to AD"),
			N_("net ads dns register [FQDN [IP [IP.....]]]\n"
			   "    Add FQDN dns entry to AD")
		},
		{
			"unregister",
			net_ads_dns_unregister,
			NET_TRANSPORT_ADS,
			N_("Remove FQDN dns entry from AD"),
			N_("net ads dns unregister <FQDN>\n"
			   "    Remove FQDN dns entry from AD")
		},
		{
			"async",
			net_ads_dns_async,
			NET_TRANSPORT_ADS,
			N_("Look up host"),
			N_("net ads dns async\n"
			   "    Look up host using async DNS")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads dns", func);
}

/*******************************************************************
 ********************************************************************/

int net_ads_printer_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_(
"\nnet ads printer search <printer>"
"\n\tsearch for a printer in the directory\n"
"\nnet ads printer info <printer> <server>"
"\n\tlookup info in directory for printer on server"
"\n\t(note: printer defaults to \"*\", server defaults to local)\n"
"\nnet ads printer publish <printername>"
"\n\tpublish printer in directory"
"\n\t(note: printer name is required)\n"
"\nnet ads printer remove <printername>"
"\n\tremove printer from directory"
"\n\t(note: printer name is required)\n"));
	return -1;
}

/*******************************************************************
 ********************************************************************/

static int net_ads_printer_search(struct net_context *c,
				  int argc,
				  const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads printer search\n"
			   "    %s\n",
			 _("Usage:"),
			 _("List printers in the AD"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_printers(ads, &res);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_find_printer: %s\n"),
			  ads_errstr(status));
		goto out;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, _("No results found\n"));
		goto out;
	}

	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_printer_info(struct net_context *c,
				int argc,
				const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *servername = NULL;
	const char *printername = NULL;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads printer info [printername [servername]]\n"
			   "  Display printer info from AD\n"
			   "    printername\tPrinter name or wildcard\n"
			   "    servername\tName of the print server\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (argc > 0) {
		printername = argv[0];
	} else {
		printername = "*";
	}

	if (argc > 1) {
		servername =  argv[1];
	} else {
		servername = lp_netbios_name();
	}

	status = ads_find_printer_on_server(ads, &res, printername, servername);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Server '%s' not found: %s\n"),
			  servername, ads_errstr(status));
		goto out;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, _("Printer '%s' not found\n"), printername);
		goto out;
	}

	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_printer_publish(struct net_context *c,
				   int argc,
				   const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *servername = NULL;
	const char *printername = NULL;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;
	struct sockaddr_storage server_ss = { 0 };
	NTSTATUS nt_status;
	ADS_MODLIST mods = NULL;
	char *prt_dn = NULL;
	char *srv_dn = NULL;
	char **srv_cn = NULL;
	char *srv_cn_escaped = NULL;
	char *printername_escaped = NULL;
	LDAPMessage *res = NULL;
	bool ok;
	int ret = -1;
	struct smb_transports ts =
		smb_transports_parse("client smb transports",
				     lp_client_smb_transports());

	if (argc < 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads printer publish <printername> [servername]\n"
			   "  Publish printer in AD\n"
			   "    printername\tName of the printer\n"
			   "    servername\tName of the print server\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	mods = ads_init_mods(tmp_ctx);
	if (mods == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	printername = argv[0];

	if (argc == 2) {
		servername = argv[1];
	} else {
		servername = lp_netbios_name();
	}

	/* Get printer data from SPOOLSS */

	ok = resolve_name(servername, &server_ss, 0x20, false);
	if (!ok) {
		d_fprintf(stderr, _("Could not find server %s\n"),
			  servername);
		goto out;
	}

	cli_credentials_set_kerberos_state(c->creds,
					   CRED_USE_KERBEROS_REQUIRED,
					   CRED_SPECIFIED);

	nt_status = cli_full_connection_creds(c,
					      &cli,
					      lp_netbios_name(),
					      servername,
					      &server_ss,
					      &ts,
					      "IPC$",
					      "IPC",
					      c->creds,
					      CLI_FULL_CONNECTION_IPC);

	if (NT_STATUS_IS_ERR(nt_status)) {
		d_fprintf(stderr, _("Unable to open a connection to %s to "
			            "obtain data for %s\n"),
			  servername, printername);
		goto out;
	}

	/* Publish on AD server */

	ads_find_machine_acct(ads, &res, servername);

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, _("Could not find machine account for server "
				    "%s\n"),
			 servername);
		goto out;
	}

	srv_dn = ldap_get_dn((LDAP *)ads->ldap.ld, (LDAPMessage *)res);
	srv_cn = ldap_explode_dn(srv_dn, 1);

	srv_cn_escaped = escape_rdn_val_string_alloc(srv_cn[0]);
	printername_escaped = escape_rdn_val_string_alloc(printername);
	if (!srv_cn_escaped || !printername_escaped) {
		SAFE_FREE(srv_cn_escaped);
		SAFE_FREE(printername_escaped);
		d_fprintf(stderr, _("Internal error, out of memory!"));
		goto out;
	}

	prt_dn = talloc_asprintf(tmp_ctx,
				 "cn=%s-%s,%s",
				 srv_cn_escaped,
				 printername_escaped,
				 srv_dn);
	if (prt_dn == NULL) {
		SAFE_FREE(srv_cn_escaped);
		SAFE_FREE(printername_escaped);
		d_fprintf(stderr, _("Internal error, out of memory!"));
		goto out;
	}

	SAFE_FREE(srv_cn_escaped);
	SAFE_FREE(printername_escaped);

	nt_status = cli_rpc_pipe_open_noauth(cli, &ndr_table_spoolss, &pipe_hnd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_fprintf(stderr, _("Unable to open a connection to the spoolss pipe on %s\n"),
			 servername);
		goto out;
	}

	if (!W_ERROR_IS_OK(get_remote_printer_publishing_data(pipe_hnd,
							      tmp_ctx,
							      &mods,
							      printername))) {
		goto out;
	}

        status = ads_add_printer_entry(ads, prt_dn, tmp_ctx, &mods);
        if (!ADS_ERR_OK(status)) {
                d_fprintf(stderr, "ads_publish_printer: %s\n",
			  ads_errstr(status));
		goto out;
        }

        d_printf("published printer\n");

	ret = 0;
out:
	talloc_destroy(tmp_ctx);

	return ret;
}

static int net_ads_printer_remove(struct net_context *c,
				  int argc,
				  const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *servername = NULL;
	char *prt_dn = NULL;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (argc < 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads printer remove <printername> [servername]\n"
			   "  Remove a printer from the AD\n"
			   "    printername\tName of the printer\n"
			   "    servername\tName of the print server\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (argc > 1) {
		servername = argv[1];
	} else {
		servername = lp_netbios_name();
	}

	status = ads_find_printer_on_server(ads, &res, argv[0], servername);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_find_printer_on_server: %s\n"),
			  ads_errstr(status));
		goto out;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, _("Printer '%s' not found\n"), argv[1]);
		goto out;
	}

	prt_dn = ads_get_dn(ads, tmp_ctx, res);
	if (prt_dn == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	status = ads_del_dn(ads, prt_dn);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("ads_del_dn: %s\n"), ads_errstr(status));
		goto out;
	}

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_printer(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"search",
			net_ads_printer_search,
			NET_TRANSPORT_ADS,
			N_("Search for a printer"),
			N_("net ads printer search\n"
			   "    Search for a printer")
		},
		{
			"info",
			net_ads_printer_info,
			NET_TRANSPORT_ADS,
			N_("Display printer information"),
			N_("net ads printer info\n"
			   "    Display printer information")
		},
		{
			"publish",
			net_ads_printer_publish,
			NET_TRANSPORT_ADS,
			N_("Publish a printer"),
			N_("net ads printer publish\n"
			   "    Publish a printer")
		},
		{
			"remove",
			net_ads_printer_remove,
			NET_TRANSPORT_ADS,
			N_("Delete a printer"),
			N_("net ads printer remove\n"
			   "    Delete a printer")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads printer", func);
}


static int net_ads_password(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	const char *auth_principal = cli_credentials_get_username(c->creds);
	const char *auth_password = cli_credentials_get_password(c->creds);
	const char *realm = NULL;
	char *new_password = NULL;
	char *chr = NULL;
	char *prompt = NULL;
	const char *user = NULL;
	char pwd[256] = {0};
	ADS_STATUS status;
	int ret = 0;

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads password <username>\n"
			   "  Change password for user\n"
			   "    username\tName of user to change password for\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (auth_principal == NULL || auth_password == NULL) {
		d_fprintf(stderr, _("You must supply an administrator "
				    "username/password\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (argc < 1) {
		d_fprintf(stderr, _("ERROR: You must say which username to "
				    "change password for\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (strchr_m(argv[0], '@')) {
		user = talloc_strdup(tmp_ctx, argv[0]);
	} else {
		user = talloc_asprintf(tmp_ctx, "%s@%s", argv[0], lp_realm());
	}
	if (user == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	chr = strchr_m(auth_principal, '@');
	if (chr) {
		realm = ++chr;
	} else {
		realm = lp_realm();
	}

	/* use the realm so we can eventually change passwords for users
	in realms other than default */
	ads = ads_init(tmp_ctx,
		       realm,
		       c->opt_workgroup,
		       c->opt_host,
		       ADS_SASL_PLAIN);
	if (ads == NULL) {
		goto out;
	}

	/* we don't actually need a full connect, but it's the easy way to
		fill in the KDC's address */
	ads->auth.flags |= ADS_AUTH_GENERATE_KRB5_CONFIG;
	ads_connect_cldap_only(ads);

	if (!ads->config.realm) {
		d_fprintf(stderr, _("Didn't find the kerberos server!\n"));
		goto out;
	}

	if (argv[1] != NULL) {
		new_password = talloc_strdup(tmp_ctx, argv[1]);
	} else {
		int rc;

		prompt = talloc_asprintf(tmp_ctx, _("Enter new password for %s:"), user);
		if (prompt == NULL) {
			d_fprintf(stderr, _("Out of memory\n"));
			goto out;
		}

		rc = samba_getpass(prompt, pwd, sizeof(pwd), false, true);
		if (rc < 0) {
			goto out;
		}
		new_password = talloc_strdup(tmp_ctx, pwd);
		memset(pwd, '\0', sizeof(pwd));
	}

	if (new_password == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	status = kerberos_set_password(auth_principal,
				       auth_password,
				       user,
				       new_password);
	memset(new_password, '\0', strlen(new_password));
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Password change failed: %s\n"),
			  ads_errstr(status));
		goto out;
	}

	d_printf(_("Password change for %s completed.\n"), user);

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int net_ads_changetrustpw(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	char *host_principal = NULL;
	char *my_name = NULL;
	ADS_STATUS status;
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads changetrustpw\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Change the machine account's trust password"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		goto out;
	}

	net_warn_member_options();

	net_use_krb_machine_account(c);

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	my_name = talloc_asprintf_strlower_m(tmp_ctx, "%s", lp_netbios_name());
	if (my_name == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	host_principal = talloc_asprintf(tmp_ctx, "%s$@%s", my_name, ads->config.realm);
	if (host_principal == NULL) {
		d_fprintf(stderr, _("Out of memory\n"));
		goto out;
	}

	d_printf(_("Changing password for principal: %s\n"), host_principal);

	status = ads_change_trust_account_password(ads, host_principal);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("Password change failed: %s\n"), ads_errstr(status));
		goto out;
	}

	d_printf(_("Password change for principal %s succeeded.\n"), host_principal);

	ret = 0;
out:
	TALLOC_FREE(tmp_ctx);

	return ret;
}

/*
  help for net ads search
*/
static int net_ads_search_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_(
		"\nnet ads search <expression> <attributes...>\n"
		"\nPerform a raw LDAP search on a ADS server and dump the results.\n"
		"The expression is a standard LDAP search expression, and the\n"
		"attributes are a list of LDAP fields to show in the results.\n\n"
		"Example: net ads search '(objectCategory=group)' sAMAccountName\n\n"
		));
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_search(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *ldap_exp = NULL;
	const char **attrs = NULL;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_search_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	ldap_exp = argv[0];
	attrs = (argv + 1);

	status = ads_do_search_retry(ads,
				     ads->config.bind_path,
				     LDAP_SCOPE_SUBTREE,
				     ldap_exp,
				     attrs,
				     &res);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("search failed: %s\n"), ads_errstr(status));
		goto out;
	}

	d_printf(_("Got %d replies\n\n"), ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}


/*
  help for net ads search
*/
static int net_ads_dn_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_(
		"\nnet ads dn <dn> <attributes...>\n"
		"\nperform a raw LDAP search on a ADS server and dump the results\n"
		"The DN standard LDAP DN, and the attributes are a list of LDAP fields \n"
		"to show in the results\n\n"
		"Example: net ads dn 'CN=administrator,CN=Users,DC=my,DC=domain' sAMAccountName\n\n"
		"Note: the DN must be provided properly escaped. See RFC 4514 for details\n\n"
		));
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_dn(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *dn = NULL;
	const char **attrs = NULL;
	LDAPMessage *res = NULL;
	int ret = -1;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_dn_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	dn = argv[0];
	attrs = (argv + 1);

	status = ads_do_search_all(ads,
				   dn,
				   LDAP_SCOPE_BASE,
				   "(objectclass=*)",
				   attrs,
				   &res);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("search failed: %s\n"), ads_errstr(status));
		goto out;
	}

	d_printf("Got %d replies\n\n", ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*
  help for net ads sid search
*/
static int net_ads_sid_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_(
		"\nnet ads sid <sid> <attributes...>\n"
		"\nperform a raw LDAP search on a ADS server and dump the results\n"
		"The SID is in string format, and the attributes are a list of LDAP fields \n"
		"to show in the results\n\n"
		"Example: net ads sid 'S-1-5-32' distinguishedName\n\n"
		));
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_sid(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	const char *sid_string = NULL;
	const char **attrs = NULL;
	LDAPMessage *res = NULL;
	struct dom_sid sid = { 0 };
	int ret = -1;

	if (argc < 1 || c->display_usage) {
		TALLOC_FREE(tmp_ctx);
		return net_ads_sid_usage(c, argc, argv);
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	sid_string = argv[0];
	attrs = (argv + 1);

	if (!string_to_sid(&sid, sid_string)) {
		d_fprintf(stderr, _("could not convert sid\n"));
		goto out;
	}

	status = ads_search_retry_sid(ads, &res, &sid, attrs);
	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, _("search failed: %s\n"), ads_errstr(status));
		goto out;
	}

	d_printf(_("Got %d replies\n\n"), ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ret = 0;
out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_keytab_create(struct net_context *c, int argc, const char **argv)
{
	NTSTATUS ntstatus;
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads keytab create\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Create (sync) new default keytab"));
		return -1;
	}

	net_warn_member_options();

	if (!c->explicit_credentials) {
		net_use_krb_machine_account(c);
	}

	ntstatus = sync_pw2keytabs(c->opt_host);
	ret = NT_STATUS_IS_OK(ntstatus) ? 0 : 1;
	return ret;
}

static int net_ads_keytab_list(struct net_context *c, int argc, const char **argv)
{
	const char *keytab = NULL;

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads keytab list [keytab]\n"
			   "  List a local keytab (default: krb5 default)\n"
			   "    keytab\tKeytab to list\n"));
		return -1;
	}

	if (argc >= 1) {
		keytab = argv[0];
	}

	return ads_keytab_list(keytab);
}

int net_ads_keytab(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"create",
			net_ads_keytab_create,
			NET_TRANSPORT_ADS,
			N_("Create (sync) a fresh keytab"),
			N_("net ads keytab create\n"
			   "    Create (sync) a fresh keytab or update existing one (see also smb.conf 'sync machine password to keytab'.")
		},
		{
			"list",
			net_ads_keytab_list,
			NET_TRANSPORT_ADS,
			N_("List a keytab"),
			N_("net ads keytab list\n"
			   "    List a keytab")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads keytab", func);
}

static int net_ads_kerberos_renew(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads kerberos renew\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Renew TGT from existing credential cache"));
		return -1;
	}

	ret = smb_krb5_renew_ticket(c->opt_krb5_ccache, NULL, NULL, NULL);
	if (ret) {
		d_printf(_("failed to renew kerberos ticket: %s\n"),
			error_message(ret));
	}
	return ret;
}

static int net_ads_kerberos_pac_common(struct net_context *c, int argc, const char **argv,
				       struct PAC_DATA_CTR **pac_data_ctr)
{
	NTSTATUS status;
	int ret = -1;
	const char *impersonate_princ_s = NULL;
	const char *local_service = NULL;
	const char *principal = NULL;
	const char *password = NULL;
	int i;

	for (i=0; i<argc; i++) {
		if (strnequal(argv[i], "impersonate", strlen("impersonate"))) {
			impersonate_princ_s = get_string_param(argv[i]);
			if (impersonate_princ_s == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "local_service", strlen("local_service"))) {
			local_service = get_string_param(argv[i]);
			if (local_service == NULL) {
				return -1;
			}
		}
	}

	if (local_service == NULL) {
		local_service = talloc_asprintf(c, "%s$@%s",
						lp_netbios_name(), lp_realm());
		if (local_service == NULL) {
			goto out;
		}
	}

	principal = cli_credentials_get_principal(c->creds, c);
	if (principal == NULL) {
		d_printf("cli_credentials_get_principal() failed\n");
		goto out;
	}
	password = cli_credentials_get_password(c->creds);

	status = kerberos_return_pac(c,
				     principal,
				     password,
				     0,
				     NULL,
				     NULL,
				     c->opt_krb5_ccache,
				     true,
				     true,
				     2592000, /* one month */
				     impersonate_princ_s,
				     local_service,
				     NULL,
				     NULL,
				     pac_data_ctr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf(_("failed to query kerberos PAC: %s\n"),
			nt_errstr(status));
		goto out;
	}

	ret = 0;
 out:
	return ret;
}

static int net_ads_kerberos_pac_dump(struct net_context *c, int argc, const char **argv)
{
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	int i, num_buffers;
	int ret = -1;
	enum PAC_TYPE type = 0;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads kerberos pac dump [impersonate=string] [local_service=string] [pac_buffer_type=int]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Dump the Kerberos PAC"));
		return -1;
	}

	for (i=0; i<argc; i++) {
		if (strnequal(argv[i], "pac_buffer_type", strlen("pac_buffer_type"))) {
			type = get_int_param(argv[i]);
		}
	}

	ret = net_ads_kerberos_pac_common(c, argc, argv, &pac_data_ctr);
	if (ret) {
		return ret;
	}

	if (type == 0) {

		char *s = NULL;

		s = NDR_PRINT_STRUCT_STRING(c, PAC_DATA,
			pac_data_ctr->pac_data);
		if (s != NULL) {
			d_printf(_("The Pac: %s\n"), s);
			talloc_free(s);
		}

		return 0;
	}

	num_buffers = pac_data_ctr->pac_data->num_buffers;

	for (i=0; i<num_buffers; i++) {

		char *s = NULL;

		if (pac_data_ctr->pac_data->buffers[i].type != type) {
			continue;
		}

		s = NDR_PRINT_UNION_STRING(c, PAC_INFO, type,
				pac_data_ctr->pac_data->buffers[i].info);
		if (s != NULL) {
			d_printf(_("The Pac: %s\n"), s);
			talloc_free(s);
		}
		break;
	}

	return 0;
}

static int net_ads_kerberos_pac_save(struct net_context *c, int argc, const char **argv)
{
	struct PAC_DATA_CTR *pac_data_ctr = NULL;
	char *filename = NULL;
	int ret = -1;
	int i;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads kerberos pac save [impersonate=string] [local_service=string] [filename=string]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Save the Kerberos PAC"));
		return -1;
	}

	for (i=0; i<argc; i++) {
		if (strnequal(argv[i], "filename", strlen("filename"))) {
			filename = get_string_param(argv[i]);
			if (filename == NULL) {
				return -1;
			}
		}
	}

	ret = net_ads_kerberos_pac_common(c, argc, argv, &pac_data_ctr);
	if (ret) {
		return ret;
	}

	if (filename == NULL) {
		d_printf(_("please define \"filename=<filename>\" to save the PAC\n"));
		return -1;
	}

	/* save the raw format */
	if (!file_save(filename, pac_data_ctr->pac_blob.data, pac_data_ctr->pac_blob.length)) {
		d_printf(_("failed to save PAC in %s\n"), filename);
		return -1;
	}

	return 0;
}

static int net_ads_kerberos_pac(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"dump",
			net_ads_kerberos_pac_dump,
			NET_TRANSPORT_ADS,
			N_("Dump Kerberos PAC"),
			N_("net ads kerberos pac dump\n"
			   "    Dump a Kerberos PAC to stdout")
		},
		{
			"save",
			net_ads_kerberos_pac_save,
			NET_TRANSPORT_ADS,
			N_("Save Kerberos PAC"),
			N_("net ads kerberos pac save\n"
			   "    Save a Kerberos PAC in a file")
		},

		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads kerberos pac", func);
}

static int net_ads_kerberos_kinit(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;
	NTSTATUS status;
	const char *principal = NULL;
	const char *password = NULL;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads kerberos kinit\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Get Ticket Granting Ticket (TGT) for the user"));
		return -1;
	}

	principal = cli_credentials_get_principal(c->creds, c);
	if (principal == NULL) {
		d_printf("cli_credentials_get_principal() failed\n");
		return -1;
	}
	password = cli_credentials_get_password(c->creds);

	ret = kerberos_kinit_password_ext(principal,
					  password,
					  0,
					  NULL,
					  NULL,
					  c->opt_krb5_ccache,
					  true,
					  true,
					  2592000, /* one month */
					  NULL,
					  NULL,
					  NULL,
					  &status);
	if (ret) {
		d_printf(_("failed to kinit password: %s\n"),
			nt_errstr(status));
	}
	return ret;
}

int net_ads_kerberos(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"kinit",
			net_ads_kerberos_kinit,
			NET_TRANSPORT_ADS,
			N_("Retrieve Ticket Granting Ticket (TGT)"),
			N_("net ads kerberos kinit\n"
			   "    Receive Ticket Granting Ticket (TGT)")
		},
		{
			"renew",
			net_ads_kerberos_renew,
			NET_TRANSPORT_ADS,
			N_("Renew Ticket Granting Ticket from credential cache"),
			N_("net ads kerberos renew\n"
			   "    Renew Ticket Granting Ticket (TGT) from "
			   "credential cache")
		},
		{
			"pac",
			net_ads_kerberos_pac,
			NET_TRANSPORT_ADS,
			N_("Dump Kerberos PAC"),
			N_("net ads kerberos pac\n"
			   "    Dump Kerberos PAC")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads kerberos", func);
}

static int net_ads_setspn_list(struct net_context *c,
			       int argc,
			       const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	bool ok = false;
	int ret = -1;

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads setspn list [machinename]\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (argc) {
		ok = ads_setspn_list(ads, argv[0]);
	} else {
		ok = ads_setspn_list(ads, lp_netbios_name());
	}

	ret = ok ? 0 : -1;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_setspn_add(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	bool ok = false;
	int ret = -1;

	if (c->display_usage || argc < 1) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads setspn add [machinename] spn\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (argc > 1) {
		ok = ads_setspn_add(ads, argv[0], argv[1]);
	} else {
		ok = ads_setspn_add(ads, lp_netbios_name(), argv[0]);
	}

	ret = ok ? 0 : -1;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_setspn_delete(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	bool ok = false;
	int ret = -1;

	if (c->display_usage || argc < 1) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net ads setspn delete [machinename] spn\n"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, true, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (argc > 1) {
		ok = ads_setspn_delete(ads, argv[0], argv[1]);
	} else {
		ok = ads_setspn_delete(ads, lp_netbios_name(), argv[0]);
	}

	ret = ok ? 0 : -1;
out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int net_ads_setspn(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"list",
			net_ads_setspn_list,
			NET_TRANSPORT_ADS,
			N_("List Service Principal Names (SPN)"),
			N_("net ads setspn list [machine]\n"
			   "    List Service Principal Names (SPN)")
		},
		{
			"add",
			net_ads_setspn_add,
			NET_TRANSPORT_ADS,
			N_("Add Service Principal Names (SPN)"),
			N_("net ads setspn add [machine] spn\n"
			   "    Add Service Principal Names (SPN)")
		},
		{
			"delete",
			net_ads_setspn_delete,
			NET_TRANSPORT_ADS,
			N_("Delete Service Principal Names (SPN)"),
			N_("net ads setspn delete [machine] spn\n"
			   "    Delete Service Principal Names (SPN)")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads setspn", func);
}

static int net_ads_enctype_lookup_account(struct net_context *c,
					  ADS_STRUCT *ads,
					  const char *account,
					  LDAPMessage **res,
					  const char **enctype_str)
{
	const char *filter;
	const char *attrs[] = {
		"msDS-SupportedEncryptionTypes",
		NULL
	};
	int count;
	int ret = -1;
	ADS_STATUS status;

	filter = talloc_asprintf(c, "(&(objectclass=user)(sAMAccountName=%s))",
				 account);
	if (filter == NULL) {
		goto done;
	}

	status = ads_search(ads, res, filter, attrs);
	if (!ADS_ERR_OK(status)) {
		d_printf(_("no account found with filter: %s\n"), filter);
		goto done;
	}

	count = ads_count_replies(ads, *res);
	switch (count) {
	case 1:
		break;
	case 0:
		d_printf(_("no account found with filter: %s\n"), filter);
		goto done;
	default:
		d_printf(_("multiple accounts found with filter: %s\n"), filter);
		goto done;
	}

	if (enctype_str) {
		*enctype_str = ads_pull_string(ads, c, *res,
					       "msDS-SupportedEncryptionTypes");
		if (*enctype_str == NULL) {
			d_printf(_("no msDS-SupportedEncryptionTypes attribute found\n"));
			goto done;
		}
	}

	ret = 0;
 done:
	return ret;
}

static void net_ads_enctype_dump_enctypes(const char *username,
					  const char *enctype_str)
{
	int enctypes = atoi(enctype_str);

	d_printf(_("'%s' uses \"msDS-SupportedEncryptionTypes\": %d (0x%08x)\n"),
		username, enctypes, enctypes);

	printf("[%s] 0x%08x DES-CBC-CRC\n",
		enctypes & ENC_CRC32 ? "X" : " ",
		ENC_CRC32);
	printf("[%s] 0x%08x DES-CBC-MD5\n",
		enctypes & ENC_RSA_MD5 ? "X" : " ",
		ENC_RSA_MD5);
	printf("[%s] 0x%08x RC4-HMAC\n",
		enctypes & ENC_RC4_HMAC_MD5 ? "X" : " ",
		ENC_RC4_HMAC_MD5);
	printf("[%s] 0x%08x AES128-CTS-HMAC-SHA1-96\n",
		enctypes & ENC_HMAC_SHA1_96_AES128 ? "X" : " ",
		ENC_HMAC_SHA1_96_AES128);
	printf("[%s] 0x%08x AES256-CTS-HMAC-SHA1-96\n",
		enctypes & ENC_HMAC_SHA1_96_AES256 ? "X" : " ",
		ENC_HMAC_SHA1_96_AES256);
	printf("[%s] 0x%08x AES256-CTS-HMAC-SHA1-96-SK\n",
		enctypes & ENC_HMAC_SHA1_96_AES256_SK ? "X" : " ",
		ENC_HMAC_SHA1_96_AES256_SK);
	printf("[%s] 0x%08x RESOURCE-SID-COMPRESSION-DISABLED\n",
		enctypes & KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED ? "X" : " ",
		KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED);
}

static int net_ads_enctypes_list(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STATUS status;
	ADS_STRUCT *ads = NULL;
	LDAPMessage *res = NULL;
	const char *str = NULL;
	int ret = -1;

	if (c->display_usage || (argc < 1)) {
		d_printf(  "%s\n"
			   "net ads enctypes list <account_name>\n"
			   "    %s\n",
			 _("Usage:"),
			 _("List supported enctypes"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	ret = net_ads_enctype_lookup_account(c, ads, argv[0], &res, &str);
	if (ret) {
		goto out;
	}

	net_ads_enctype_dump_enctypes(argv[0], str);

	ret = 0;
 out:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_enctypes_set(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	int ret = -1;
	ADS_STATUS status;
	ADS_STRUCT *ads = NULL;
	LDAPMessage *res = NULL;
	const char *etype_list_str = NULL;
	const char *dn = NULL;
	ADS_MODLIST mods = NULL;
	uint32_t etype_list;
	const char *str = NULL;

	if (c->display_usage || argc < 1) {
		d_printf(  "%s\n"
			   "net ads enctypes set <sAMAccountName> [enctypes]\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Set supported enctypes"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	ret = net_ads_enctype_lookup_account(c, ads, argv[0], &res, NULL);
	if (ret) {
		goto done;
	}

	dn = ads_get_dn(ads, tmp_ctx, res);
	if (dn == NULL) {
		goto done;
	}

	etype_list = 0;
	etype_list |= ENC_RC4_HMAC_MD5;
	etype_list |= ENC_HMAC_SHA1_96_AES128;
	etype_list |= ENC_HMAC_SHA1_96_AES256;

	if (argv[1] != NULL) {
		sscanf(argv[1], "%i", &etype_list);
	}

	etype_list_str = talloc_asprintf(tmp_ctx, "%d", etype_list);
	if (!etype_list_str) {
		goto done;
	}

	mods = ads_init_mods(tmp_ctx);
	if (!mods) {
		goto done;
	}

	status = ads_mod_str(tmp_ctx, &mods, "msDS-SupportedEncryptionTypes",
			     etype_list_str);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	status = ads_gen_mod(ads, dn, mods);
	if (!ADS_ERR_OK(status)) {
		d_printf(_("failed to add msDS-SupportedEncryptionTypes: %s\n"),
			ads_errstr(status));
		goto done;
	}

	ads_msgfree(ads, res);
	res = NULL;

	ret = net_ads_enctype_lookup_account(c, ads, argv[0], &res, &str);
	if (ret) {
		goto done;
	}

	net_ads_enctype_dump_enctypes(argv[0], str);

	ret = 0;
 done:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_enctypes_delete(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	int ret = -1;
	ADS_STATUS status;
	ADS_STRUCT *ads = NULL;
	LDAPMessage *res = NULL;
	const char *dn = NULL;
	ADS_MODLIST mods = NULL;

	if (c->display_usage || argc < 1) {
		d_printf(  "%s\n"
			   "net ads enctypes delete <sAMAccountName>\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Delete supported enctypes"));
		TALLOC_FREE(tmp_ctx);
		return -1;
	}

	status = ads_startup(c, false, tmp_ctx, &ads);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	ret = net_ads_enctype_lookup_account(c, ads, argv[0], &res, NULL);
	if (ret) {
		goto done;
	}

	dn = ads_get_dn(ads, tmp_ctx, res);
	if (dn == NULL) {
		goto done;
	}

	mods = ads_init_mods(tmp_ctx);
	if (!mods) {
		goto done;
	}

	status = ads_mod_str(tmp_ctx, &mods, "msDS-SupportedEncryptionTypes", NULL);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	status = ads_gen_mod(ads, dn, mods);
	if (!ADS_ERR_OK(status)) {
		d_printf(_("failed to remove msDS-SupportedEncryptionTypes: %s\n"),
			ads_errstr(status));
		goto done;
	}

	ret = 0;

 done:
	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static int net_ads_enctypes(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"list",
			net_ads_enctypes_list,
			NET_TRANSPORT_ADS,
			N_("List the supported encryption types"),
			N_("net ads enctypes list <account_name>\n"
			   "    List the supported encryption types")
		},
		{
			"set",
			net_ads_enctypes_set,
			NET_TRANSPORT_ADS,
			N_("Set the supported encryption types"),
			N_("net ads enctypes set <account_name> [enctypes]\n"
			   "    Set the supported encryption types")
		},
		{
			"delete",
			net_ads_enctypes_delete,
			NET_TRANSPORT_ADS,
			N_("Delete the msDS-SupportedEncryptionTypes attribute"),
			N_("net ads enctypes delete <account_name>\n"
			   "    Delete the LDAP attribute")
		},

		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads enctypes", func);
}


int net_ads(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"info",
			net_ads_info,
			NET_TRANSPORT_ADS,
			N_("Display details on remote ADS server"),
			N_("net ads info\n"
			   "    Display details on remote ADS server")
		},
		{
			"join",
			net_ads_join,
			NET_TRANSPORT_ADS,
			N_("Join the local machine to ADS realm"),
			N_("net ads join\n"
			   "    Join the local machine to ADS realm")
		},
		{
			"testjoin",
			net_ads_testjoin,
			NET_TRANSPORT_ADS,
			N_("Validate machine account"),
			N_("net ads testjoin\n"
			   "    Validate machine account")
		},
		{
			"leave",
			net_ads_leave,
			NET_TRANSPORT_ADS,
			N_("Remove the local machine from ADS"),
			N_("net ads leave\n"
			   "    Remove the local machine from ADS")
		},
		{
			"status",
			net_ads_status,
			NET_TRANSPORT_ADS,
			N_("Display machine account details"),
			N_("net ads status\n"
			   "    Display machine account details")
		},
		{
			"user",
			net_ads_user,
			NET_TRANSPORT_ADS,
			N_("List/modify users"),
			N_("net ads user\n"
			   "    List/modify users")
		},
		{
			"group",
			net_ads_group,
			NET_TRANSPORT_ADS,
			N_("List/modify groups"),
			N_("net ads group\n"
			   "    List/modify groups")
		},
		{
			"dns",
			net_ads_dns,
			NET_TRANSPORT_ADS,
			N_("Issue dynamic DNS update"),
			N_("net ads dns\n"
			   "    Issue dynamic DNS update")
		},
		{
			"password",
			net_ads_password,
			NET_TRANSPORT_ADS,
			N_("Change user passwords"),
			N_("net ads password\n"
			   "    Change user passwords")
		},
		{
			"changetrustpw",
			net_ads_changetrustpw,
			NET_TRANSPORT_ADS,
			N_("Change trust account password"),
			N_("net ads changetrustpw\n"
			   "    Change trust account password")
		},
		{
			"printer",
			net_ads_printer,
			NET_TRANSPORT_ADS,
			N_("List/modify printer entries"),
			N_("net ads printer\n"
			   "    List/modify printer entries")
		},
		{
			"search",
			net_ads_search,
			NET_TRANSPORT_ADS,
			N_("Issue LDAP search using filter"),
			N_("net ads search\n"
			   "    Issue LDAP search using filter")
		},
		{
			"dn",
			net_ads_dn,
			NET_TRANSPORT_ADS,
			N_("Issue LDAP search by DN"),
			N_("net ads dn\n"
			   "    Issue LDAP search by DN")
		},
		{
			"sid",
			net_ads_sid,
			NET_TRANSPORT_ADS,
			N_("Issue LDAP search by SID"),
			N_("net ads sid\n"
			   "    Issue LDAP search by SID")
		},
		{
			"workgroup",
			net_ads_workgroup,
			NET_TRANSPORT_ADS,
			N_("Display workgroup name"),
			N_("net ads workgroup\n"
			   "    Display the workgroup name")
		},
		{
			"lookup",
			net_ads_lookup,
			NET_TRANSPORT_ADS,
			N_("Perform CLDAP query on DC"),
			N_("net ads lookup\n"
			   "    Find the ADS DC using CLDAP lookups")
		},
		{
			"keytab",
			net_ads_keytab,
			NET_TRANSPORT_ADS,
			N_("Manage local keytab file"),
			N_("net ads keytab\n"
			   "    Manage local keytab file")
		},
		{
			"setspn",
			net_ads_setspn,
			NET_TRANSPORT_ADS,
			N_("Manage Service Principal Names (SPN)s"),
			N_("net ads spnset\n"
			   "    Manage Service Principal Names (SPN)s")
		},
		{
			"gpo",
			net_ads_gpo,
			NET_TRANSPORT_ADS,
			N_("Manage group policy objects"),
			N_("net ads gpo\n"
			   "    Manage group policy objects")
		},
		{
			"kerberos",
			net_ads_kerberos,
			NET_TRANSPORT_ADS,
			N_("Manage kerberos keytab"),
			N_("net ads kerberos\n"
			   "    Manage kerberos keytab")
		},
		{
			"enctypes",
			net_ads_enctypes,
			NET_TRANSPORT_ADS,
			N_("List/modify supported encryption types"),
			N_("net ads enctypes\n"
			   "    List/modify enctypes")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads", func);
}

#else

static int net_ads_noads(void)
{
	d_fprintf(stderr, _("ADS support not compiled in\n"));
	return -1;
}

int net_ads_keytab(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_kerberos(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_setspn(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_changetrustpw(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_join(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_user(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_group(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_gpo(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

/* this one shouldn't display a message */
int net_ads_check(struct net_context *c)
{
	return -1;
}

int net_ads_check_our_domain(struct net_context *c)
{
	return -1;
}

int net_ads(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

#endif	/* HAVE_ADS */
