/* 
   Unix SMB/CIFS implementation.
   krb5 set password implementation
   Copyright (C) Remus Koos 2001 (remuskoos@yahoo.com)
   
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
#include "secrets.h"
#include "librpc/gen_ndr/ndr_secrets.h"

#ifdef HAVE_KRB5
ADS_STATUS ads_change_trust_account_password(ADS_STRUCT *ads, char *host_principal)
{
	const char *password = NULL;
	const char *new_password = NULL;
	ADS_STATUS ret;
	const char *domain = lp_workgroup();
	struct secrets_domain_info1 *info = NULL;
	struct secrets_domain_info1_change *prev = NULL;
	const DATA_BLOB *cleartext_blob = NULL;
	DATA_BLOB pw_blob = data_blob_null;
	DATA_BLOB new_pw_blob = data_blob_null;
	NTSTATUS status;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	int role = lp_server_role();
	bool ok;

	if (role != ROLE_DOMAIN_MEMBER) {
		DBG_ERR("Machine account password change only supported on a DOMAIN_MEMBER.\n");
		return ADS_ERROR_NT(NT_STATUS_INVALID_SERVER_STATE);
	}

	new_password = trust_pw_new_value(talloc_tos(), SEC_CHAN_WKSTA, SEC_ADS);
	if (new_password == NULL) {
		ret = ADS_ERROR_SYSTEM(errno);
		DEBUG(1,("Failed to generate machine password\n"));
		return ret;
	}

	status = secrets_prepare_password_change(domain,
						 ads->auth.kdc_server,
						 new_password,
						 talloc_tos(),
						 &info, &prev);
	if (!NT_STATUS_IS_OK(status)) {
		return ADS_ERROR_NT(status);
	}
	if (prev != NULL) {
		status = NT_STATUS_REQUEST_NOT_ACCEPTED;
		secrets_failed_password_change("localhost",
					       status,
					       NT_STATUS_NOT_COMMITTED,
					       info);
		return ADS_ERROR_NT(status);
	}

	cleartext_blob = &info->password->cleartext_blob;
	ok = convert_string_talloc(talloc_tos(), CH_UTF16MUNGED, CH_UNIX,
				   cleartext_blob->data,
				   cleartext_blob->length,
				   (void **)&pw_blob.data,
				   &pw_blob.length);
	if (!ok) {
		status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		DBG_ERR("convert_string_talloc(CH_UTF16MUNGED, CH_UNIX) "
			"failed for password of %s - %s\n",
			domain, nt_errstr(status));
		return ADS_ERROR_NT(status);
	}
	password = (const char *)pw_blob.data;

	cleartext_blob = &info->next_change->password->cleartext_blob;
	ok = convert_string_talloc(talloc_tos(), CH_UTF16MUNGED, CH_UNIX,
				   cleartext_blob->data,
				   cleartext_blob->length,
				   (void **)&new_pw_blob.data,
				   &new_pw_blob.length);
	if (!ok) {
		status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		DBG_ERR("convert_string_talloc(CH_UTF16MUNGED, CH_UNIX) "
			"failed for new_password of %s - %s\n",
			domain, nt_errstr(status));
		secrets_failed_password_change("localhost",
					       status,
					       NT_STATUS_NOT_COMMITTED,
					       info);
		return ADS_ERROR_NT(status);
	}
	new_password = (const char *)new_pw_blob.data;

	ret = kerberos_set_password(ads->auth.kdc_server, host_principal, password, host_principal, new_password, ads->auth.time_offset);

	if (!ADS_ERR_OK(ret)) {
		status = ads_ntstatus(ret);
		DBG_ERR("kerberos_set_password(%s, %s) "
			"failed for new_password of %s - %s\n",
			ads->auth.kdc_server, host_principal,
			domain, nt_errstr(status));
		secrets_failed_password_change(ads->auth.kdc_server,
					       NT_STATUS_NOT_COMMITTED,
					       status,
					       info);
		return ret;
	}

	status = secrets_finish_password_change(ads->auth.kdc_server, now, info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("Failed to save machine password\n"));
		return ADS_ERROR_NT(status);
	}

	return ADS_SUCCESS;
}
#endif

/**
* @brief Parses windows style SPN service/host:port/servicename
*      serviceclass - A string that identifies the general class of service
*            e.g. 'http'
*      host - A netbios name or fully-qualified DNS name
*      port - An optional TCP or UDP port number
*      servicename - An optional distinguished name, GUID, DNS name or
*                    DNS name of an SRV or MX record. (not needed for host
*                    based services)
*
* @param[in]  ctx 	- Talloc context.
* @param[in]  srvprinc  - The service principal
*
* @return 		- struct spn_struct containing the fields parsed or NULL
*			  if srvprinc could not be parsed.
*/
struct spn_struct *parse_spn(TALLOC_CTX *ctx, const char *srvprinc)
{
	struct spn_struct * result = NULL;
	char *tmp = NULL;
	char *port_str = NULL;
	char *host_str = NULL;

	result = talloc_zero(ctx, struct spn_struct);
	if (result == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	result->serviceclass = talloc_strdup(result, srvprinc);
	if (result->serviceclass == NULL) {
		DBG_ERR("Out of memory\n");
		goto fail;
	}
	result->port = -1;

	tmp = strchr_m(result->serviceclass, '/');
	if (tmp == NULL) {
		/* illegal */
		DBG_ERR("Failed to parse spn %s, no host definition\n",
			srvprinc);
		goto fail;
	}

	/* terminate service principal */
	*tmp = '\0';
	tmp++;
	host_str = tmp;

	tmp = strchr_m(host_str, ':');
	if (tmp != NULL) {
		*tmp  = '\0';
		tmp++;
		port_str = tmp;
	} else {
		tmp = host_str;
	}

	tmp = strchr_m(tmp, '/');
	if (tmp != NULL) {
		*tmp  = '\0';
		tmp++;
		result->servicename = tmp;
	}

	if (strlen(host_str) == 0) {
		/* illegal */
		DBG_ERR("Failed to parse spn %s, illegal host definition\n",
			srvprinc);
		goto fail;
	}
	result->host = host_str;

	if (result->servicename != NULL && (strlen(result->servicename) == 0)) {
		DBG_ERR("Failed to parse spn %s, empty servicename "
			"definition\n", srvprinc);
		goto fail;
	}
	if (port_str != NULL) {
		if (strlen(port_str) == 0) {
			DBG_ERR("Failed to parse spn %s, empty port "
				"definition\n", srvprinc);
			goto fail;
		}
		result->port = (int32_t)strtol(port_str, NULL, 10);
		if (result->port <= 0
		    || result->port > 65535
		    || errno == ERANGE) {
			DBG_ERR("Failed to parse spn %s, port number "
				"conversion failed\n", srvprinc);
			errno = 0;
			goto fail;
		}
	}
	return result;
fail:
	TALLOC_FREE(result);
	return NULL;
}
