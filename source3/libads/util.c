/* 
   Unix SMB/CIFS implementation.
   krb5 set password implementation
   Copyright (C) Remus Koos 2001 (remuskoos@yahoo.com)
   
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

#ifdef HAVE_KRB5

ADS_STATUS ads_change_trust_account_password(ADS_STRUCT *ads, char *host_principal)
{
    char *tmp_password;
    char *password;
    char *new_password;
    char *service_principal;
    ADS_STATUS ret;
    uint32 sec_channel_type;
    
    if ((password = secrets_fetch_machine_password(lp_workgroup(), NULL, &sec_channel_type)) == NULL) {
	DEBUG(1,("Failed to retrieve password for principal %s\n", host_principal));
	return ADS_ERROR_SYSTEM(ENOENT);
    }

    tmp_password = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
    new_password = strdup(tmp_password);
    
    asprintf(&service_principal, "HOST/%s", host_principal);

    ret = kerberos_set_password(ads->auth.kdc_server, service_principal, password, service_principal, new_password, ads->auth.time_offset);

    if (!ADS_ERR_OK(ret)) goto failed;

    if (!secrets_store_machine_password(new_password, lp_workgroup(), sec_channel_type)) {
	    DEBUG(1,("Failed to save machine password\n"));
	    return ADS_ERROR_SYSTEM(EACCES);
    }

failed:
    SAFE_FREE(service_principal);
    SAFE_FREE(new_password);

    return ret;
}



#endif
