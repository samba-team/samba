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
    NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
    SAM_TRUST_PASSWD *trust = NULL;
    char *password;
    char *new_password;
    char *service_principal;
    ADS_STATUS ret;
    uint32 sec_channel_type;

    nt_status = pdb_init_trustpw(&trust);
    if (!NT_STATUS_IS_OK(nt_status)) {
	    DEBUG(0, ("Could not init trust password\n"));
	    return ADS_ERROR_SYSTEM(ENOMEM);
    }
    
    nt_status = pdb_gettrustpwnam(trust, lp_workgroup());
    if (!NT_STATUS_IS_OK(nt_status) || !(trust->private.flags | PASS_MACHINE_TRUST_ADS)) {
	    DEBUG(1,("Failed to retrieve password for principal %s\n", host_principal));
	    trust->free_fn(&trust);
	    return ADS_ERROR_SYSTEM(ENOENT);
    }
    
    password = trust->private.pass.data;
    sec_channel_type = SCHANNEL_TYPE(trust->private.flags);
    
    tmp_password = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
    new_password = strdup(tmp_password);
    
    asprintf(&service_principal, "HOST/%s", host_principal);

    ret = kerberos_set_password(ads->auth.kdc_server, service_principal, password, service_principal, new_password, ads->auth.time_offset);

    if (!ADS_ERR_OK(ret)) goto failed;

    pdb_set_tp_pass(trust, new_password, strlen(new_password) + 1);
    trust->private.pass.data[trust->private.pass.length] = '\0';
    pdb_set_tp_mod_time(trust, time(NULL));

    nt_status = pdb_update_trust_passwd(trust);
    if (!NT_STATUS_IS_OK(nt_status)) {
	    DEBUG(1,("Failed to update trust password\n"));
	    trust->free_fn(&trust);
	    return ADS_ERROR_SYSTEM(EACCES);
    }
    
failed:
    SAFE_FREE(service_principal);
    SAFE_FREE(new_password);
    trust->free_fn(&trust);

    return ret;
}



#endif
