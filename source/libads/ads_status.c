/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
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

/*
  build a ADS_STATUS structure
*/
ADS_STATUS ads_build_error(enum ads_error_type etype, 
			   int rc, int minor_status)
{
	ADS_STATUS ret;
	ret.error_type = etype;
	ret.rc = rc;
	ret.minor_status = minor_status;
	return ret;
}

/*
  do a rough conversion between ads error codes and NT status codes
  we'll need to fill this in more
*/
NTSTATUS ads_ntstatus(ADS_STATUS rc)
{
	if (ADS_ERR_OK(rc)) return NT_STATUS_OK;
	return NT_STATUS_UNSUCCESSFUL;
}

/*
  return a string for an error from a ads routine
*/
const char *ads_errstr(ADS_STATUS status)
{
	int msg_ctx;
	static char *ret;

	SAFE_FREE(ret);
	msg_ctx = 0;

	switch (status.error_type) {
	case ADS_ERROR_SYSTEM:
		return strerror(status.rc);
#ifdef HAVE_LDAP
	case ADS_ERROR_LDAP:
		return ldap_err2string(status.rc);
#endif
#ifdef HAVE_KRB5
	case ADS_ERROR_KRB5: 
		return error_message(status.rc);
#endif
#ifdef HAVE_GSSAPI
	case ADS_ERROR_GSS:
	{
		uint32 minor;
		
		gss_buffer_desc msg1, msg2;
		msg1.value = NULL;
		msg2.value = NULL;
		gss_display_status(&minor, status.rc, GSS_C_GSS_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg1);
		gss_display_status(&minor, status.minor_status, GSS_C_MECH_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg2);
		asprintf(&ret, "%s : %s", (char *)msg1.value, (char *)msg2.value);
		gss_release_buffer(&minor, &msg1);
		gss_release_buffer(&minor, &msg2);
		return ret;
	}
#endif
	default:
		return "Unknown ADS error type!? (not compiled in?)";
	}

}


