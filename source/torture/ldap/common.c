#include "includes.h"

/* open a ldap connection to a server */
/* TODO: Add support to pass over credentials */
NTSTATUS torture_ldap_connection(struct ldap_connection **conn, 
				const char *url)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	BOOL ret;

	if (!url) {
		printf("You must specify a url string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	*conn = new_ldap_connection();
	if (!*conn) {
		printf("Failed to initialize ldap_connection structure\n");
		return status;
	}

	ret = ldap_setup_connection(*conn, url);
	if (!ret) {
		printf("Failed to connect with url [%s]", url);
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

/* close an ldap connection to a server */
NTSTATUS torture_ldap_close(struct ldap_connection *conn)
{
	/* FIXME: what about actually implementing ldap_close() ?
		  :-) sss */
	return NT_STATUS_OK;
}

