#include "includes.h"

NTSTATUS torture_ldap_bind(struct ldap_connection *conn, const char *userdn, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int result;

	if (!conn) {
		printf("We need a valid ldap_connection structure and be connected\n");
		return status;
	}

	result = ldap_bind_simple(conn, userdn, password);
	if (result != LDAP_SUCCESS) {
		printf("Failed to bind with provided credentials\n");
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

NTSTATUS torture_ldap_bind_sasl(struct ldap_connection *conn, const char *username, const char *domain, const char *password)
{
        NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int result;

	if (!conn) {
		printf("We need a valid ldap_connection structure and be connected\n");
		return status;
	}

	result = ldap_bind_sasl(conn, username, domain, password);
	if (result != LDAP_SUCCESS) {
		printf("Failed to bind with provided credentialsi and SASL mechanism\n");
		/* FIXME: what abut actually implementing an ldap_connection_free() function ?
		          :-) sss */
		return status;
	}
 
	return NT_STATUS_OK;
}

/* open a ldap connection to a server */
NTSTATUS torture_ldap_connection(struct ldap_connection **conn, 
				const char *url, const char *userdn, const char *password)
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

	ret = ldap_setup_connection(*conn, url, userdn, password);
	if (!ret) {
		printf("Failed to connect with url [%s]\n", url);
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

