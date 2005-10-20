/* 
   Unix SMB/CIFS implementation.

   Handle user credentials (as regards krb5)

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

int cli_credentials_get_krb5_context(struct cli_credentials *cred, 
				     struct smb_krb5_context **smb_krb5_context) 
{
	int ret;
	if (cred->smb_krb5_context) {
		*smb_krb5_context = cred->smb_krb5_context;
		return 0;
	}

	ret = smb_krb5_init_context(cred, &cred->smb_krb5_context);
	if (ret) {
		return ret;
	}
	*smb_krb5_context = cred->smb_krb5_context;
	return 0;
}

int cli_credentials_set_from_ccache(struct cli_credentials *cred, 
				    enum credentials_obtained obtained)
{
	
	krb5_principal princ;
	krb5_error_code ret;
	char *name;
	char **realm;

	ret = krb5_cc_get_principal(cred->ccache->smb_krb5_context->krb5_context, 
				    cred->ccache->ccache, &princ);

	if (ret) {
		char *err_mess = smb_get_krb5_error_message(cred->ccache->smb_krb5_context->krb5_context, ret, cred);
		DEBUG(1,("failed to get principal from ccache: %s\n", 
			 err_mess));
		talloc_free(err_mess);
		return ret;
	}
	
	ret = krb5_unparse_name(cred->ccache->smb_krb5_context->krb5_context, princ, &name);
	if (ret) {
		char *err_mess = smb_get_krb5_error_message(cred->ccache->smb_krb5_context->krb5_context, ret, cred);
		DEBUG(1,("failed to unparse principal from ccache: %s\n", 
			 err_mess));
		talloc_free(err_mess);
		return ret;
	}

	realm = krb5_princ_realm(cred->ccache->smb_krb5_context->krb5_context, princ);

	cli_credentials_set_principal(cred, name, obtained);

	free(name);

	krb5_free_principal(cred->ccache->smb_krb5_context->krb5_context, princ);

	cred->ccache_obtained = obtained;

	return 0;
}


static int free_mccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	krb5_cc_destroy(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

static int free_dccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	krb5_cc_close(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

int cli_credentials_set_ccache(struct cli_credentials *cred, 
			       const char *name, 
			       enum credentials_obtained obtained)
{
	krb5_error_code ret;
	krb5_principal princ;
	struct ccache_container *ccc = talloc(cred, struct ccache_container);
	if (!ccc) {
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, &ccc->smb_krb5_context);
	if (ret) {
		talloc_free(ccc);
		return ret;
	}
	talloc_reference(ccc, ccc->smb_krb5_context);

	if (name) {
		ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, name, &ccc->ccache);
		if (ret) {
			DEBUG(1,("failed to read krb5 ccache: %s: %s\n", 
				 name, 
				 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
			talloc_free(ccc);
			return ret;
		}
	} else {
		ret = krb5_cc_default(ccc->smb_krb5_context->krb5_context, &ccc->ccache);
		if (ret) {
			DEBUG(3,("failed to read default krb5 ccache: %s\n", 
				 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
			talloc_free(ccc);
			return ret;
		}
	}

	talloc_set_destructor(ccc, free_dccache);

	ret = krb5_cc_get_principal(ccc->smb_krb5_context->krb5_context, ccc->ccache, &princ);

	if (ret) {
		DEBUG(3,("failed to get principal from default ccache: %s\n", 
			 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
		talloc_free(ccc);		
		return ret;
	}

	krb5_free_principal(ccc->smb_krb5_context->krb5_context, princ);

	cred->ccache = ccc;
	talloc_steal(cred, ccc);

	ret = cli_credentials_set_from_ccache(cred, obtained);

	if (ret) {
		return ret;
	}

	return 0;
}


int cli_credentials_new_ccache(struct cli_credentials *cred)
{
	krb5_error_code ret;
	char *rand_string;
	struct ccache_container *ccc = talloc(cred, struct ccache_container);
	char *ccache_name;
	if (!ccc) {
		return ENOMEM;
	}

	rand_string = generate_random_str(NULL, 16);
	if (!rand_string) {
		talloc_free(ccc);
		return ENOMEM;
	}

	ccache_name = talloc_asprintf(ccc, "MEMORY:%s", 
				      rand_string);
	talloc_free(rand_string);

	if (!ccache_name) {
		talloc_free(ccc);
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, &ccc->smb_krb5_context);
	if (ret) {
		talloc_free(ccc);
		return ret;
	}
	talloc_reference(ccc, ccc->smb_krb5_context);

	ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, ccache_name, &ccc->ccache);
	if (ret) {
		DEBUG(1,("failed to generate a new krb5 ccache (%s): %s\n", 
			 ccache_name,
			 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
		talloc_free(ccache_name);
		talloc_free(ccc);
		return ret;
	}

	talloc_set_destructor(ccc, free_mccache);

	cred->ccache = ccc;
	talloc_steal(cred, ccc);
	talloc_free(ccache_name);

	return ret;
}

int cli_credentials_get_ccache(struct cli_credentials *cred, 
			       struct ccache_container **ccc)
{
	krb5_error_code ret;
	
	if (cred->ccache_obtained >= (MAX(cred->principal_obtained, 
					  cred->username_obtained))) {
		*ccc = cred->ccache;
		return 0;
	}
	if (cli_credentials_is_anonymous(cred)) {
		return EINVAL;
	}

	ret = cli_credentials_new_ccache(cred);
	if (ret) {
		return ret;
	}
	ret = kinit_to_ccache(cred, cred, cred->ccache->smb_krb5_context, cred->ccache->ccache);
	if (ret) {
		return ret;
	}
	ret = cli_credentials_set_from_ccache(cred, cred->principal_obtained);

	if (ret) {
		return ret;
	}
	*ccc = cred->ccache;
	return ret;
}

int cli_credentials_get_keytab(struct cli_credentials *cred, 
			       struct keytab_container **_ktc)
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;

	if (cred->keytab_obtained >= (MAX(cred->principal_obtained, 
					  cred->username_obtained))) {
		*_ktc = cred->keytab;
		return 0;
	}

	if (cli_credentials_is_anonymous(cred)) {
		return EINVAL;
	}

	ret = cli_credentials_get_krb5_context(cred, &smb_krb5_context);
	if (ret) {
		return ret;
	}

	ret = create_memory_keytab(cred, cred, smb_krb5_context, &ktc);
	if (ret) {
		return ret;
	}

	cred->keytab_obtained = (MAX(cred->principal_obtained, 
				     cred->username_obtained));

	cred->keytab = ktc;
	*_ktc = cred->keytab;
	return ret;
}

/** 
 * Set Kerberos KVNO
 */

void cli_credentials_set_kvno(struct cli_credentials *cred,
			      int kvno)
{
	cred->kvno = kvno;
}

/**
 * Return Kerberos KVNO
 */

int cli_credentials_get_kvno(struct cli_credentials *cred)
{
	return cred->kvno;
}

