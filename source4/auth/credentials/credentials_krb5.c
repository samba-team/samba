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
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"

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

/* This needs to be called directly after the cli_credentials_init(),
 * otherwise we might have problems with the krb5 context already
 * being here.
 */
NTSTATUS cli_credentials_set_krb5_context(struct cli_credentials *cred, 
					  struct smb_krb5_context *smb_krb5_context)
{
	if (!talloc_reference(cred, smb_krb5_context)) {
		return NT_STATUS_NO_MEMORY;
	}
	cred->smb_krb5_context = smb_krb5_context;
	return NT_STATUS_OK;
}

int cli_credentials_set_from_ccache(struct cli_credentials *cred, 
				    enum credentials_obtained obtained)
{
	
	krb5_principal princ;
	krb5_error_code ret;
	char *name;
	char **realm;

	if (cred->ccache_obtained > obtained) {
		return 0;
	}

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

/* Free a memory ccache */
static int free_mccache(struct ccache_container *ccc)
{
	krb5_cc_destroy(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

/* Free a disk-based ccache */
static int free_dccache(struct ccache_container *ccc) {
	krb5_cc_close(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

int cli_credentials_set_ccache(struct cli_credentials *cred, 
			       const char *name, 
			       enum credentials_obtained obtained)
{
	krb5_error_code ret;
	krb5_principal princ;
	struct ccache_container *ccc;
	if (cred->ccache_obtained > obtained) {
		return 0;
	}

	ccc = talloc(cred, struct ccache_container);
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


int cli_credentials_new_ccache(struct cli_credentials *cred, struct ccache_container **_ccc)
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

	if (_ccc) {
		*_ccc = ccc;
	}

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

	ret = cli_credentials_new_ccache(cred, NULL);
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

static int free_gssapi_creds(struct gssapi_creds_container *gcc)
{
	OM_uint32 min_stat, maj_stat;
	maj_stat = gss_release_cred(&min_stat, &gcc->creds);
	return 0;
}

int cli_credentials_get_client_gss_creds(struct cli_credentials *cred, 
					 struct gssapi_creds_container **_gcc) 
{
	int ret = 0;
	OM_uint32 maj_stat, min_stat;
	struct gssapi_creds_container *gcc;
	struct ccache_container *ccache;
	if (cred->client_gss_creds_obtained >= (MAX(cred->ccache_obtained, 
					     MAX(cred->principal_obtained, 
						 cred->username_obtained)))) {
		*_gcc = cred->client_gss_creds;
		return 0;
	}
	ret = cli_credentials_get_ccache(cred, 
					 &ccache);
	if (ret) {
		DEBUG(1, ("Failed to get CCACHE for GSSAPI client: %s\n", error_message(ret)));
		return ret;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		return ENOMEM;
	}

	maj_stat = gss_krb5_import_cred(&min_stat, ccache->ccache, NULL, NULL, 
					&gcc->creds);
	if (maj_stat) {
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
	}
	if (ret == 0) {
		cred->client_gss_creds_obtained = cred->ccache_obtained;
		talloc_set_destructor(gcc, free_gssapi_creds);
		cred->client_gss_creds = gcc;
		*_gcc = gcc;
	}
	return ret;
}

/**
   Set a gssapi cred_id_t into the credentails system. (Client case)

   This grabs the credentials both 'intact' and getting the krb5
   ccache out of it.  This routine can be generalised in future for
   the case where we deal with GSSAPI mechs other than krb5.  

   On sucess, the caller must not free gssapi_cred, as it now belongs
   to the credentials system.
*/

int cli_credentials_set_client_gss_creds(struct cli_credentials *cred, 
					 gss_cred_id_t gssapi_cred,
					 enum credentials_obtained obtained) 
{
	int ret;
	OM_uint32 maj_stat, min_stat;
	struct ccache_container *ccc;
	struct gssapi_creds_container *gcc;
	if (cred->client_gss_creds_obtained > obtained) {
		return 0;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		return ENOMEM;
	}

	ret = cli_credentials_new_ccache(cred, &ccc);
	if (ret != 0) {
		return ret;
	}

	maj_stat = gss_krb5_copy_ccache(&min_stat, 
					gssapi_cred, ccc->ccache);
	if (maj_stat) {
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
	}

	if (ret == 0) {
		ret = cli_credentials_set_from_ccache(cred, obtained);
	}
	if (ret == 0) {
		gcc->creds = gssapi_cred;
		talloc_set_destructor(gcc, free_gssapi_creds);
		
		cred->client_gss_creds_obtained = obtained;
		cred->client_gss_creds = gcc;
	}
	return ret;
}

/* Get the keytab (actually, a container containing the krb5_keytab)
 * attached to this context.  If this hasn't been done or set before,
 * it will be generated from the password.
 */
int cli_credentials_get_keytab(struct cli_credentials *cred, 
			       struct keytab_container **_ktc)
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;

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

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = smb_krb5_create_memory_keytab(mem_ctx, cred, smb_krb5_context, &ktc);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	cred->keytab_obtained = (MAX(cred->principal_obtained, 
				     cred->username_obtained));

	talloc_steal(cred, ktc);
	cred->keytab = ktc;
	*_ktc = cred->keytab;
	talloc_free(mem_ctx);
	return ret;
}

/* Given the name of a keytab (presumably in the format
 * FILE:/etc/krb5.keytab), open it and attach it */

int cli_credentials_set_keytab_name(struct cli_credentials *cred, 
				    const char *keytab_name, 
				    enum credentials_obtained obtained) 
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;

	if (cred->keytab_obtained >= obtained) {
		return 0;
	}

	ret = cli_credentials_get_krb5_context(cred, &smb_krb5_context);
	if (ret) {
		return ret;
	}

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = smb_krb5_open_keytab(mem_ctx, smb_krb5_context, 
				   keytab_name, &ktc);
	if (ret) {
		return ret;
	}

	cred->keytab_obtained = obtained;

	talloc_steal(cred, ktc);
	cred->keytab = ktc;
	talloc_free(mem_ctx);

	return ret;
}

int cli_credentials_update_keytab(struct cli_credentials *cred) 
{
	krb5_error_code ret;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;
	
	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = cli_credentials_get_krb5_context(cred, &smb_krb5_context);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = cli_credentials_get_keytab(cred, &ktc);
	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = smb_krb5_update_keytab(mem_ctx, cred, smb_krb5_context, ktc);

	talloc_free(mem_ctx);
	return ret;
}

/* Get server gss credentials (in gsskrb5, this means the keytab) */

int cli_credentials_get_server_gss_creds(struct cli_credentials *cred, 
					 struct gssapi_creds_container **_gcc) 
{
	int ret = 0;
	OM_uint32 maj_stat, min_stat;
	struct gssapi_creds_container *gcc;
	struct keytab_container *ktc;
	struct smb_krb5_context *smb_krb5_context;
	TALLOC_CTX *mem_ctx;
	krb5_principal princ;

	if (cred->server_gss_creds_obtained >= (MAX(cred->keytab_obtained, 
						    MAX(cred->principal_obtained, 
							cred->username_obtained)))) {
		*_gcc = cred->server_gss_creds;
		return 0;
	}

	ret = cli_credentials_get_krb5_context(cred, &smb_krb5_context);
	if (ret) {
		return ret;
	}

	ret = cli_credentials_get_keytab(cred, 
					 &ktc);
	if (ret) {
		DEBUG(1, ("Failed to get keytab for GSSAPI server: %s\n", error_message(ret)));
		return ret;
	}

	mem_ctx = talloc_new(cred);
	if (!mem_ctx) {
		return ENOMEM;
	}

	ret = principal_from_credentials(mem_ctx, cred, smb_krb5_context, &princ);
	if (ret) {
		DEBUG(1,("cli_credentials_get_server_gss_creds: makeing krb5 principal failed (%s)\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, 
						    ret, mem_ctx)));
		talloc_free(mem_ctx);
		return ret;
	}

	gcc = talloc(cred, struct gssapi_creds_container);
	if (!gcc) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	/* This creates a GSSAPI cred_id_t with the principal and keytab set */
	maj_stat = gss_krb5_import_cred(&min_stat, NULL, princ, ktc->keytab, 
					&gcc->creds);
	if (maj_stat) {
		if (min_stat) {
			ret = min_stat;
		} else {
			ret = EINVAL;
		}
	}
	if (ret == 0) {
		cred->server_gss_creds_obtained = cred->keytab_obtained;
		talloc_set_destructor(gcc, free_gssapi_creds);
		cred->server_gss_creds = gcc;
		*_gcc = gcc;
	}
	talloc_free(mem_ctx);
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

const char *cli_credentials_get_salt_principal(struct cli_credentials *cred) 
{
	return cred->salt_principal;
}

void cli_credentials_set_salt_principal(struct cli_credentials *cred, const char *principal) 
{
	cred->salt_principal = talloc_strdup(cred, principal);
}


